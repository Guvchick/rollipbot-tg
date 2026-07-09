// Package gcore implements the Provider for Gcore Cloud floating IPs.
// Заголовок авторизации буквально "Authorization: apikey <token>".
// Docs: https://docs.gcore.com/api-reference/cloud
//
// Особенности Gcore, которые обрабатывает адаптер:
//   - Создание floating IP часто АСИНХРОННО: вместо floating_ip_address
//     приходит {"tasks": ["<task_id>"]}. Тогда мы опрашиваем /v1/tasks/<id>
//     до состояния FINISHED и затем читаем адрес созданного IP.
//   - Режим "любой регион" (RegionID == 0): на каждый Allocate выбираем
//     ACTIVE-регион по кругу (round-robin) из GET /v1/regions и кодируем
//     регион в id ресурса как "<regionID>/<fipID>", чтобы Release/Attach
//     били в тот же регион.
package gcore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"ip-roller-bot/internal/provider"
)

const defaultBaseURL = "https://api.gcore.com/cloud"

// Параметры опроса асинхронных задач. Объявлены как var (не const), чтобы
// тесты могли ускорить интервал. // Async task polling knobs (var for tests).
var (
	taskPollInterval = 1 * time.Second
	taskPollTimeout  = 60 * time.Second
)

type Config struct {
	APIURL    string
	APIToken  string
	ProjectID string
	RegionID  int
}

type Provider struct {
	token     string
	base      string
	projectID string
	regionID  int
	client    *http.Client
	caps      provider.RollCaps

	// mu защищает кэш регионов и счётчик round-robin (any-region mode).
	mu          sync.Mutex
	regionCache []int
	rr          int
}

func New(cfg Config, caps provider.RollCaps) *Provider {
	base := cfg.APIURL
	if base == "" {
		base = defaultBaseURL
	}
	return &Provider{
		token:     cfg.APIToken,
		base:      base,
		projectID: cfg.ProjectID,
		regionID:  cfg.RegionID,
		client:    &http.Client{Timeout: 40 * time.Second},
		caps:      caps,
	}
}

func (p *Provider) Name() string            { return "gcore" }
func (p *Provider) Caps() provider.RollCaps { return p.caps }

func (p *Provider) newReq(ctx context.Context, method, path string, body any) (*http.Request, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.base+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "apikey "+p.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// floatingIPResp покрывает и синхронный ответ (с адресом), и асинхронный
// (со списком tasks). // Covers both sync (address) and async (tasks) replies.
type floatingIPResp struct {
	ID                string   `json:"id"`
	FloatingIPAddress string   `json:"floating_ip_address"`
	Tasks             []string `json:"tasks"`
}

// taskResp — часть /v1/tasks/<id>, которая нам нужна. // Subset of the task object.
type taskResp struct {
	ID               string `json:"id"`
	State            string `json:"state"` // NEW | RUNNING | FINISHED | ERROR
	Error            string `json:"error"` // nullable, заполнен при ERROR
	CreatedResources struct {
		Floatingips []string `json:"floatingips"`
	} `json:"created_resources"`
}

// fipPath строит путь к floating IP-ам заданного региона.
// Builds the floatingips path for a given region.
func (p *Provider) fipPath(regionID int) string {
	return fmt.Sprintf("/v1/floatingips/%s/%d", p.projectID, regionID)
}

// resolveID достаёт (regionID, fipID) из сохранённого id ресурса.
// В режиме any-region id имеет вид "<regionID>/<fipID>"; в режиме
// фиксированного региона это просто "<fipID>", и используется p.regionID.
// Returns (regionID, fipID) from a stored resource id.
func (p *Provider) resolveID(id string) (int, string) {
	if i := strings.IndexByte(id, '/'); i >= 0 {
		if rid, err := strconv.Atoi(id[:i]); err == nil {
			return rid, id[i+1:]
		}
	}
	return p.regionID, id
}

// encodeID кодирует регион в id ресурса в режиме any-region, иначе оставляет
// голый fipID (обратная совместимость). // Encodes region only in any-region mode.
func (p *Provider) encodeID(anyRegion bool, regionID int, fipID string) string {
	if anyRegion {
		return fmt.Sprintf("%d/%s", regionID, fipID)
	}
	return fipID
}

func (p *Provider) Allocate(ctx context.Context) (provider.AllocatedIP, error) {
	// Определяем регион: фиксированный (RegionID != 0) или любой ACTIVE.
	anyRegion := p.regionID == 0
	regionID := p.regionID
	if anyRegion {
		rid, err := p.pickRegion(ctx)
		if err != nil {
			return provider.AllocatedIP{}, err
		}
		regionID = rid
	}

	// Создаём floating IP. Тело пустое — {}.
	req, err := p.newReq(ctx, http.MethodPost, p.fipPath(regionID), map[string]any{})
	if err != nil {
		return provider.AllocatedIP{}, err
	}
	var resp floatingIPResp
	if err := provider.DoJSON(p.client, req, p.Name(), &resp); err != nil {
		return provider.AllocatedIP{}, err
	}

	fipID, addrStr := resp.ID, resp.FloatingIPAddress
	if addrStr == "" {
		// Асинхронный ответ: {"tasks": [...]} вместо адреса — опрашиваем задачу.
		// Async reply: poll the task, then read the created floating IP.
		if len(resp.Tasks) == 0 {
			return provider.AllocatedIP{}, fmt.Errorf("gcore: ответ без floating_ip_address и без tasks")
		}
		id, addr, err := p.resolveTask(ctx, regionID, resp.Tasks[0])
		if err != nil {
			return provider.AllocatedIP{}, err
		}
		fipID, addrStr = id, addr
	}

	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return provider.AllocatedIP{}, fmt.Errorf("gcore: некорректный ip %q: %w", addrStr, err)
	}
	return provider.AllocatedIP{Addr: addr, ID: p.encodeID(anyRegion, regionID, fipID)}, nil
}

// resolveTask ждёт завершения задачи и возвращает (fipID, address) созданного
// floating IP. // Waits for the task, then fetches the fip address.
func (p *Provider) resolveTask(ctx context.Context, regionID int, taskID string) (string, string, error) {
	// Общий бюджет времени на асинхронную операцию (~60s) + отмена ctx.
	ctx, cancel := context.WithTimeout(ctx, taskPollTimeout)
	defer cancel()

	t, err := p.waitTask(ctx, taskID)
	if err != nil {
		return "", "", err
	}
	fips := t.CreatedResources.Floatingips
	if len(fips) == 0 {
		return "", "", fmt.Errorf("gcore: задача %s завершена, но floating IP не создан", taskID)
	}
	fipID := fips[0]

	// Забираем сам floating IP, чтобы узнать его адрес.
	req, err := p.newReq(ctx, http.MethodGet, p.fipPath(regionID)+"/"+fipID, nil)
	if err != nil {
		return "", "", err
	}
	var fip floatingIPResp
	if err := provider.DoJSON(p.client, req, p.Name(), &fip); err != nil {
		return "", "", err
	}
	if fip.FloatingIPAddress == "" {
		return "", "", fmt.Errorf("gcore: floating IP %s создан без адреса", fipID)
	}
	return fipID, fip.FloatingIPAddress, nil
}

// waitTask опрашивает /v1/tasks/<id> каждые taskPollInterval до состояния
// FINISHED (успех) или ERROR (ошибка), уважая отмену/таймаут контекста.
// Polls the task until FINISHED or ERROR, honoring ctx cancellation.
func (p *Provider) waitTask(ctx context.Context, taskID string) (taskResp, error) {
	ticker := time.NewTicker(taskPollInterval)
	defer ticker.Stop()

	for {
		req, err := p.newReq(ctx, http.MethodGet, "/v1/tasks/"+taskID, nil)
		if err != nil {
			return taskResp{}, err
		}
		var t taskResp
		if err := provider.DoJSON(p.client, req, p.Name(), &t); err != nil {
			return taskResp{}, err
		}
		switch strings.ToUpper(t.State) {
		case "FINISHED":
			return t, nil
		case "ERROR":
			msg := t.Error
			if msg == "" {
				msg = "без деталей"
			}
			return taskResp{}, fmt.Errorf("gcore: задача %s завершилась ошибкой (state=ERROR): %s", taskID, msg)
		}
		// NEW / RUNNING → ждём следующий тик или отмену контекста.
		select {
		case <-ctx.Done():
			return taskResp{}, fmt.Errorf("gcore: ожидание задачи %s прервано: %w", taskID, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (p *Provider) Release(ctx context.Context, ip provider.AllocatedIP) error {
	regionID, fipID := p.resolveID(ip.ID)
	req, err := p.newReq(ctx, http.MethodDelete, p.fipPath(regionID)+"/"+fipID, nil)
	if err != nil {
		return err
	}
	// Удаление может быть асинхронным — освобождаем "best-effort", задачу не ждём.
	// Delete may be async; best-effort, we don't block waiting on its task.
	return provider.DoJSON(p.client, req, p.Name(), nil)
}

func (p *Provider) Attach(ctx context.Context, ip provider.AllocatedIP, portID string) error {
	regionID, fipID := p.resolveID(ip.ID)
	body := map[string]any{"port_id": portID}
	req, err := p.newReq(ctx, http.MethodPost, p.fipPath(regionID)+"/"+fipID+"/assign", body)
	if err != nil {
		return err
	}
	return provider.DoJSON(p.client, req, p.Name(), nil)
}

// regionsResp — форма ответа GET /v1/regions. // Shape of the regions listing.
type regionsResp struct {
	Results []struct {
		ID          int    `json:"id"`
		DisplayName string `json:"display_name"`
		State       string `json:"state"`
	} `json:"results"`
}

// regionUsable считает регион пригодным, если он ACTIVE (или без явного статуса).
// Treats a region as usable when ACTIVE (or when state is absent).
func regionUsable(state string) bool {
	return state == "" || strings.EqualFold(state, "ACTIVE")
}

// listRegions возвращает id пригодных регионов, кэшируя список под мьютексом.
// Returns usable region ids, caching the list under the mutex.
func (p *Provider) listRegions(ctx context.Context) ([]int, error) {
	p.mu.Lock()
	if len(p.regionCache) > 0 {
		ids := append([]int(nil), p.regionCache...)
		p.mu.Unlock()
		return ids, nil
	}
	p.mu.Unlock()

	req, err := p.newReq(ctx, http.MethodGet, "/v1/regions", nil)
	if err != nil {
		return nil, err
	}
	var resp regionsResp
	if err := provider.DoJSON(p.client, req, p.Name(), &resp); err != nil {
		return nil, fmt.Errorf("gcore: не смог получить список регионов: %w", err)
	}
	var ids []int
	for _, r := range resp.Results {
		if regionUsable(r.State) {
			ids = append(ids, r.ID)
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("gcore: не найдено активных регионов (any-region mode)")
	}
	p.mu.Lock()
	p.regionCache = ids
	p.mu.Unlock()
	return ids, nil
}

// pickRegion выбирает регион по кругу (round-robin), чтобы последовательные
// роллы расходились по регионам. // Round-robin so rolls spread across regions.
func (p *Provider) pickRegion(ctx context.Context) (int, error) {
	ids, err := p.listRegions(ctx)
	if err != nil {
		return 0, err
	}
	p.mu.Lock()
	rid := ids[p.rr%len(ids)]
	p.rr++
	p.mu.Unlock()
	return rid, nil
}

// Regexes для ParseConsoleURL. Якорим по литералам /projects/ и /regions/;
// голое число — по краям строки. // Anchored on path literals; bare number on ends.
var (
	reProjectPath = regexp.MustCompile(`/projects/(\d+)`)
	reRegionPath  = regexp.MustCompile(`/regions/(\d+)`)
	reRegionQuery = regexp.MustCompile(`[?&](?:region_id|region)=(\d+)`)
	reBareNumber  = regexp.MustCompile(`^\s*(\d+)\s*$`)
)

// ParseConsoleURL вытаскивает числовой id проекта и (если есть) id региона из
// вставленной ссылки на облачную консоль Gcore. Поддерживаемые формы:
//   - https://cloud.gcore.com/projects/12345/...            → project 12345
//   - https://cloud.gcore.com/projects/12345/regions/7/...  → project 12345, region 7
//   - .../projects/12345?region=7  или  ...&region_id=7     → region 7
//   - голое число "12345"                                   → project 12345, region 0
//
// ok=false, если id проекта найти не удалось.
// Extracts project/region ids from a pasted Gcore console URL.
func ParseConsoleURL(raw string) (projectID string, regionID int, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", 0, false
	}
	// Голое число трактуем как id проекта. // A bare number is a project id.
	if m := reBareNumber.FindStringSubmatch(s); m != nil {
		return m[1], 0, true
	}
	m := reProjectPath.FindStringSubmatch(s)
	if m == nil {
		return "", 0, false
	}
	projectID = m[1]
	// Регион из пути имеет приоритет над query-параметром.
	// Region from the path wins over the query param.
	if rm := reRegionPath.FindStringSubmatch(s); rm != nil {
		regionID, _ = strconv.Atoi(rm[1])
	} else if rm := reRegionQuery.FindStringSubmatch(s); rm != nil {
		regionID, _ = strconv.Atoi(rm[1])
	}
	return projectID, regionID, true
}

// SetHTTPClient routes REST calls through c (e.g. a proxy client).
func (p *Provider) SetHTTPClient(c *http.Client) { p.client = c }

var (
	_ provider.Provider         = (*Provider)(nil)
	_ provider.HTTPConfigurable = (*Provider)(nil)
)
