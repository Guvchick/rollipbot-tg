package gcore

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"ip-roller-bot/internal/provider"
)

// recorder — потокобезопасный журнал запросов "METHOD PATH", т.к. httptest
// обслуживает каждый запрос в своей горутине. // Thread-safe request log.
type recorder struct {
	mu   sync.Mutex
	reqs []string
}

func (rec *recorder) add(s string) {
	rec.mu.Lock()
	rec.reqs = append(rec.reqs, s)
	rec.mu.Unlock()
}

func (rec *recorder) all() []string {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]string(nil), rec.reqs...)
}

func (rec *recorder) count(s string) int {
	n := 0
	for _, x := range rec.all() {
		if x == s {
			n++
		}
	}
	return n
}

func (rec *recorder) has(s string) bool { return rec.count(s) > 0 }

// fastPolling ускоряет опрос задач на время теста. // Speed up task polling.
func fastPolling(t *testing.T) {
	t.Helper()
	oldI, oldT := taskPollInterval, taskPollTimeout
	taskPollInterval = 2 * time.Millisecond
	taskPollTimeout = 2 * time.Second
	t.Cleanup(func() { taskPollInterval, taskPollTimeout = oldI, oldT })
}

// (a) Синхронный Allocate: сразу приходит floating_ip_address.
func TestAllocateSync(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r.Method + " " + r.URL.Path)
		if got := r.Header.Get("Authorization"); got != "apikey tok" {
			t.Errorf("Authorization = %q, want %q", got, "apikey tok")
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/floatingips/proj1/5":
			io.WriteString(w, `{"id":"fip-1","floating_ip_address":"1.2.3.4"}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := New(Config{APIURL: srv.URL, APIToken: "tok", ProjectID: "proj1", RegionID: 5}, provider.RollCaps{})
	ip, err := p.Allocate(context.Background())
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if ip.Addr.String() != "1.2.3.4" {
		t.Fatalf("addr = %s, want 1.2.3.4", ip.Addr)
	}
	if ip.ID != "fip-1" { // фиксированный регион → голый fipID
		t.Fatalf("id = %s, want fip-1", ip.ID)
	}
}

// (b) Асинхронный Allocate: task → RUNNING → FINISHED с created_resources,
// затем GET floating IP отдаёт адрес.
func TestAllocateAsync(t *testing.T) {
	fastPolling(t)
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r.Method + " " + r.URL.Path)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/floatingips/proj1/5":
			io.WriteString(w, `{"tasks":["task-1"]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks/task-1":
			// Первый опрос — RUNNING, последующие — FINISHED.
			if rec.count("GET /v1/tasks/task-1") < 2 {
				io.WriteString(w, `{"id":"task-1","state":"RUNNING"}`)
			} else {
				io.WriteString(w, `{"id":"task-1","state":"FINISHED","created_resources":{"floatingips":["fip-2"]}}`)
			}
		case r.Method == http.MethodGet && r.URL.Path == "/v1/floatingips/proj1/5/fip-2":
			io.WriteString(w, `{"id":"fip-2","floating_ip_address":"5.6.7.8"}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := New(Config{APIURL: srv.URL, APIToken: "tok", ProjectID: "proj1", RegionID: 5}, provider.RollCaps{})
	ip, err := p.Allocate(context.Background())
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if ip.Addr.String() != "5.6.7.8" {
		t.Fatalf("addr = %s, want 5.6.7.8", ip.Addr)
	}
	if ip.ID != "fip-2" {
		t.Fatalf("id = %s, want fip-2", ip.ID)
	}
	if n := rec.count("GET /v1/tasks/task-1"); n < 2 {
		t.Fatalf("expected the task to be polled >=2 times, got %d", n)
	}
}

// (c) Задача завершается ошибкой — Allocate возвращает понятную ошибку с текстом.
func TestAllocateTaskError(t *testing.T) {
	fastPolling(t)
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r.Method + " " + r.URL.Path)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/floatingips/proj1/5":
			io.WriteString(w, `{"tasks":["task-err"]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks/task-err":
			io.WriteString(w, `{"id":"task-err","state":"ERROR","error":"quota exceeded"}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := New(Config{APIURL: srv.URL, APIToken: "tok", ProjectID: "proj1", RegionID: 5}, provider.RollCaps{})
	_, err := p.Allocate(context.Background())
	if err == nil {
		t.Fatal("expected an error on task state ERROR")
	}
	if !strings.Contains(err.Error(), "quota exceeded") {
		t.Fatalf("error should carry the task error text, got: %v", err)
	}
}

// (c') Отмена контекста прерывает опрос задачи.
func TestAllocateAsyncCtxCancel(t *testing.T) {
	fastPolling(t)
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r.Method + " " + r.URL.Path)
		switch {
		case r.Method == http.MethodPost:
			io.WriteString(w, `{"tasks":["task-stuck"]}`)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/tasks/"):
			io.WriteString(w, `{"id":"task-stuck","state":"RUNNING"}`) // никогда не завершается
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := New(Config{APIURL: srv.URL, APIToken: "tok", ProjectID: "proj1", RegionID: 5}, provider.RollCaps{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := p.Allocate(ctx)
	if err == nil {
		t.Fatal("expected a cancellation/timeout error")
	}
}

// (d) Any-region mode: /v1/regions листится (и кэшируется), Allocate кодирует
// регион в id, а Release/Attach бьют в правильный регион; роллы идут по кругу.
func TestAllocateAnyRegion(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r.Method + " " + r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/regions":
			io.WriteString(w, `{"results":[
				{"id":11,"display_name":"ams","state":"ACTIVE"},
				{"id":22,"display_name":"lux","state":"ACTIVE"},
				{"id":33,"display_name":"old","state":"DELETED"}
			]}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/assign"):
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/floatingips/proj1/"):
			io.WriteString(w, `{"id":"fipA","floating_ip_address":"9.9.9.9"}`)
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := New(Config{APIURL: srv.URL, APIToken: "tok", ProjectID: "proj1", RegionID: 0}, provider.RollCaps{})

	// Первый ролл → регион 11 (round-robin index 0), 33 отфильтрован (DELETED).
	ip, err := p.Allocate(context.Background())
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if ip.ID != "11/fipA" {
		t.Fatalf("id = %s, want 11/fipA (region encoded)", ip.ID)
	}
	if ip.Addr.String() != "9.9.9.9" {
		t.Fatalf("addr = %s, want 9.9.9.9", ip.Addr)
	}
	if !rec.has("POST /v1/floatingips/proj1/11") {
		t.Fatalf("create should hit region 11, reqs=%v", rec.all())
	}

	// Attach должен уйти в тот же регион 11.
	if err := p.Attach(context.Background(), ip, "port-1"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if !rec.has("POST /v1/floatingips/proj1/11/fipA/assign") {
		t.Fatalf("attach should hit region 11 path, reqs=%v", rec.all())
	}

	// Release должен уйти в тот же регион 11.
	if err := p.Release(context.Background(), ip); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if !rec.has("DELETE /v1/floatingips/proj1/11/fipA") {
		t.Fatalf("release should hit region 11 path, reqs=%v", rec.all())
	}

	// Второй ролл → регион 22 (round-robin index 1).
	ip2, err := p.Allocate(context.Background())
	if err != nil {
		t.Fatalf("Allocate #2: %v", err)
	}
	if ip2.ID != "22/fipA" {
		t.Fatalf("id2 = %s, want 22/fipA (round-robin rotate)", ip2.ID)
	}

	// Список регионов должен запрашиваться один раз (кэш).
	if n := rec.count("GET /v1/regions"); n != 1 {
		t.Fatalf("regions listed %d times, want 1 (cached)", n)
	}
}

// (d') Any-region без активных регионов — понятная ошибка.
func TestAllocateAnyRegionNoRegions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/regions" {
			io.WriteString(w, `{"results":[{"id":33,"display_name":"old","state":"DELETED"}]}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p := New(Config{APIURL: srv.URL, APIToken: "tok", ProjectID: "proj1", RegionID: 0}, provider.RollCaps{})
	if _, err := p.Allocate(context.Background()); err == nil {
		t.Fatal("expected an error when no ACTIVE regions are available")
	}
}

// (e) ParseConsoleURL — таблица.
func TestParseConsoleURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		proj string
		reg  int
		ok   bool
	}{
		{"project only", "https://cloud.gcore.com/projects/12345/", "12345", 0, true},
		{"project no trailing slash", "https://cloud.gcore.com/projects/12345", "12345", 0, true},
		{"project + region path", "https://cloud.gcore.com/projects/12345/regions/7/instances", "12345", 7, true},
		{"region query", "https://cloud.gcore.com/projects/12345?region=7", "12345", 7, true},
		{"region_id query", "https://cloud.gcore.com/projects/12345?foo=1&region_id=7", "12345", 7, true},
		{"path region beats query", "https://cloud.gcore.com/projects/99/regions/3/x?region=8", "99", 3, true},
		{"deep trailing path", "https://cloud.gcore.com/projects/555/regions/2/networks/abc/ports", "555", 2, true},
		{"bare number", "12345", "12345", 0, true},
		{"bare number spaced", "  678  ", "678", 0, true},
		{"no project", "https://cloud.gcore.com/dashboard", "", 0, false},
		{"empty", "", "", 0, false},
		{"non-numeric junk", "not a url", "", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			proj, reg, ok := ParseConsoleURL(c.in)
			if proj != c.proj || reg != c.reg || ok != c.ok {
				t.Fatalf("ParseConsoleURL(%q) = (%q,%d,%v), want (%q,%d,%v)",
					c.in, proj, reg, ok, c.proj, c.reg, c.ok)
			}
		})
	}
}

// (f) Удалённый/деактивированный аккаунт Gcore (403 с info.status) — типизированная
// RefusedError с понятным текстом, а не сырой ответ API.
func TestAllocateDeletedClientBecomesRefusedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"exception_class":"UnauthorizedError","message":"The client(1004991) product status is in <deleted> status","request_id":"03e450d0","info":{"client_id":1004991,"status":"deleted"}}`)
	}))
	defer srv.Close()

	p := New(Config{APIURL: srv.URL, APIToken: "tok", ProjectID: "proj1", RegionID: 5}, provider.RollCaps{})
	_, err := p.Allocate(context.Background())
	var re *provider.RefusedError
	if !errors.As(err, &re) {
		t.Fatalf("err = %v, want *provider.RefusedError", err)
	}
	if !strings.Contains(re.Detail, "1004991") || !strings.Contains(re.Detail, "deleted") {
		t.Errorf("detail = %q, want client id and status", re.Detail)
	}
}

// (f') То же в режиме any-region: 403 приходит уже на GET /v1/regions.
func TestAllocateAnyRegionDeletedClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"exception_class":"UnauthorizedError","message":"The client(1004991) product status is in <deleted> status","info":{"client_id":1004991,"status":"deleted"}}`)
	}))
	defer srv.Close()

	p := New(Config{APIURL: srv.URL, APIToken: "tok", ProjectID: "proj1", RegionID: 0}, provider.RollCaps{})
	_, err := p.Allocate(context.Background())
	var re *provider.RefusedError
	if !errors.As(err, &re) {
		t.Fatalf("err = %v, want *provider.RefusedError", err)
	}
}
