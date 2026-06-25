// Package cookie is the panel-only fallback for hosters without a public API
// (IHC, Contell, UFO.Hosting, Vinton): one logs into the panel by hand (captcha
// /2FA solved by a human), exports the session cookies, and replays authed
// requests. It is deliberately a thin scaffold — panel endpoints differ per
// hoster and must be filled in per target. It satisfies provider.Provider so it
// can be slotted into the engine, but allocate is guarded by default.
package cookie

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"time"

	"ip-roller-bot/internal/provider"
)

type Config struct {
	Name       string // hoster machine name, e.g. "ihc"
	BaseURL    string // panel base url
	CookieFile string // JSON file with exported session cookies
}

type Provider struct {
	name   string
	base   string
	client *http.Client
	caps   provider.RollCaps
}

// New builds a cookie-backed client, loading session cookies from CookieFile if
// present.
func New(cfg Config, caps provider.RollCaps) (*Provider, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	if cfg.CookieFile != "" && cfg.BaseURL != "" {
		if cookies, err := loadCookies(cfg.CookieFile); err == nil {
			if u, err := url.Parse(cfg.BaseURL); err == nil {
				jar.SetCookies(u, cookies)
			}
		}
	}
	return &Provider{
		name:   cfg.Name,
		base:   cfg.BaseURL,
		client: &http.Client{Timeout: 30 * time.Second, Jar: jar},
		caps:   caps,
	}, nil
}

func (p *Provider) Name() string            { return p.name }
func (p *Provider) Caps() provider.RollCaps { return p.caps }

func (p *Provider) Allocate(ctx context.Context) (provider.AllocatedIP, error) {
	return provider.AllocatedIP{}, &provider.NotImplementedError{
		Provider: p.name,
		Detail:   "панель без публичного API: роллинг только через cookie-фолбэк, эндпоинты задаются под конкретную панель",
	}
}

func (p *Provider) Release(ctx context.Context, ip provider.AllocatedIP) error {
	return &provider.NotImplementedError{Provider: p.name, Detail: "cookie-фолбэк: release через панель"}
}

func (p *Provider) Attach(ctx context.Context, ip provider.AllocatedIP, vmID string) error {
	return &provider.NotImplementedError{Provider: p.name, Detail: "cookie-фолбэк: привязка через панель"}
}

func loadCookies(path string) ([]*http.Cookie, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cookies []*http.Cookie
	if err := json.Unmarshal(data, &cookies); err != nil {
		return nil, err
	}
	return cookies, nil
}

var _ provider.Provider = (*Provider)(nil)
