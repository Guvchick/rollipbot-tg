// Package beget implements the Provider for Beget. Like RuVDS, Beget has no
// floating IP: rolling means ordering an additional IPv4 for a VPS or recreating
// the VPS. The REST client and config are wired; allocate is guarded until a
// target server is configured (paid, mutating operations).
// Docs: https://developer.beget.com
package beget

import (
	"context"
	"net/http"
	"time"

	"ip-roller-bot/internal/provider"
)

const defaultBaseURL = "https://api.beget.com"

type Config struct {
	APIURL   string
	Token    string
	Strategy string // "additional_ip" | "recreate"
	ServerID string
}

type Provider struct {
	token    string
	base     string
	strategy string
	serverID string
	client   *http.Client
	caps     provider.RollCaps
}

func New(cfg Config, caps provider.RollCaps) *Provider {
	base := cfg.APIURL
	if base == "" {
		base = defaultBaseURL
	}
	return &Provider{
		token:    cfg.Token,
		base:     base,
		strategy: cfg.Strategy,
		serverID: cfg.ServerID,
		client:   &http.Client{Timeout: 60 * time.Second},
		caps:     caps,
	}
}

func (p *Provider) Name() string            { return "beget" }
func (p *Provider) Caps() provider.RollCaps { return p.caps }

func (p *Provider) Allocate(ctx context.Context) (provider.AllocatedIP, error) {
	return provider.AllocatedIP{}, &provider.NotImplementedError{
		Provider: p.Name(),
		Detail:   "роллинг Beget = заказ доп. IPv4 / пересоздание VPS; нужен server_id и подтверждённый платный сценарий",
	}
}

func (p *Provider) Release(ctx context.Context, ip provider.AllocatedIP) error {
	return &provider.NotImplementedError{Provider: p.Name(), Detail: "release не реализован для additional_ip/recreate"}
}

func (p *Provider) Attach(ctx context.Context, ip provider.AllocatedIP, vmID string) error {
	return &provider.NotImplementedError{Provider: p.Name(), Detail: "IP закрепляется за VPS при заказе/создании"}
}

var _ provider.Provider = (*Provider)(nil)
