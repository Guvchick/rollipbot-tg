// Package ruvds implements the Provider for RuVDS. RuVDS has no floating IP:
// rolling means recreating the server or ordering an additional IP, both bound
// to a concrete server. The REST client and config are wired here; the
// allocate flow is intentionally guarded until a target server is configured,
// because it mutates/recreates real (paid) servers.
// Docs: https://ruvds.com/api-docs/
package ruvds

import (
	"net/http"
	"time"

	"context"

	"ip-roller-bot/internal/provider"
)

const defaultBaseURL = "https://api.ruvds.com/v2"

type Config struct {
	Token    string
	Strategy string // "recreate" | "additional_ip"
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
	return &Provider{
		token:    cfg.Token,
		base:     defaultBaseURL,
		strategy: cfg.Strategy,
		serverID: cfg.ServerID,
		client:   &http.Client{Timeout: 60 * time.Second},
		caps:     caps,
	}
}

func (p *Provider) Name() string            { return "ruvds" }
func (p *Provider) Caps() provider.RollCaps { return p.caps }

func (p *Provider) Allocate(ctx context.Context) (provider.AllocatedIP, error) {
	// recreate: DELETE+POST /servers ; additional_ip: order an extra IPv4 for
	// serverID. Both depend on server_id and on destructive/paid actions, so we
	// surface a clear error rather than silently churning real servers.
	return provider.AllocatedIP{}, &provider.NotImplementedError{
		Provider: p.Name(),
		Detail:   "роллинг RuVDS = пересоздание сервера / заказ доп. IP; нужен server_id и подтверждённый платный сценарий",
	}
}

func (p *Provider) Release(ctx context.Context, ip provider.AllocatedIP) error {
	return &provider.NotImplementedError{Provider: p.Name(), Detail: "release не реализован для recreate/additional_ip"}
}

func (p *Provider) Attach(ctx context.Context, ip provider.AllocatedIP, vmID string) error {
	return &provider.NotImplementedError{Provider: p.Name(), Detail: "IP уже закреплён за сервером при создании/заказе"}
}

var _ provider.Provider = (*Provider)(nil)
