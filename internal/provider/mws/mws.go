// Package mws implements the Provider for MWS Cloud public IPs by reserving an
// address in a subnetwork. Docs: https://mws.ru/docs/cloud-platform/api/
package mws

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"

	"ip-roller-bot/internal/provider"
)

const defaultBaseURL = "https://api.mws.ru"

type Config struct {
	Token        string
	ProjectID    string
	NetworkID    string
	SubnetworkID string
}

type Provider struct {
	token  string
	base   string
	cfg    Config
	client *http.Client
	caps   provider.RollCaps
}

func New(cfg Config, caps provider.RollCaps) *Provider {
	return &Provider{
		token:  cfg.Token,
		base:   defaultBaseURL,
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
		caps:   caps,
	}
}

func (p *Provider) Name() string            { return "mws" }
func (p *Provider) Caps() provider.RollCaps { return p.caps }

func (p *Provider) ipsPath() string {
	return fmt.Sprintf("/v1/projects/%s/networks/%s/subnetworks/%s/ips",
		p.cfg.ProjectID, p.cfg.NetworkID, p.cfg.SubnetworkID)
}

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
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return req, nil
}

type ipResource struct {
	ID        string `json:"id"`
	IPID      string `json:"ip_id"`
	IPAddress string `json:"ip_address"`
	Address   string `json:"address"`
}

// reserveResp tolerates either a flat object or one wrapped in {"ip": {...}}.
type reserveResp struct {
	IP *ipResource `json:"ip"`
	ipResource
}

func (r reserveResp) resolve() (id, addr string) {
	if r.IP != nil {
		return firstNonEmpty(r.IP.ID, r.IP.IPID), firstNonEmpty(r.IP.IPAddress, r.IP.Address)
	}
	return firstNonEmpty(r.ID, r.IPID), firstNonEmpty(r.IPAddress, r.Address)
}

func (p *Provider) Allocate(ctx context.Context) (provider.AllocatedIP, error) {
	req, err := p.newReq(ctx, http.MethodPost, p.ipsPath(), map[string]any{})
	if err != nil {
		return provider.AllocatedIP{}, err
	}
	var resp reserveResp
	if err := provider.DoJSON(p.client, req, p.Name(), &resp); err != nil {
		return provider.AllocatedIP{}, err
	}
	id, ipStr := resp.resolve()
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return provider.AllocatedIP{}, fmt.Errorf("mws: некорректный ip %q: %w", ipStr, err)
	}
	return provider.AllocatedIP{Addr: addr, ID: id}, nil
}

func (p *Provider) Release(ctx context.Context, ip provider.AllocatedIP) error {
	req, err := p.newReq(ctx, http.MethodDelete, p.ipsPath()+"/"+ip.ID, nil)
	if err != nil {
		return err
	}
	return provider.DoJSON(p.client, req, p.Name(), nil)
}

func (p *Provider) Attach(ctx context.Context, ip provider.AllocatedIP, vmID string) error {
	// Binding a reserved IP to a VM happens at VM-create time or by attaching to
	// a network interface — not a single standalone endpoint in the public API.
	return &provider.NotImplementedError{
		Provider: p.Name(),
		Detail:   "привязка IP — при создании ВМ или к сетевому интерфейсу; задайте ip_address вручную",
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

var _ provider.Provider = (*Provider)(nil)
