// Package gcore implements the Provider for Gcore Cloud floating IPs.
// Auth header is literally "Authorization: apikey <token>".
// Docs: https://gcore.com/docs/api-reference/cloud
package gcore

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

const defaultBaseURL = "https://api.gcore.com/cloud"

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

type floatingIPResp struct {
	ID                string   `json:"id"`
	FloatingIPAddress string   `json:"floating_ip_address"`
	Tasks             []string `json:"tasks"`
}

func (p *Provider) fipPath() string {
	return fmt.Sprintf("/v1/floatingips/%s/%d", p.projectID, p.regionID)
}

func (p *Provider) Allocate(ctx context.Context) (provider.AllocatedIP, error) {
	req, err := p.newReq(ctx, http.MethodPost, p.fipPath(), map[string]any{})
	if err != nil {
		return provider.AllocatedIP{}, err
	}
	var resp floatingIPResp
	if err := provider.DoJSON(p.client, req, p.Name(), &resp); err != nil {
		return provider.AllocatedIP{}, err
	}
	if resp.FloatingIPAddress == "" {
		// Some Gcore endpoints return an async task list instead of the address.
		return provider.AllocatedIP{}, &provider.NotImplementedError{
			Provider: p.Name(),
			Detail:   "ответ без floating_ip_address (асинхронная задача) — нужно опрашивать /v1/tasks",
		}
	}
	addr, err := netip.ParseAddr(resp.FloatingIPAddress)
	if err != nil {
		return provider.AllocatedIP{}, fmt.Errorf("gcore: некорректный ip %q: %w", resp.FloatingIPAddress, err)
	}
	return provider.AllocatedIP{Addr: addr, ID: resp.ID}, nil
}

func (p *Provider) Release(ctx context.Context, ip provider.AllocatedIP) error {
	req, err := p.newReq(ctx, http.MethodDelete, p.fipPath()+"/"+ip.ID, nil)
	if err != nil {
		return err
	}
	return provider.DoJSON(p.client, req, p.Name(), nil)
}

func (p *Provider) Attach(ctx context.Context, ip provider.AllocatedIP, portID string) error {
	body := map[string]any{"port_id": portID}
	req, err := p.newReq(ctx, http.MethodPost, p.fipPath()+"/"+ip.ID+"/assign", body)
	if err != nil {
		return err
	}
	return provider.DoJSON(p.client, req, p.Name(), nil)
}

var _ provider.Provider = (*Provider)(nil)
