// Package timeweb implements the Provider for Timeweb Cloud floating IPs.
// Docs: https://timeweb.cloud/api-docs
package timeweb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"ip-roller-bot/internal/provider"
)

const defaultBaseURL = "https://api.timeweb.cloud/api/v1"

// Timeweb assigns the address to a freshly created floating IP asynchronously,
// so the create response usually carries an empty ip — we poll the resource
// until the address appears.
const (
	defaultPollInterval = 700 * time.Millisecond
	defaultPollTimeout  = 25 * time.Second
)

type Provider struct {
	token        string
	zone         string
	base         string
	client       *http.Client
	caps         provider.RollCaps
	pollInterval time.Duration
	pollTimeout  time.Duration
}

func New(token, zone string, caps provider.RollCaps) *Provider {
	return &Provider{
		token:        token,
		zone:         zone,
		base:         defaultBaseURL,
		client:       &http.Client{Timeout: 30 * time.Second},
		caps:         caps,
		pollInterval: defaultPollInterval,
		pollTimeout:  defaultPollTimeout,
	}
}

func (p *Provider) Name() string            { return "timeweb" }
func (p *Provider) Caps() provider.RollCaps { return p.caps }

// floatingIP mirrors the Timeweb FloatingIp model. `ip` is nullable (empty
// while the address is still being provisioned); `resource_id`/`resource_type`
// are null until the IP is bound to a server.
type floatingIP struct {
	ID           string   `json:"id"`
	IP           string   `json:"ip"`
	ResourceID   *float64 `json:"resource_id"`
	ResourceType *string  `json:"resource_type"`
}

// bound reports whether the floating IP is attached to a resource.
func (f floatingIP) bound() bool {
	return f.ResourceID != nil || (f.ResourceType != nil && *f.ResourceType != "")
}

// ipResp wraps a single floating IP: {"ip": {...}} — used by both create and
// GET-by-id. Note the outer key is "ip" and the address is the inner "ip".
type ipResp struct {
	IP floatingIP `json:"ip"`
}

// listResp wraps the list endpoint: {"ips": [...]}.
type listResp struct {
	IPs []floatingIP `json:"ips"`
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

func (p *Provider) Allocate(ctx context.Context) (provider.AllocatedIP, error) {
	body := map[string]any{"is_ddos_guard": false}
	if p.zone != "" {
		body["availability_zone"] = p.zone
	}
	req, err := p.newReq(ctx, http.MethodPost, "/floating-ips", body)
	if err != nil {
		return provider.AllocatedIP{}, err
	}
	var resp ipResp
	if err := provider.DoJSON(p.client, req, p.Name(), &resp); err != nil {
		return provider.AllocatedIP{}, err
	}
	fip := resp.IP
	if fip.ID == "" {
		return provider.AllocatedIP{}, fmt.Errorf("timeweb: пустой id в ответе создания floating ip")
	}
	// The address is provisioned asynchronously — poll until it appears. If it
	// never does, delete the orphaned IP so it doesn't keep billing.
	if fip.IP == "" {
		ip, err := p.waitForIP(ctx, fip.ID)
		if err != nil {
			p.releaseQuietly(fip.ID)
			return provider.AllocatedIP{}, err
		}
		fip.IP = ip
	}
	addr, err := netip.ParseAddr(fip.IP)
	if err != nil {
		return provider.AllocatedIP{}, fmt.Errorf("timeweb: некорректный ip %q: %w", fip.IP, err)
	}
	return provider.AllocatedIP{Addr: addr, ID: fip.ID}, nil
}

// waitForIP polls GET /floating-ips/{id} until Timeweb assigns the address, the
// context is cancelled, or pollTimeout elapses.
func (p *Provider) waitForIP(ctx context.Context, id string) (string, error) {
	deadline := time.Now().Add(p.pollTimeout)
	for {
		req, err := p.newReq(ctx, http.MethodGet, "/floating-ips/"+id, nil)
		if err != nil {
			return "", err
		}
		var resp ipResp
		if err := provider.DoJSON(p.client, req, p.Name(), &resp); err != nil {
			return "", err
		}
		if ip := resp.IP.IP; ip != "" {
			return ip, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("timeweb: floating ip %s не получил адрес за %s", id, p.pollTimeout)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(p.pollInterval):
		}
	}
}

// releaseQuietly deletes a floating IP best-effort, on a fresh short context so
// cleanup still runs when the roll context is already cancelled.
func (p *Provider) releaseQuietly(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = p.Release(ctx, provider.AllocatedIP{ID: id})
}

func (p *Provider) Release(ctx context.Context, ip provider.AllocatedIP) error {
	req, err := p.newReq(ctx, http.MethodDelete, "/floating-ips/"+ip.ID, nil)
	if err != nil {
		return err
	}
	return provider.DoJSON(p.client, req, p.Name(), nil)
}

func (p *Provider) Attach(ctx context.Context, ip provider.AllocatedIP, vmID string) error {
	// vmID is the server id; Timeweb expects a numeric resource_id when possible.
	var resourceID any = vmID
	if n, err := strconv.Atoi(vmID); err == nil {
		resourceID = n
	}
	body := map[string]any{"resource_id": resourceID, "resource_type": "server"}
	req, err := p.newReq(ctx, http.MethodPost, "/floating-ips/"+ip.ID+"/bind", body)
	if err != nil {
		return err
	}
	return provider.DoJSON(p.client, req, p.Name(), nil)
}

// ListUnused returns floating IPs not bound to any resource — leaked/orphaned
// addresses that keep billing. The caller decides which to delete.
func (p *Provider) ListUnused(ctx context.Context) ([]provider.UnusedIP, error) {
	req, err := p.newReq(ctx, http.MethodGet, "/floating-ips?limit=1000", nil)
	if err != nil {
		return nil, err
	}
	var resp listResp
	if err := provider.DoJSON(p.client, req, p.Name(), &resp); err != nil {
		return nil, err
	}
	var out []provider.UnusedIP
	for _, f := range resp.IPs {
		if f.bound() || f.IP == "" {
			continue
		}
		addr, err := netip.ParseAddr(f.IP)
		if err != nil {
			continue // skip anything without a parseable address
		}
		out = append(out, provider.UnusedIP{Addr: addr, ID: f.ID})
	}
	return out, nil
}

var (
	_ provider.Provider = (*Provider)(nil)
	_ provider.Cleaner  = (*Provider)(nil)
)
