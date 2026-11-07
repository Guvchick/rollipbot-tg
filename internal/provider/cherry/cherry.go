// Package cherry implements the Provider for Cherry Servers floating IPs.
// Auth: "Authorization: Bearer <api key>" (portal.cherryservers.com → Settings
// → API Keys). Endpoints mirror the official Go client (cherrygo/ipaddresses.go).
// Docs: https://api.cherryservers.com/doc/#tag/Ip-Addresses
//
// Floating IPs are region-scoped: a roll orders a floating IP in the account's
// region, so a caught address can be targeted to a server in that region.
package cherry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"ip-roller-bot/internal/provider"
)

const defaultBaseURL = "https://api.cherryservers.com/v1"

// Every IP the bot orders carries this tag; ListUnused only offers tagged IPs
// for cleanup, so floating IPs the user created by hand are never deleted.
const (
	tagKey   = "created_by"
	tagValue = "ip-roller-bot"
)

// The create response normally carries the address; if it doesn't, we poll the
// resource until it does (same safety net as Timeweb).
const (
	defaultPollInterval = 1 * time.Second
	defaultPollTimeout  = 25 * time.Second
)

type Config struct {
	APIURL    string
	Token     string
	ProjectID string // numeric project id
	Region    string // region slug, e.g. LT-Siauliai
}

type Provider struct {
	token        string
	base         string
	projectID    string
	region       string
	client       *http.Client
	caps         provider.RollCaps
	pollInterval time.Duration
	pollTimeout  time.Duration
}

func New(cfg Config, caps provider.RollCaps) *Provider {
	base := strings.TrimRight(cfg.APIURL, "/")
	if base == "" {
		base = defaultBaseURL
	}
	return &Provider{
		token:        cfg.Token,
		base:         base,
		projectID:    cfg.ProjectID,
		region:       cfg.Region,
		client:       &http.Client{Timeout: 30 * time.Second},
		caps:         caps,
		pollInterval: defaultPollInterval,
		pollTimeout:  defaultPollTimeout,
	}
}

func (p *Provider) Name() string            { return "cherry" }
func (p *Provider) Caps() provider.RollCaps { return p.caps }

// SetHTTPClient routes all REST calls through c (e.g. a proxy client).
func (p *Provider) SetHTTPClient(c *http.Client) { p.client = c }

// ipAddress mirrors the Cherry Servers IP model. targeted_to/assigned_to are
// the server the IP is bound to, routed_to the subnet IP it is routed via —
// all empty for an unbound floating IP.
type ipAddress struct {
	ID         string            `json:"id"`
	Address    string            `json:"address"`
	CIDR       string            `json:"cidr"`
	Type       string            `json:"type"`
	Region     region            `json:"region"`
	TargetedTo server            `json:"targeted_to"`
	AssignedTo server            `json:"assigned_to"`
	RoutedTo   routedTo          `json:"routed_to"`
	Tags       map[string]string `json:"tags"`
}

type region struct {
	Slug string `json:"slug"`
}

type server struct {
	ID int `json:"id"`
}

type routedTo struct {
	ID string `json:"id"`
}

// bound reports whether the IP is attached to a server or routed to a subnet.
func (ip ipAddress) bound() bool {
	return ip.TargetedTo.ID != 0 || ip.AssignedTo.ID != 0 || ip.RoutedTo.ID != ""
}

// addr returns the IP's address, falling back to the cidr when address is empty.
func (ip ipAddress) addr() (netip.Addr, bool) {
	if a, err := netip.ParseAddr(ip.Address); err == nil {
		return a, true
	}
	if pfx, err := netip.ParsePrefix(ip.CIDR); err == nil {
		return pfx.Addr(), true
	}
	return netip.Addr{}, false
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
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func (p *Provider) Allocate(ctx context.Context) (provider.AllocatedIP, error) {
	body := map[string]any{
		"region": p.region,
		"tags":   map[string]string{tagKey: tagValue},
	}
	req, err := p.newReq(ctx, http.MethodPost, "/projects/"+p.projectID+"/ips", body)
	if err != nil {
		return provider.AllocatedIP{}, err
	}
	var ip ipAddress
	if err := provider.DoJSON(p.client, req, p.Name(), &ip); err != nil {
		return provider.AllocatedIP{}, p.mapErr(err)
	}
	if ip.ID == "" {
		return provider.AllocatedIP{}, fmt.Errorf("cherry: пустой id в ответе создания floating ip")
	}
	addr, ok := ip.addr()
	if !ok {
		// No address yet — poll for it; if it never comes, delete the orphan so
		// it doesn't keep billing.
		addr, err = p.waitForIP(ctx, ip.ID)
		if err != nil {
			p.releaseQuietly(ip.ID)
			return provider.AllocatedIP{}, err
		}
	}
	return provider.AllocatedIP{Addr: addr, ID: ip.ID}, nil
}

// waitForIP polls GET /ips/{id} until the address appears, the context is
// cancelled, or pollTimeout elapses.
func (p *Provider) waitForIP(ctx context.Context, id string) (netip.Addr, error) {
	deadline := time.Now().Add(p.pollTimeout)
	for {
		req, err := p.newReq(ctx, http.MethodGet, "/ips/"+id, nil)
		if err != nil {
			return netip.Addr{}, err
		}
		var ip ipAddress
		if err := provider.DoJSON(p.client, req, p.Name(), &ip); err != nil {
			return netip.Addr{}, err
		}
		if addr, ok := ip.addr(); ok {
			return addr, nil
		}
		if time.Now().After(deadline) {
			return netip.Addr{}, fmt.Errorf("cherry: floating ip %s не получил адрес за %s", id, p.pollTimeout)
		}
		select {
		case <-ctx.Done():
			return netip.Addr{}, ctx.Err()
		case <-time.After(p.pollInterval):
		}
	}
}

// mapErr turns non-retryable 4xx answers into provider.RefusedError carrying
// the API's own message ({"code":…, "message":…}), so the user sees why Cherry
// refused (bad key, unknown region, floating IP limit, …). 429/5xx pass
// through as *provider.APIError so the engine backs off and retries.
func (p *Provider) mapErr(err error) error {
	var apiErr *provider.APIError
	if !errors.As(err, &apiErr) || apiErr.Retryable() {
		return err
	}
	var body struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal([]byte(apiErr.Body), &body)
	msg := strings.TrimSpace(body.Message)

	switch apiErr.StatusCode {
	case http.StatusUnauthorized:
		return &provider.RefusedError{Provider: p.Name(), Detail: "API-ключ не принят — проверь token (portal.cherryservers.com → Settings → API Keys)"}
	case http.StatusForbidden:
		return &provider.RefusedError{Provider: p.Name(), Detail: "у API-ключа нет прав на проект " + p.projectID}
	case http.StatusNotFound:
		return &provider.RefusedError{Provider: p.Name(), Detail: "проект " + p.projectID + " не найден — проверь project_id"}
	}
	if msg == "" {
		return err
	}
	return &provider.RefusedError{Provider: p.Name(), Detail: fmt.Sprintf("API отказал (регион %s): %s", p.region, msg)}
}

// releaseQuietly deletes an IP best-effort, on a fresh short context so cleanup
// still runs when the roll context is already cancelled.
func (p *Provider) releaseQuietly(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = p.Release(ctx, provider.AllocatedIP{ID: id})
}

func (p *Provider) Release(ctx context.Context, ip provider.AllocatedIP) error {
	req, err := p.newReq(ctx, http.MethodDelete, "/ips/"+ip.ID, nil)
	if err != nil {
		return err
	}
	return provider.DoJSON(p.client, req, p.Name(), nil)
}

// Attach targets the floating IP to a server (vmID = numeric server id).
func (p *Provider) Attach(ctx context.Context, ip provider.AllocatedIP, vmID string) error {
	serverID, err := strconv.Atoi(strings.TrimSpace(vmID))
	if err != nil || serverID <= 0 {
		return fmt.Errorf("cherry: id сервера должен быть числом, получено %q", vmID)
	}
	req, err := p.newReq(ctx, http.MethodPut, "/ips/"+ip.ID, map[string]any{"targeted_to": serverID})
	if err != nil {
		return err
	}
	return provider.DoJSON(p.client, req, p.Name(), nil)
}

// ListUnused returns unbound floating IPs in the account's region that the bot
// itself ordered (tagged) — leaked addresses from interrupted rolls.
func (p *Provider) ListUnused(ctx context.Context) ([]provider.UnusedIP, error) {
	req, err := p.newReq(ctx, http.MethodGet, "/projects/"+p.projectID+"/ips", nil)
	if err != nil {
		return nil, err
	}
	var ips []ipAddress
	if err := provider.DoJSON(p.client, req, p.Name(), &ips); err != nil {
		return nil, err
	}
	var out []provider.UnusedIP
	for _, ip := range ips {
		if ip.Type != "floating-ip" || ip.bound() || ip.Tags[tagKey] != tagValue {
			continue
		}
		if p.region != "" && !strings.EqualFold(ip.Region.Slug, p.region) {
			continue
		}
		addr, ok := ip.addr()
		if !ok {
			continue
		}
		out = append(out, provider.UnusedIP{Addr: addr, ID: ip.ID})
	}
	return out, nil
}

var (
	_ provider.Provider         = (*Provider)(nil)
	_ provider.Cleaner          = (*Provider)(nil)
	_ provider.HTTPConfigurable = (*Provider)(nil)
)
