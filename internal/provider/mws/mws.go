// Package mws implements the Provider for MWS Cloud Platform (MTS Web Services)
// public IPs. Rolling creates an *external* address (by name), reads the
// assigned status.ipAddress, and deletes it (by name) if it doesn't match.
//
// Confirmed from mws.ru/docs/cloud-platform/api (vpc externalAddresses):
//
//	host:   https://vpc.mwsapis.ru        (api.mws.ru is dead)
//	create: POST   /vpc/v1/projects/{project}/externalAddresses/{name}?createOnly=true
//	get:    GET    /vpc/v1/projects/{project}/externalAddresses/{name}
//	delete: DELETE /vpc/v1/projects/{project}/externalAddresses/{name}
//	auth:   Authorization: Bearer <IAM-token>   (mws iam create-token)
//	body:   {"kind":"vpc/v1/externalAddress","metadata":{"name":"..."}}
//	ip:     response.status.ipAddress ; id for release = metadata.name
package mws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"ip-roller-bot/internal/provider"
)

const (
	defaultBaseURL = "https://vpc.mwsapis.ru"

	// The address may be assigned asynchronously — poll status.ipAddress.
	pollInterval = 700 * time.Millisecond
	pollTimeout  = 25 * time.Second
)

type Config struct {
	APIURL       string // base, defaults to https://vpc.mwsapis.ru
	Token        string // IAM token (Bearer)
	ProjectID    string
	Region       string // optional (unused by externalAddresses, kept for compat)
	NetworkID    string // optional
	SubnetworkID string // optional
}

type Provider struct {
	token  string
	base   string
	cfg    Config
	client *http.Client
	caps   provider.RollCaps
}

func New(cfg Config, caps provider.RollCaps) *Provider {
	base := cfg.APIURL
	if base == "" {
		base = defaultBaseURL
	}
	return &Provider{
		token:  sanitizeToken(cfg.Token),
		base:   strings.TrimRight(base, "/"),
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
		caps:   caps,
	}
}

// sanitizeToken removes whitespace/newlines a token can pick up when pasted
// (Telegram soft-wrapping, copy artifacts). A valid IAM/JWS token has none.
func sanitizeToken(s string) string {
	return strings.Join(strings.Fields(s), "")
}

// mapErr turns MWS's 401 into an actionable message about the IAM token.
func mapErr(err error) error {
	var apiErr *provider.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("mws: IAM-токен недействителен или протух — обнови (mws iam create-token) и перезапиши поле token: %w", err)
	}
	return err
}

func (p *Provider) Name() string            { return "mws" }
func (p *Provider) Caps() provider.RollCaps { return p.caps }

// SetHTTPClient routes REST calls through c (e.g. a proxy client).
func (p *Provider) SetHTTPClient(c *http.Client) { p.client = c }

func (p *Provider) addrPath(name string) string {
	return fmt.Sprintf("/vpc/v1/projects/%s/externalAddresses/%s", p.cfg.ProjectID, name)
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

// externalAddress mirrors the vpc/v1/externalAddress resource.
type externalAddress struct {
	Metadata struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"metadata"`
	Status struct {
		Ready struct {
			State   string `json:"state"`
			Message string `json:"message"`
		} `json:"ready"`
		IPAddress string `json:"ipAddress"`
	} `json:"status"`
}

// externalAddressName satisfies the API pattern ^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$.
func externalAddressName() string {
	return fmt.Sprintf("roll-%d", time.Now().UnixNano())
}

func (p *Provider) Allocate(ctx context.Context) (provider.AllocatedIP, error) {
	name := externalAddressName()
	body := map[string]any{
		"kind":     "vpc/v1/externalAddress",
		"metadata": map[string]any{"name": name},
	}
	req, err := p.newReq(ctx, http.MethodPost, p.addrPath(name)+"?createOnly=true", body)
	if err != nil {
		return provider.AllocatedIP{}, err
	}
	var ea externalAddress
	if err := provider.DoJSON(p.client, req, p.Name(), &ea); err != nil {
		return provider.AllocatedIP{}, mapErr(err)
	}
	// The delete path uses the NAME, so that (not metadata.id) is our resource id.
	id := firstNonEmpty(ea.Metadata.Name, name)
	ipStr := ea.Status.IPAddress
	if ipStr == "" {
		got, err := p.waitForIP(ctx, name)
		if err != nil {
			p.releaseQuietly(id)
			return provider.AllocatedIP{}, err
		}
		ipStr = got
	}
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		p.releaseQuietly(id)
		return provider.AllocatedIP{}, fmt.Errorf("mws: некорректный ip %q: %w", ipStr, err)
	}
	return provider.AllocatedIP{Addr: addr, ID: id}, nil
}

// waitForIP polls GET until status.ipAddress is assigned.
func (p *Provider) waitForIP(ctx context.Context, name string) (string, error) {
	deadline := time.Now().Add(pollTimeout)
	for {
		req, err := p.newReq(ctx, http.MethodGet, p.addrPath(name), nil)
		if err != nil {
			return "", err
		}
		var ea externalAddress
		if err := provider.DoJSON(p.client, req, p.Name(), &ea); err != nil {
			return "", err
		}
		if ea.Status.IPAddress != "" {
			return ea.Status.IPAddress, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("mws: адрес %s не получил ip за %s (state %q)", name, pollTimeout, ea.Status.Ready.State)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

func (p *Provider) Release(ctx context.Context, ip provider.AllocatedIP) error {
	req, err := p.newReq(ctx, http.MethodDelete, p.addrPath(ip.ID), nil)
	if err != nil {
		return err
	}
	return provider.DoJSON(p.client, req, p.Name(), nil)
}

func (p *Provider) releaseQuietly(id string) {
	if id == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = p.Release(ctx, provider.AllocatedIP{ID: id})
}

func (p *Provider) Attach(ctx context.Context, ip provider.AllocatedIP, vmID string) error {
	return &provider.NotImplementedError{
		Provider: p.Name(),
		Detail:   "привязка внешнего IP — при создании ВМ или к сетевому интерфейсу инстанса",
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

var (
	_ provider.Provider         = (*Provider)(nil)
	_ provider.HTTPConfigurable = (*Provider)(nil)
)
