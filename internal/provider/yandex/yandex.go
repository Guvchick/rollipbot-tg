// Package yandex implements the Provider for Yandex Cloud static public IPs.
// It exchanges a Yandex Passport OAuth token for a short-lived IAM token, then
// reserves/deletes external IPv4 addresses via the VPC API (async operations).
// Docs: https://yandex.cloud/docs/vpc/api-ref/Address/
package yandex

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"ip-roller-bot/internal/provider"
)

const (
	defaultAPIURL = "https://vpc.api.cloud.yandex.net/vpc/v1"
	defaultIAMURL = "https://iam.api.cloud.yandex.net/iam/v1"
	defaultOpURL  = "https://operation.api.cloud.yandex.net/operations"

	pollInterval = 700 * time.Millisecond
	pollTimeout  = 30 * time.Second
)

type Config struct {
	APIURL     string
	IAMURL     string
	OpURL      string
	OAuthToken string
	FolderID   string
	ZoneID     string
}

type Provider struct {
	cfg    Config
	client *http.Client
	caps   provider.RollCaps

	mu     sync.Mutex
	iam    string
	iamExp time.Time
}

func New(cfg Config, caps provider.RollCaps) *Provider {
	if cfg.APIURL == "" {
		cfg.APIURL = defaultAPIURL
	}
	if cfg.IAMURL == "" {
		cfg.IAMURL = defaultIAMURL
	}
	if cfg.OpURL == "" {
		cfg.OpURL = defaultOpURL
	}
	if cfg.ZoneID == "" {
		cfg.ZoneID = "ru-central1-a"
	}
	return &Provider{cfg: cfg, client: &http.Client{Timeout: 40 * time.Second}, caps: caps}
}

func (p *Provider) Name() string            { return "yandex" }
func (p *Provider) Caps() provider.RollCaps { return p.caps }

// SetHTTPClient routes REST calls through c (e.g. a proxy client).
func (p *Provider) SetHTTPClient(c *http.Client) { p.client = c }

// iamToken returns a cached IAM token, exchanging the OAuth token when needed.
func (p *Provider) iamToken(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.iam != "" && time.Now().Before(p.iamExp.Add(-time.Minute)) {
		return p.iam, nil
	}
	body, _ := json.Marshal(map[string]string{"yandexPassportOauthToken": p.cfg.OAuthToken})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.IAMURL+"/tokens", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	var resp struct {
		IAMToken  string `json:"iamToken"`
		ExpiresAt string `json:"expiresAt"`
	}
	if err := provider.DoJSON(p.client, req, p.Name(), &resp); err != nil {
		return "", fmt.Errorf("yandex: обмен OAuth→IAM: %w", err)
	}
	if resp.IAMToken == "" {
		return "", fmt.Errorf("yandex: пустой IAM-токен в ответе")
	}
	p.iam = resp.IAMToken
	if t, err := time.Parse(time.RFC3339, resp.ExpiresAt); err == nil {
		p.iamExp = t
	} else {
		p.iamExp = time.Now().Add(11 * time.Hour)
	}
	return p.iam, nil
}

func (p *Provider) newReq(ctx context.Context, method, url string, body any) (*http.Request, error) {
	tok, err := p.iamToken(ctx)
	if err != nil {
		return nil, err
	}
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return req, nil
}

type address struct {
	ID          string `json:"id"`
	ExternalIP4 struct {
		Address string `json:"address"`
	} `json:"externalIpv4Address"`
}

type operation struct {
	ID       string `json:"id"`
	Done     bool   `json:"done"`
	Metadata struct {
		AddressID string `json:"addressId"`
	} `json:"metadata"`
	Response *address `json:"response"`
	Error    *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (p *Provider) Allocate(ctx context.Context) (provider.AllocatedIP, error) {
	req, err := p.newReq(ctx, http.MethodPost, p.cfg.APIURL+"/addresses", map[string]any{
		"folderId":                p.cfg.FolderID,
		"externalIpv4AddressSpec": map[string]any{"zoneId": p.cfg.ZoneID},
	})
	if err != nil {
		return provider.AllocatedIP{}, err
	}
	var op operation
	if err := provider.DoJSON(p.client, req, p.Name(), &op); err != nil {
		return provider.AllocatedIP{}, err
	}
	op, err = p.waitOp(ctx, op)
	if err != nil {
		return provider.AllocatedIP{}, err
	}
	id, ip := op.Metadata.AddressID, ""
	if op.Response != nil {
		if op.Response.ID != "" {
			id = op.Response.ID
		}
		ip = op.Response.ExternalIP4.Address
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		// clean up the reserved-but-unusable address
		if id != "" {
			p.releaseQuietly(id)
		}
		return provider.AllocatedIP{}, fmt.Errorf("yandex: некорректный ip %q: %w", ip, err)
	}
	return provider.AllocatedIP{Addr: addr, ID: id}, nil
}

// waitOp polls the operation until done (or timeout).
func (p *Provider) waitOp(ctx context.Context, op operation) (operation, error) {
	deadline := time.Now().Add(pollTimeout)
	for {
		if op.Error != nil {
			return op, fmt.Errorf("yandex: операция %s: %s", op.ID, op.Error.Message)
		}
		if op.Done {
			return op, nil
		}
		if time.Now().After(deadline) {
			return op, fmt.Errorf("yandex: операция %s не завершилась за %s", op.ID, pollTimeout)
		}
		select {
		case <-ctx.Done():
			return op, ctx.Err()
		case <-time.After(pollInterval):
		}
		req, err := p.newReq(ctx, http.MethodGet, p.cfg.OpURL+"/"+op.ID, nil)
		if err != nil {
			return op, err
		}
		var next operation
		if err := provider.DoJSON(p.client, req, p.Name(), &next); err != nil {
			return op, err
		}
		op = next
	}
}

func (p *Provider) Release(ctx context.Context, ip provider.AllocatedIP) error {
	req, err := p.newReq(ctx, http.MethodDelete, p.cfg.APIURL+"/addresses/"+ip.ID, nil)
	if err != nil {
		return err
	}
	return provider.DoJSON(p.client, req, p.Name(), nil)
}

func (p *Provider) releaseQuietly(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = p.Release(ctx, provider.AllocatedIP{ID: id})
}

// Attach binds a reserved address to an instance's network interface — this
// requires the instance id and NIC index, so it's not a standalone step here.
func (p *Provider) Attach(ctx context.Context, ip provider.AllocatedIP, vmID string) error {
	return &provider.NotImplementedError{
		Provider: p.Name(),
		Detail:   "привязка адреса — при создании ВМ или к сетевому интерфейсу инстанса (нужны instance_id и индекс NIC)",
	}
}

var (
	_ provider.Provider         = (*Provider)(nil)
	_ provider.HTTPConfigurable = (*Provider)(nil)
)
