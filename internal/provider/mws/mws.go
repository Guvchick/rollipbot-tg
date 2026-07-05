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
	"sync"
	"time"

	"ip-roller-bot/internal/provider"
)

const (
	defaultBaseURL = "https://vpc.mwsapis.ru"
	defaultIAMURL  = "https://iam.mwsapis.ru"

	// The address may be assigned asynchronously — poll status.ipAddress.
	pollInterval = 700 * time.Millisecond
	pollTimeout  = 25 * time.Second
)

type Config struct {
	APIURL string // vpc base, defaults to https://vpc.mwsapis.ru
	IAMURL string // iam base, defaults to https://iam.mwsapis.ru

	// Authorized (ES256) key — the bot signs the JWT itself. Provide EITHER the
	// three separate fields, OR the whole downloaded JSON in AuthorizedKey.
	PrivateKey       string // ES256 private key PEM
	KeyID            string // authorized key id (JWT kid)
	ServiceAccountID string // service account id (JWT iss)
	AuthorizedKey    string // OR the whole downloaded key JSON

	Token        string // OR a ready IAM token (Bearer), e.g. from `mws iam create-token`
	ProjectID    string
	Region       string // optional (unused by externalAddresses, kept for compat)
	NetworkID    string // optional
	SubnetworkID string // optional
}

type Provider struct {
	token       string
	privPEM     string
	keyID       string
	saID        string
	authKeyJSON string
	base        string
	iamBase     string
	cfg         Config
	client      *http.Client
	caps        provider.RollCaps

	mu     sync.Mutex
	iam    string
	iamExp time.Time
}

func New(cfg Config, caps provider.RollCaps) *Provider {
	base := cfg.APIURL
	if base == "" {
		base = defaultBaseURL
	}
	iamBase := cfg.IAMURL
	if iamBase == "" {
		iamBase = defaultIAMURL
	}
	// Any id field may carry the full pasted resource path — split it up front
	// (addrPath interpolates ProjectID, the JWT needs the separate ids).
	keyID, saID, projectID := expandResourcePaths(
		strings.TrimSpace(cfg.KeyID), strings.TrimSpace(cfg.ServiceAccountID), strings.TrimSpace(cfg.ProjectID))
	cfg.ProjectID = projectID
	return &Provider{
		token:       sanitizeToken(cfg.Token),
		privPEM:     strings.TrimSpace(cfg.PrivateKey),
		keyID:       keyID,
		saID:        saID,
		authKeyJSON: strings.TrimSpace(cfg.AuthorizedKey),
		base:        strings.TrimRight(base, "/"),
		iamBase:     strings.TrimRight(iamBase, "/"),
		cfg:         cfg,
		client:      &http.Client{Timeout: 30 * time.Second},
		caps:        caps,
	}
}

// hasAuthKey reports whether an authorized key (separate fields or JSON) is set.
func (p *Provider) hasAuthKey() bool {
	return p.authKeyJSON != "" || p.privPEM != ""
}

// bearer returns the IAM token to send. MWS's VPC API needs a real IAM token
// (a signed JWS), NOT the static v1.… API key (that one is only for Artifact
// Registry / GPT). Preferred: an authorized key the bot signs into a JWT and
// exchanges (auto-refresh). Fallback: a ready token from `mws iam create-token`.
func (p *Provider) bearer(ctx context.Context) (string, error) {
	// The authorized key wins over a pasted token: the bot re-issues IAM tokens
	// itself, while a pasted one протухает и начинает давать 401.
	if p.hasAuthKey() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.iam != "" && time.Now().Before(p.iamExp.Add(-time.Minute)) {
			return p.iam, nil
		}
		tok, exp, err := p.issueIAMToken(ctx)
		if err != nil {
			return "", err
		}
		p.iam, p.iamExp = tok, exp
		return tok, nil
	}
	if p.token != "" {
		if err := checkToken(p.token); err != nil {
			return "", err
		}
		return p.token, nil
	}
	return "", fmt.Errorf("mws: нет ключа — задай authorized_key (JSON «Авторизованного ключа») или private_key + key_id + service_account_id, либо token")
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
		return fmt.Errorf("mws: IAM-токен не принят (протух/неверный). Надёжно: задай authorized_key (JSON «Авторизованного ключа») — бот обновляет токен сам. Либо обнови token: mws iam create-token. NB: v1.… API-ключ для VPC НЕ подходит: %w", err)
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
	tok, err := p.bearer(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, p.base+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
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
