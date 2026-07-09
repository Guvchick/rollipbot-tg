// Package provider defines the single abstraction the engine uses to roll IPs,
// plus shared error types. Each cloud service has its own adapter sub-package
// implementing Provider.
package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"
)

// AllocatedIP is a freshly allocated public/floating address.
type AllocatedIP struct {
	Addr netip.Addr // the IP itself
	ID   string     // provider-side resource id (used for release/attach)
}

// Provider is the contract every service adapter implements.
type Provider interface {
	// Name is the machine name ("timeweb", "vkcloud", ...).
	Name() string

	// Allocate reserves a new public/floating IP. The address is chosen by the
	// provider (usually random out of a pool).
	Allocate(ctx context.Context) (AllocatedIP, error)

	// Release frees an address that did not match the mask.
	Release(ctx context.Context, ip AllocatedIP) error

	// Attach binds a matched IP to a VM (vmID is provider-specific: server id,
	// neutron port id, etc.).
	Attach(ctx context.Context, ip AllocatedIP, vmID string) error

	// Caps describes how often and how much this provider may be rolled.
	Caps() RollCaps
}

// UnusedIP is a provider-side floating/public address that is reserved but not
// bound to any resource — a candidate for automatic cleanup.
type UnusedIP struct {
	Addr netip.Addr
	ID   string
}

// HTTPConfigurable is an optional capability: adapters whose REST calls can be
// routed through a custom http.Client (e.g. via a proxy) implement it. The
// registry sets the client per account when a proxy is bound.
type HTTPConfigurable interface {
	SetHTTPClient(*http.Client)
}

// Cleaner is an optional capability. Providers that can enumerate their own
// unbound addresses implement it, so the bot can purge floating IPs that leaked
// (e.g. from an interrupted roll) and aren't attached to any service. Callers
// delete each returned IP via Release, skipping any they want to keep.
type Cleaner interface {
	// ListUnused returns addresses not bound to any resource.
	ListUnused(ctx context.Context) ([]UnusedIP, error)
}

// AsCleaner reports whether the account's adapter supports cleanup.
func (a *Account) AsCleaner() (Cleaner, bool) {
	c, ok := a.Provider.(Cleaner)
	return c, ok
}

// RollCaps describes how many and how often an account may be rolled.
type RollCaps struct {
	MaxRollsPerRun int           // hard cap on attempts per single run
	DailyCap       int           // max new IPs per day (0 = no daily limit, quota only)
	RateLimitRPS   float64       // requests per second to the API
	RollDelay      time.Duration // pause between consecutive rolls (0 = default jitter)
	CostPerRoll    string        // informational, to warn the user
	Strategy       string        // "floating" | "recreate" | "additional_ip" | ...
}

// QuotaError means the provider refused to allocate because a usage quota
// (usually a daily creation limit) is exhausted. AvailableAt, when set, is when
// allocation may resume; Limit is the provider's cap when known.
type QuotaError struct {
	Provider    string
	Limit       int
	AvailableAt time.Time
}

func (e *QuotaError) Error() string {
	if !e.AvailableAt.IsZero() {
		return fmt.Sprintf("%s: дневная квота исчерпана (лимит %d), снова с %s",
			e.Provider, e.Limit, e.AvailableAt.Format(time.RFC3339))
	}
	return fmt.Sprintf("%s: дневная квота исчерпана (лимит %d)", e.Provider, e.Limit)
}

// Account wraps a concrete adapter as one credentialed account. Several accounts
// can exist per provider type; each gets a unique key so the engine's rate
// limiter and daily counter track it independently. It embeds Provider, so
// Allocate/Release/Attach/Caps are served by the inner adapter while Name()
// returns the unique account key.
type Account struct {
	Provider
	key   string
	typ   string
	label string
	id    int64
}

// NewAccount builds an account wrapper. The key (typ#id) is stable across
// restarts, so daily caps and pool rows stay consistent.
func NewAccount(inner Provider, typ, label string, id int64) *Account {
	return &Account{
		Provider: inner,
		key:      fmt.Sprintf("%s#%d", typ, id),
		typ:      typ,
		label:    label,
		id:       id,
	}
}

func (a *Account) Name() string  { return a.key }   // engine keys on this
func (a *Account) Key() string   { return a.key }   // alias, for clarity at call sites
func (a *Account) Type() string  { return a.typ }   // provider type, e.g. "timeweb"
func (a *Account) Label() string { return a.label } // human label
func (a *Account) ID() int64     { return a.id }    // accounts-table row id

// APIError wraps a non-2xx HTTP response from a provider REST API.
type APIError struct {
	Provider   string
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s API: HTTP %d: %s", e.Provider, e.StatusCode, truncate(e.Body, 300))
}

// Retryable reports whether the request may be retried after a backoff
// (rate-limit or transient server error).
func (e *APIError) Retryable() bool {
	return e.StatusCode == 429 || e.StatusCode >= 500
}

// ErrNotImplemented marks operations a provider cannot perform via API
// (e.g. panel-only hosters, or strategies that need extra account setup).
var ErrNotImplemented = errors.New("operation not implemented for this provider")

// NotImplementedError carries a human-readable reason and unwraps to
// ErrNotImplemented.
type NotImplementedError struct {
	Provider string
	Detail   string
}

func (e *NotImplementedError) Error() string {
	return fmt.Sprintf("%s: %s", e.Provider, e.Detail)
}

func (e *NotImplementedError) Unwrap() error { return ErrNotImplemented }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
