package timeweb

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ip-roller-bot/internal/provider"
)

func TestAllocateReleaseAttach(t *testing.T) {
	var (
		gotAuth   string
		allocBody bool
		delPath   string
		bindPath  string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/floating-ips":
			allocBody = true
			_, _ = w.Write([]byte(`{"ip":{"id":"fip-1","ip":"185.12.7.9"}}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/floating-ips/fip-1":
			delPath = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/floating-ips/fip-1/bind":
			bindPath = r.URL.Path
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := New("tok", "spb-1", provider.RollCaps{})
	p.base = srv.URL
	ctx := context.Background()

	ip, err := p.Allocate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ip.Addr.String() != "185.12.7.9" || ip.ID != "fip-1" {
		t.Fatalf("allocate = %+v", ip)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("auth header = %q, want Bearer tok", gotAuth)
	}
	if !allocBody {
		t.Error("allocate endpoint not hit")
	}

	if err := p.Release(ctx, ip); err != nil {
		t.Fatal(err)
	}
	if delPath != "/floating-ips/fip-1" {
		t.Errorf("release path = %q", delPath)
	}

	if err := p.Attach(ctx, ip, "123"); err != nil {
		t.Fatal(err)
	}
	if bindPath != "/floating-ips/fip-1/bind" {
		t.Errorf("attach path = %q", bindPath)
	}
}

// Timeweb assigns the address asynchronously: the create response has an empty
// ip, and the address only appears on a later GET. Allocate must poll for it.
func TestAllocatePollsForAsyncIP(t *testing.T) {
	var gets int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/floating-ips":
			// created, but no address yet (Timeweb returns ip: null)
			_, _ = w.Write([]byte(`{"ip":{"id":"fip-9","ip":null}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/floating-ips/fip-9":
			// address appears only on the third poll
			if atomic.AddInt32(&gets, 1) < 3 {
				_, _ = w.Write([]byte(`{"ip":{"id":"fip-9","ip":null}}`))
				return
			}
			_, _ = w.Write([]byte(`{"ip":{"id":"fip-9","ip":"185.12.7.42"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := New("tok", "", provider.RollCaps{})
	p.base = srv.URL
	p.pollInterval = time.Millisecond
	p.pollTimeout = 5 * time.Second

	ip, err := p.Allocate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ip.Addr.String() != "185.12.7.42" || ip.ID != "fip-9" {
		t.Fatalf("allocate = %+v", ip)
	}
	if atomic.LoadInt32(&gets) < 3 {
		t.Errorf("expected at least 3 polls, got %d", gets)
	}
}

// If the address never arrives, Allocate must give up with a clear error rather
// than trying to parse an empty ip.
func TestAllocatePollTimeout(t *testing.T) {
	var deleted int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodDelete && r.URL.Path == "/floating-ips/fip-x":
			atomic.StoreInt32(&deleted, 1)
			w.WriteHeader(http.StatusNoContent)
		default: // POST create and GET poll both return no address
			_, _ = w.Write([]byte(`{"ip":{"id":"fip-x","ip":null}}`))
		}
	}))
	defer srv.Close()

	p := New("tok", "", provider.RollCaps{})
	p.base = srv.URL
	p.pollInterval = time.Millisecond
	p.pollTimeout = 20 * time.Millisecond

	if _, err := p.Allocate(context.Background()); err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
	// the orphaned, unaddressed IP must be cleaned up so it doesn't keep billing
	if atomic.LoadInt32(&deleted) != 1 {
		t.Error("orphaned floating ip was not released after poll timeout")
	}
}

// ListUnused must return only floating IPs not bound to a resource (and skip
// ones still without an address).
func TestListUnused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/floating-ips" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"meta":{"total":4},"ips":[
			{"id":"free-1","ip":"1.1.1.1","resource_id":null,"resource_type":null},
			{"id":"bound-1","ip":"2.2.2.2","resource_id":123,"resource_type":"server"},
			{"id":"free-2","ip":"3.3.3.3","resource_id":null,"resource_type":null},
			{"id":"pending","ip":null,"resource_id":null,"resource_type":null}
		]}`))
	}))
	defer srv.Close()

	p := New("tok", "", provider.RollCaps{})
	p.base = srv.URL

	unused, err := p.ListUnused(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, u := range unused {
		got[u.ID] = u.Addr.String()
	}
	if len(got) != 2 || got["free-1"] != "1.1.1.1" || got["free-2"] != "3.3.3.3" {
		t.Fatalf("ListUnused = %v, want free-1 and free-2 only", got)
	}
	if _, ok := got["bound-1"]; ok {
		t.Error("bound IP must not be reported as unused")
	}
	if _, ok := got["pending"]; ok {
		t.Error("address-less IP must be skipped")
	}
}

// The bot reaches ListUnused through the Account wrapper's embedded provider, so
// the capability assertion must survive that indirection.
func TestAccountAsCleaner(t *testing.T) {
	acc := provider.NewAccount(New("tok", "", provider.RollCaps{}), "timeweb", "tw1", 1)
	if _, ok := acc.AsCleaner(); !ok {
		t.Error("timeweb account should expose the Cleaner capability")
	}
}

// A 403 daily_limit_exceeded must surface as a typed QuotaError carrying the
// resume date, so the engine can pause the account instead of retrying.
func TestAllocateDailyLimitBecomesQuotaError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"status_code":403,"error_code":"daily_limit_exceeded","message":"Daily limit exceeded","details":{"limit":10,"available_date_for_creation":"2026-07-04T20:29:10.000Z"},"response_id":"9df8a0a0"}`))
	}))
	defer srv.Close()

	p := New("tok", "", provider.RollCaps{})
	p.base = srv.URL

	_, err := p.Allocate(context.Background())
	var q *provider.QuotaError
	if !errors.As(err, &q) {
		t.Fatalf("err = %v, want *provider.QuotaError", err)
	}
	if q.Limit != 10 {
		t.Errorf("limit = %d, want 10", q.Limit)
	}
	want, _ := time.Parse(time.RFC3339, "2026-07-04T20:29:10Z")
	if !q.AvailableAt.Equal(want) {
		t.Errorf("availableAt = %v, want %v", q.AvailableAt, want)
	}
}

func TestAllocateAPIErrorRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	p := New("tok", "", provider.RollCaps{})
	p.base = srv.URL

	_, err := p.Allocate(context.Background())
	var apiErr *provider.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *provider.APIError", err)
	}
	if apiErr.StatusCode != http.StatusTooManyRequests || !apiErr.Retryable() {
		t.Errorf("status = %d retryable = %v, want 429/retryable", apiErr.StatusCode, apiErr.Retryable())
	}
}

// A 404 no_free_ip means the zone's pool is empty — surface it as a typed
// RefusedError naming the zone, not a raw API dump.
func TestAllocateNoFreeIPBecomesRefusedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"status_code":404,"error_code":"no_free_ip","message":"There are no available free IPs","response_id":"6bde9645"}`))
	}))
	defer srv.Close()

	p := New("tok", "spb-3", provider.RollCaps{})
	p.base = srv.URL

	_, err := p.Allocate(context.Background())
	var re *provider.RefusedError
	if !errors.As(err, &re) {
		t.Fatalf("err = %v, want *provider.RefusedError", err)
	}
	if !strings.Contains(re.Detail, "spb-3") {
		t.Errorf("detail = %q, want it to name the zone spb-3", re.Detail)
	}
}
