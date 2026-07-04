package timeweb

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
			_, _ = w.Write([]byte(`{"floating_ip":{"id":"fip-1","ip":"185.12.7.9"}}`))
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
			// created, but no address yet
			_, _ = w.Write([]byte(`{"floating_ip":{"id":"fip-9","ip":"","status":"in_process"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/floating-ips/fip-9":
			// address appears only on the third poll
			if atomic.AddInt32(&gets, 1) < 3 {
				_, _ = w.Write([]byte(`{"floating_ip":{"id":"fip-9","ip":"","status":"in_process"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"floating_ip":{"id":"fip-9","ip":"185.12.7.42","status":"created"}}`))
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
			_, _ = w.Write([]byte(`{"floating_ip":{"id":"fip-x","ip":"","status":"in_process"}}`))
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
