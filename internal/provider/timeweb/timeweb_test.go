package timeweb

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

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
