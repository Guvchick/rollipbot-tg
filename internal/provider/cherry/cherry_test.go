package cherry

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ip-roller-bot/internal/provider"
)

func newTest(srvURL string) *Provider {
	p := New(Config{APIURL: srvURL, Token: "tok", ProjectID: "123", Region: "LT-Siauliai"}, provider.RollCaps{})
	p.pollInterval = time.Millisecond
	return p
}

func TestAllocateReleaseAttach(t *testing.T) {
	var (
		gotAuth    string
		createBody map[string]any
		delPath    string
		attachBody map[string]any
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/projects/123/ips":
			_ = json.NewDecoder(r.Body).Decode(&createBody)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"ip-1","address":"5.199.170.9","cidr":"5.199.170.9/32","type":"floating-ip","region":{"slug":"LT-Siauliai"}}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/ips/ip-1":
			delPath = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && r.URL.Path == "/ips/ip-1":
			_ = json.NewDecoder(r.Body).Decode(&attachBody)
			_, _ = w.Write([]byte(`{"id":"ip-1","address":"5.199.170.9","targeted_to":{"id":777}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := newTest(srv.URL)
	ctx := context.Background()

	ip, err := p.Allocate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ip.Addr.String() != "5.199.170.9" || ip.ID != "ip-1" {
		t.Fatalf("allocate = %+v", ip)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("auth header = %q, want Bearer tok", gotAuth)
	}
	if createBody["region"] != "LT-Siauliai" {
		t.Errorf("create body region = %v", createBody["region"])
	}
	if tags, _ := createBody["tags"].(map[string]any); tags[tagKey] != tagValue {
		t.Errorf("create body must tag the IP as ours, got %v", createBody["tags"])
	}

	if err := p.Release(ctx, ip); err != nil {
		t.Fatal(err)
	}
	if delPath != "/ips/ip-1" {
		t.Errorf("release path = %q", delPath)
	}

	if err := p.Attach(ctx, ip, "777"); err != nil {
		t.Fatal(err)
	}
	// targeted_to must be sent as a number, not a string
	if v, ok := attachBody["targeted_to"].(float64); !ok || v != 777 {
		t.Errorf("attach body = %v, want targeted_to: 777", attachBody)
	}
	if err := p.Attach(ctx, ip, "web-1"); err == nil {
		t.Error("attach with non-numeric server id must fail")
	}
}

// If the create response has no address yet, Allocate polls GET /ips/{id}.
func TestAllocatePollsForAddress(t *testing.T) {
	var gets int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			_, _ = w.Write([]byte(`{"id":"ip-9","type":"floating-ip"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/ips/ip-9":
			if atomic.AddInt32(&gets, 1) < 3 {
				_, _ = w.Write([]byte(`{"id":"ip-9"}`))
				return
			}
			_, _ = w.Write([]byte(`{"id":"ip-9","cidr":"5.199.170.42/32"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := newTest(srv.URL)
	ip, err := p.Allocate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// address taken from cidr when the address field is empty
	if ip.Addr.String() != "5.199.170.42" || ip.ID != "ip-9" {
		t.Fatalf("allocate = %+v", ip)
	}
}

// An IP that never gets an address must be deleted so it doesn't keep billing.
func TestAllocatePollTimeoutReleases(t *testing.T) {
	var deleted int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/ips/ip-x" {
			atomic.StoreInt32(&deleted, 1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write([]byte(`{"id":"ip-x"}`))
	}))
	defer srv.Close()

	p := newTest(srv.URL)
	p.pollTimeout = 20 * time.Millisecond
	if _, err := p.Allocate(context.Background()); err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
	if atomic.LoadInt32(&deleted) != 1 {
		t.Error("orphaned floating ip was not released after poll timeout")
	}
}

func TestAllocateErrorMapping(t *testing.T) {
	cases := []struct {
		status    int
		body      string
		refused   bool
		retryable bool
		contains  string
	}{
		{http.StatusBadRequest, `{"code":400,"message":"Floating IP limit reached"}`, true, false, "Floating IP limit reached"},
		{http.StatusUnauthorized, `{"code":401,"message":"Unauthorized"}`, true, false, "API-ключ"},
		{http.StatusNotFound, `{"code":404,"message":"Not found"}`, true, false, "project_id"},
		{http.StatusTooManyRequests, `{"code":429,"message":"slow down"}`, false, true, ""},
		{http.StatusInternalServerError, ``, false, true, ""},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(c.body))
		}))
		_, err := newTest(srv.URL).Allocate(context.Background())
		srv.Close()

		var refused *provider.RefusedError
		if got := errors.As(err, &refused); got != c.refused {
			t.Errorf("HTTP %d: RefusedError = %v, want %v (err %v)", c.status, got, c.refused, err)
			continue
		}
		if c.refused && !strings.Contains(refused.Detail, c.contains) {
			t.Errorf("HTTP %d: detail %q should mention %q", c.status, refused.Detail, c.contains)
		}
		var apiErr *provider.APIError
		if c.retryable && (!errors.As(err, &apiErr) || !apiErr.Retryable()) {
			t.Errorf("HTTP %d: want retryable APIError, got %v", c.status, err)
		}
	}
}

// Only our own (tagged), unbound floating IPs in the account's region are
// offered for cleanup — never the user's hand-made or attached ones.
func TestListUnused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/projects/123/ips" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`[
			{"id":"leak","address":"5.199.170.1","type":"floating-ip","region":{"slug":"LT-Siauliai"},"tags":{"created_by":"ip-roller-bot"}},
			{"id":"leak-lower","address":"5.199.170.6","type":"floating-ip","region":{"slug":"lt-siauliai"},"tags":{"created_by":"ip-roller-bot"}},
			{"id":"bound","address":"5.199.170.2","type":"floating-ip","region":{"slug":"LT-Siauliai"},"targeted_to":{"id":42},"tags":{"created_by":"ip-roller-bot"}},
			{"id":"routed","address":"5.199.170.3","type":"floating-ip","region":{"slug":"LT-Siauliai"},"routed_to":{"id":"sub-1"},"tags":{"created_by":"ip-roller-bot"}},
			{"id":"manual","address":"5.199.170.4","type":"floating-ip","region":{"slug":"LT-Siauliai"},"tags":{}},
			{"id":"other-region","address":"5.199.170.5","type":"floating-ip","region":{"slug":"NL-Amsterdam"},"tags":{"created_by":"ip-roller-bot"}},
			{"id":"primary","address":"5.199.170.7","type":"primary-ip","region":{"slug":"LT-Siauliai"},"tags":{"created_by":"ip-roller-bot"}}
		]`))
	}))
	defer srv.Close()

	got, err := newTest(srv.URL).ListUnused(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, ip := range got {
		ids = append(ids, ip.ID)
	}
	if strings.Join(ids, ",") != "leak,leak-lower" {
		t.Errorf("ListUnused ids = %v, want [leak leak-lower]", ids)
	}
}
