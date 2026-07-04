package mws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ip-roller-bot/internal/provider"
)

func TestAllocateUsesExternalAddressAndReleases(t *testing.T) {
	var (
		gotAuth    string
		createName string
		delName    string
	)
	const prefix = "/vpc/v1/projects/proj-1/externalAddresses/"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		switch {
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, prefix):
			createName = strings.TrimPrefix(r.URL.Path, prefix)
			if r.URL.Query().Get("createOnly") != "true" {
				t.Errorf("create should pass createOnly=true, got %q", r.URL.RawQuery)
			}
			// ip in status.ipAddress, delete uses metadata.name
			_, _ = w.Write([]byte(`{"metadata":{"id":"uuid-1","name":"` + createName + `"},"status":{"ready":{"state":"READY"},"ipAddress":"89.108.5.7"}}`))
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, prefix):
			delName = strings.TrimPrefix(r.URL.Path, prefix)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := New(Config{APIURL: srv.URL, Token: "iam-tok", ProjectID: "proj-1"}, provider.RollCaps{})
	ip, err := p.Allocate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ip.Addr.String() != "89.108.5.7" {
		t.Fatalf("allocate ip = %v", ip.Addr)
	}
	// the resource id (for release) must be the NAME, not metadata.id
	if ip.ID != createName {
		t.Errorf("id = %q, want the created name %q", ip.ID, createName)
	}
	if gotAuth != "Bearer iam-tok" {
		t.Errorf("auth = %q, want Bearer iam-tok", gotAuth)
	}
	if err := p.Release(context.Background(), ip); err != nil {
		t.Fatal(err)
	}
	if delName != createName {
		t.Errorf("release name = %q, want %q", delName, createName)
	}
}

func TestAllocatePollsWhenIPPending(t *testing.T) {
	const prefix = "/vpc/v1/projects/p/externalAddresses/"
	var gets int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, prefix)
		switch r.Method {
		case http.MethodPost:
			_, _ = w.Write([]byte(`{"metadata":{"name":"` + name + `"},"status":{"ipAddress":""}}`)) // not ready
		case http.MethodGet:
			gets++
			if gets < 2 {
				_, _ = w.Write([]byte(`{"metadata":{"name":"` + name + `"},"status":{"ipAddress":""}}`))
				return
			}
			_, _ = w.Write([]byte(`{"metadata":{"name":"` + name + `"},"status":{"ipAddress":"89.108.1.1"}}`))
		}
	}))
	defer srv.Close()
	p := New(Config{APIURL: srv.URL, Token: "t", ProjectID: "p"}, provider.RollCaps{})
	p.client.Timeout = 5 * 1e9
	ip, err := p.Allocate(context.Background())
	if err != nil || ip.Addr.String() != "89.108.1.1" {
		t.Fatalf("allocate = %v %v", ip, err)
	}
}

func TestSanitizeToken(t *testing.T) {
	// line-wrapped / spaced paste artifacts are stripped; a clean token is unchanged
	if got := sanitizeToken("eyJhbG.ab\ncd\n.sig"); got != "eyJhbG.abcd.sig" {
		t.Errorf("sanitizeToken wrapped = %q", got)
	}
	if got := sanitizeToken("  eyJ.a.b  "); got != "eyJ.a.b" {
		t.Errorf("sanitizeToken trim = %q", got)
	}
}

func TestDefaultBaseURL(t *testing.T) {
	p := New(Config{Token: "t", ProjectID: "p"}, provider.RollCaps{})
	if p.base != "https://vpc.mwsapis.ru" {
		t.Errorf("default base = %q, want https://vpc.mwsapis.ru", p.base)
	}
}
