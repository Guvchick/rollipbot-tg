package yandex

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ip-roller-bot/internal/provider"
)

func TestAllocateExchangesTokenAndPollsOperation(t *testing.T) {
	var (
		gotOAuth string
		gotBear  string
		polls    int
		deleted  string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/iam/v1/tokens":
			// OAuth -> IAM exchange
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), "oauth-abc") {
				gotOAuth = "oauth-abc"
			}
			_, _ = w.Write([]byte(`{"iamToken":"iam-xyz","expiresAt":"` + time.Now().Add(time.Hour).Format(time.RFC3339) + `"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/vpc/v1/addresses":
			gotBear = r.Header.Get("Authorization")
			// async op, not done yet
			_, _ = w.Write([]byte(`{"id":"op-1","done":false,"metadata":{"addressId":"addr-1"}}`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/operations/op-1"):
			polls++
			if polls < 2 {
				_, _ = w.Write([]byte(`{"id":"op-1","done":false}`))
				return
			}
			_, _ = w.Write([]byte(`{"id":"op-1","done":true,"response":{"id":"addr-1","externalIpv4Address":{"address":"51.250.1.2"}}}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/vpc/v1/addresses/addr-1":
			deleted = "addr-1"
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := New(Config{
		APIURL: srv.URL + "/vpc/v1", IAMURL: srv.URL + "/iam/v1", OpURL: srv.URL + "/operations",
		OAuthToken: "oauth-abc", FolderID: "fold-1", ZoneID: "ru-central1-a",
	}, provider.RollCaps{})

	ip, err := p.Allocate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ip.Addr.String() != "51.250.1.2" || ip.ID != "addr-1" {
		t.Fatalf("allocate = %+v", ip)
	}
	if gotOAuth != "oauth-abc" {
		t.Error("OAuth token was not sent to the IAM exchange")
	}
	if gotBear != "Bearer iam-xyz" {
		t.Errorf("API call used auth %q, want Bearer iam-xyz", gotBear)
	}
	if err := p.Release(context.Background(), ip); err != nil {
		t.Fatal(err)
	}
	if deleted != "addr-1" {
		t.Error("Release did not DELETE the address")
	}
}

func TestAllocateOperationError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/iam/v1/tokens":
			_, _ = w.Write([]byte(`{"iamToken":"t","expiresAt":"` + time.Now().Add(time.Hour).Format(time.RFC3339) + `"}`))
		default:
			_, _ = w.Write([]byte(`{"id":"op","done":true,"error":{"code":8,"message":"quota exceeded"}}`))
		}
	}))
	defer srv.Close()
	p := New(Config{APIURL: srv.URL + "/vpc/v1", IAMURL: srv.URL + "/iam/v1", OpURL: srv.URL + "/operations", OAuthToken: "x", FolderID: "f"}, provider.RollCaps{})
	if _, err := p.Allocate(context.Background()); err == nil {
		t.Fatal("expected operation error")
	}
}
