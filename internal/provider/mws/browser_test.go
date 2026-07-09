package mws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"ip-roller-bot/internal/provider"
)

func TestBrowserTokenReplaysCurl(t *testing.T) {
	// A fake console token endpoint: accepts the captured browser Authorization
	// and returns a fresh IAM token.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer session-abc" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"iamToken":"iam-xyz","expiresAt":"2030-01-02T03:04:05Z"}`))
	}))
	defer srv.Close()

	curl := "curl '" + srv.URL + "/refresh' -H 'authorization: Bearer session-abc'"
	p := New(Config{RefreshCurl: curl, ProjectID: "p"}, provider.RollCaps{})

	tok, err := p.bearer(context.Background())
	if err != nil {
		t.Fatalf("bearer via refresh_curl: %v", err)
	}
	if tok != "iam-xyz" {
		t.Errorf("token = %q, want iam-xyz", tok)
	}
	// Second call within expiry must reuse the cached token (no re-fetch needed).
	if tok2, _ := p.bearer(context.Background()); tok2 != "iam-xyz" {
		t.Errorf("cached token = %q, want iam-xyz", tok2)
	}
}

func TestExtractBearer(t *testing.T) {
	cases := []struct{ in, want string }{
		{"eyJhbGc.payload.sig", "eyJhbGc.payload.sig"},                               // bare token unchanged
		{"Bearer eyJhbGc.payload.sig", "eyJhbGc.payload.sig"},                        // "Bearer x"
		{"authorization: Bearer eyJhbGc.payload.sig", "eyJhbGc.payload.sig"},         // header line
		{"Authorization: bearer eyJhbGc.payload.sig", "eyJhbGc.payload.sig"},         // case-insensitive
		{"  -H 'authorization: Bearer eyJhbGc.payload.sig' ", "eyJhbGc.payload.sig"}, // inside a curl flag
	}
	for _, c := range cases {
		if got := extractBearer(c.in); got != c.want {
			t.Errorf("extractBearer(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseCurl(t *testing.T) {
	curl := `curl 'https://iam.mwsapis.ru/iam/v2/tokens' \
  -H 'accept: application/json' \
  -H 'authorization: Bearer eyJsession' \
  -b 'sid=abc; csrf=xyz' \
  --data-raw '{"grant":"refresh"}' \
  --compressed`

	ba, err := parseCurl(curl)
	if err != nil {
		t.Fatalf("parseCurl error: %v", err)
	}
	if ba.method != "POST" {
		t.Errorf("method = %q, want POST (data present)", ba.method)
	}
	if ba.url != "https://iam.mwsapis.ru/iam/v2/tokens" {
		t.Errorf("url = %q", ba.url)
	}
	if got := ba.header.Get("Authorization"); got != "Bearer eyJsession" {
		t.Errorf("Authorization = %q", got)
	}
	if got := ba.header.Get("Cookie"); got != "sid=abc; csrf=xyz" {
		t.Errorf("Cookie = %q", got)
	}
	if string(ba.body) != `{"grant":"refresh"}` {
		t.Errorf("body = %q", ba.body)
	}

	// Explicit -X and no body → GET, and the bare URL token is picked up.
	ba2, err := parseCurl(`curl -X GET "https://iam.mwsapis.ru/whoami" -H "accept: application/json"`)
	if err != nil {
		t.Fatalf("parseCurl 2 error: %v", err)
	}
	if ba2.method != "GET" || ba2.url != "https://iam.mwsapis.ru/whoami" {
		t.Errorf("ba2 = %+v, want GET whoami", ba2)
	}

	if _, err := parseCurl(`curl -H 'x: y'`); err == nil {
		t.Error("parseCurl with no URL should error")
	}
}
