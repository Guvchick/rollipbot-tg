package mws

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ip-roller-bot/internal/provider"
)

func testKeyPEM(t *testing.T) string {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestProbeMintFindsWorkingShape(t *testing.T) {
	// This server accepts ONLY POST /iam/v2/tokens with a {"jwt":…} body.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/iam/v2/tokens" {
			b, _ := io.ReadAll(r.Body)
			var m map[string]string
			if json.Unmarshal(b, &m) == nil && m["jwt"] != "" {
				_, _ = w.Write([]byte(`{"token":"iam-ok","expireTime":"2030-01-02T03:04:05Z"}`))
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	old := probeMintShapes
	probeMintShapes = true
	defer func() { probeMintShapes = old }()

	p := New(Config{IAMURL: srv.URL, PrivateKey: testKeyPEM(t), KeyID: "k", ServiceAccountID: "sa", ProjectID: "proj"}, provider.RollCaps{})
	tok, _, err := p.issueIAMToken(context.Background())
	if err != nil {
		t.Fatalf("probe should have found the working shape, got err: %v", err)
	}
	if tok != "iam-ok" {
		t.Errorf("token = %q, want iam-ok", tok)
	}
}

func TestProbeMintAll401IsKeyProblem(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized) // reject every shape
	}))
	defer srv.Close()

	old := probeMintShapes
	probeMintShapes = true
	defer func() { probeMintShapes = old }()

	p := New(Config{IAMURL: srv.URL, PrivateKey: testKeyPEM(t), KeyID: "k", ServiceAccountID: "sa", ProjectID: "proj"}, provider.RollCaps{})
	_, _, err := p.issueIAMToken(context.Background())
	if err == nil {
		t.Fatal("expected an error when every shape 401s")
	}
	if !strings.Contains(err.Error(), "ключе/claims") {
		t.Errorf("all-401 error %q should point at key/claims, not request shape", err)
	}
}

func TestDecodeJWTField(t *testing.T) {
	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	hdr := `{"typ":"JWT","alg":"ES256","kid":"access-key-x"}`
	pl := `{"sub":"projects/p/serviceAccounts/sa","exp":1893456000}`
	jwt := b64(hdr) + "." + b64(pl) + "." + b64("sig-bytes")
	body := []byte(`{"jwt":"` + jwt + `"}`)

	gotH, gotP, ok := decodeJWTField(body)
	if !ok {
		t.Fatal("decodeJWTField ok=false, want true")
	}
	if gotH != hdr {
		t.Errorf("header = %q, want %q", gotH, hdr)
	}
	if gotP != pl {
		t.Errorf("payload = %q, want %q", gotP, pl)
	}

	// A body without a jwt field is not a token exchange → ok=false.
	if _, _, ok := decodeJWTField([]byte(`{"metadata":{"name":"roll-1"}}`)); ok {
		t.Error("decodeJWTField on non-jwt body ok=true, want false")
	}
}
