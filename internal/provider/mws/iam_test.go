package mws

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ip-roller-bot/internal/provider"
)

// End-to-end: the bot signs an ES256 JWT, exchanges it via
// GET :issueServiceAccountToken (JWT in Authorization: Bearer, serviceAccount
// query), and uses the returned IAM token for the VPC call. The mock IAM server
// verifies the JWT cryptographically, so a bad signature fails the test.
func TestAuthorizedKeyJWTFlow(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	keyJSON, _ := json.Marshal(map[string]string{
		"id": "key-1", "service_account_id": "sa-1", "private_key": string(pemBytes),
	})

	const vpcPrefix = "/vpc/v1/projects/p/externalAddresses/"
	var jwtVerified bool
	var vpcAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/iam/v2/tokens/:issueServiceAccountToken":
			if r.Method != http.MethodGet {
				t.Errorf("issue method = %s, want GET", r.Method)
			}
			// The self-signed JWT rides in Authorization: Bearer (proven by the
			// live probe — GET+Bearer is the only form that reaches the handler).
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				t.Errorf("issue Authorization = %q, want a Bearer JWT", auth)
			}
			jwt := strings.TrimPrefix(auth, "Bearer ")
			if sa := r.URL.Query().Get("serviceAccount"); sa != "projects/p/serviceAccounts/sa-1" {
				t.Errorf("serviceAccount = %q, want projects/p/serviceAccounts/sa-1", sa)
			}
			if verifyES256(t, jwt, &priv.PublicKey) {
				jwtVerified = true
			}
			if kid := jwtField(t, jwt, 0, "kid"); kid != "key-1" {
				t.Errorf("jwt kid = %q, want key-1", kid)
			}
			if sub := jwtField(t, jwt, 1, "sub"); sub != "projects/p/serviceAccounts/sa-1" {
				t.Errorf("jwt sub = %q, want projects/p/serviceAccounts/sa-1", sub)
			}
			_, _ = w.Write([]byte(`{"token":"iam-xyz"}`))
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, vpcPrefix):
			vpcAuth = r.Header.Get("Authorization")
			name := strings.TrimPrefix(r.URL.Path, vpcPrefix)
			_, _ = w.Write([]byte(`{"metadata":{"name":"` + name + `"},"status":{"ipAddress":"89.108.7.7"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := New(Config{APIURL: srv.URL, IAMURL: srv.URL, AuthorizedKey: string(keyJSON), ProjectID: "p"}, provider.RollCaps{})
	ip, err := p.Allocate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ip.Addr.String() != "89.108.7.7" {
		t.Fatalf("ip = %v", ip.Addr)
	}
	if !jwtVerified {
		t.Error("IAM server did not receive a valid ES256 JWT")
	}
	if vpcAuth != "Bearer iam-xyz" {
		t.Errorf("vpc auth = %q, want the issued IAM token", vpcAuth)
	}
}

// The issue response may nest the token in an object — both shapes must parse.
func TestIssueTokenResponseShapes(t *testing.T) {
	cases := map[string]string{
		`{"token":"tok-flat"}`:                    "tok-flat",
		`{"iamToken":"tok-iam"}`:                  "tok-iam",
		`{"access_token":"tok-oauth"}`:            "tok-oauth",
		`{"token":{"value":"tok-nested"}}`:        "tok-nested",
		`{"token":{"accessToken":"tok-nested2"}}`: "tok-nested2",
	}
	for in, want := range cases {
		var r issueTokenResponse
		if err := json.Unmarshal([]byte(in), &r); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got := r.token(); got != want {
			t.Errorf("token(%s) = %q, want %q", in, got, want)
		}
	}
	var r issueTokenResponse
	_ = json.Unmarshal([]byte(`{"token":"x","expireTime":"2030-01-02T03:04:05Z"}`), &r)
	if exp, ok := r.expiry(); !ok || exp.Year() != 2030 {
		t.Errorf("expiry = %v %v", exp, ok)
	}
}

// jwtClaims decodes part `idx` (0=header, 1=payload) of a compact JWT into its
// JSON object.
func jwtClaims(t *testing.T, jwt string, idx int) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt has %d parts, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[idx])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// jwtField decodes part `idx` (0=header, 1=payload) of a compact JWT and
// returns the string claim `name`.
func jwtField(t *testing.T, jwt string, idx int, name string) string {
	t.Helper()
	s, _ := jwtClaims(t, jwt, idx)[name].(string)
	return s
}

// verifyES256 checks a compact JWT's ES256 signature against pub.
func verifyES256(t *testing.T, jwt string, pub *ecdsa.PublicKey) bool {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, digest[:], r, s)
}

// readJWTBearer pulls the self-signed JWT out of the Authorization: Bearer header.
func readJWTBearer(t *testing.T, r *http.Request) string {
	t.Helper()
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		t.Fatalf("issue Authorization = %q, want a Bearer JWT", auth)
	}
	jwt := strings.TrimPrefix(auth, "Bearer ")
	if jwt == "" {
		t.Fatal("empty Bearer JWT")
	}
	return jwt
}

// TestIssueIAMTokenRequestShape locks the exact wire contract of the token
// exchange (the thing that produced HTTP 401 «JWS parsing attempt failed»): a
// GET to the :issueServiceAccountToken path with the self-signed JWT in
// Authorization: Bearer (proven by the live probe — POST → 401, no-slash → 404),
// whose JWT parses into header{typ,alg,kid} + payload{sub,iat,exp} with no stray
// iss/aud.
func TestIssueIAMTokenRequestShape(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	var (
		gotMethod, gotPath, gotJWT, gotQuery string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotQuery = r.URL.Query().Get("serviceAccount")
		gotJWT = readJWTBearer(t, r)
		_, _ = w.Write([]byte(`{"token":"iam-abc","expireTime":"2030-01-02T03:04:05Z"}`))
	}))
	defer srv.Close()

	p := New(Config{IAMURL: srv.URL, PrivateKey: pemStr, KeyID: "key-9", ServiceAccountID: "sa-9", ProjectID: "proj-9"}, provider.RollCaps{})
	tok, exp, err := p.issueIAMToken(context.Background())
	if err != nil {
		t.Fatalf("issueIAMToken: %v", err)
	}
	if tok != "iam-abc" {
		t.Errorf("token = %q, want iam-abc", tok)
	}
	if exp.Year() != 2030 {
		t.Errorf("expiry = %v, want the response expireTime", exp)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %s, want GET", gotMethod)
	}
	if gotPath != "/iam/v2/tokens/:issueServiceAccountToken" {
		t.Errorf("path = %q, want /iam/v2/tokens/:issueServiceAccountToken", gotPath)
	}
	if gotQuery != "projects/proj-9/serviceAccounts/sa-9" {
		t.Errorf("serviceAccount = %q, want projects/proj-9/serviceAccounts/sa-9", gotQuery)
	}
	// The JWT must be a valid ES256 JWS with exactly the documented claims.
	if !verifyES256(t, gotJWT, &priv.PublicKey) {
		t.Fatal("body JWT did not verify as ES256")
	}
	if typ := jwtField(t, gotJWT, 0, "typ"); typ != "JWT" {
		t.Errorf("jwt typ = %q, want JWT", typ)
	}
	if alg := jwtField(t, gotJWT, 0, "alg"); alg != "ES256" {
		t.Errorf("jwt alg = %q, want ES256", alg)
	}
	if kid := jwtField(t, gotJWT, 0, "kid"); kid != "key-9" {
		t.Errorf("jwt kid = %q, want key-9", kid)
	}
	if sub := jwtField(t, gotJWT, 1, "sub"); sub != "projects/proj-9/serviceAccounts/sa-9" {
		t.Errorf("jwt sub = %q, want projects/proj-9/serviceAccounts/sa-9", sub)
	}
	// exp must be present and in the future; iss/aud are intentionally absent
	// (MWS docs list only sub + exp).
	payload := jwtClaims(t, gotJWT, 1)
	if _, ok := payload["exp"]; !ok {
		t.Error("jwt payload missing exp")
	}
	for _, unexpected := range []string{"iss", "aud"} {
		if _, ok := payload[unexpected]; ok {
			t.Errorf("jwt payload has %q, which MWS docs do not require", unexpected)
		}
	}
}

// mapIssueErr must turn the IAM endpoint's 401 into an actionable hint that
// names where the JWT goes and what to check.
func TestIssueIAMTokenSurfaces401Hint(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	// (a) body «JWS parsing attempt failed» → parse-level hint (points at MWS_DEBUG,
	// not key/sub — the JWS didn't even parse).
	t.Run("jws-parse body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":"UNAUTHENTICATED","description":"JWS parsing attempt failed."}`))
		}))
		defer srv.Close()
		p := New(Config{IAMURL: srv.URL, PrivateKey: pemStr, KeyID: "k", ServiceAccountID: "sa", ProjectID: "proj"}, provider.RollCaps{})
		_, _, err := p.issueIAMToken(context.Background())
		if err == nil {
			t.Fatal("expected an error on 401")
		}
		for _, want := range []string{"JWS", "401", "MWS_DEBUG"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("parse-level 401 error %q does not mention %q", err, want)
			}
		}
	})

	// (b) empty-body 401 with a grpc-message header → verification hint (key_id/sub),
	// and the folded header detail surfaces in the error.
	t.Run("empty body with grpc-message header", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Grpc-Message", "signature verification failed")
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()
		p := New(Config{IAMURL: srv.URL, PrivateKey: pemStr, KeyID: "k", ServiceAccountID: "sa", ProjectID: "proj"}, provider.RollCaps{})
		_, _, err := p.issueIAMToken(context.Background())
		if err == nil {
			t.Fatal("expected an error on 401")
		}
		for _, want := range []string{"key_id", "sub", "401", "signature verification failed"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("verification 401 error %q does not mention %q", err, want)
			}
		}
	})
}

func TestNoCredentialsError(t *testing.T) {
	p := New(Config{ProjectID: "p"}, provider.RollCaps{}) // no token, no authorized_key
	if _, err := p.Allocate(context.Background()); err == nil {
		t.Fatal("expected error when neither token nor authorized_key is set")
	}
}

// The console's key list shows the bare base64 SPKI public key — the exact
// thing users paste into authorized_key. The error must say "публичный ключ",
// not a JSON parse failure.
func TestKeyMixupsAreNamed(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(spki)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))

	cases := []struct {
		name, authKey, token, want string
	}{
		{"public key base64 in authorized_key", pubB64, "", "ПУБЛИЧНЫЙ"},
		{"public key PEM in authorized_key", pubPEM, "", "ПУБЛИЧНЫЙ"},
		{"api key in authorized_key", "v1.abcdef", "", "API-ключ"},
		{"iam token in authorized_key", "eyJhbGciOi.xx.yy", "", "token"},
		{"json with only public_key", `{"id":"k","service_account_id":"sa","public_key":"` + pubB64 + `"}`, "", "public_key"},
		{"api key in token", "", "v1.abcdef", "API-ключ"},
		{"key json in token", "", `{"id":"k"}`, "authorized_key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckAuthMaterial("", "", "", "p", tc.authKey, tc.token)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestCheckAuthMaterialAcceptsGoodKey(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	keyJSON, _ := json.Marshal(map[string]string{
		"id": "key-1", "service_account_id": "sa-1", "private_key": pemStr,
	})
	if err := CheckAuthMaterial("", "", "", "p", string(keyJSON), ""); err != nil {
		t.Fatalf("downloaded JSON rejected: %v", err)
	}
	if err := CheckAuthMaterial(pemStr, "key-1", "sa-1", "p", "", ""); err != nil {
		t.Fatalf("separate fields rejected: %v", err)
	}
	// bare private-key PEM pasted into authorized_key is tolerated, but the
	// key id / service account are still required
	if err := CheckAuthMaterial("", "key-1", "sa-1", "p", pemStr, ""); err != nil {
		t.Fatalf("bare PEM in authorized_key rejected: %v", err)
	}
	if err := CheckAuthMaterial("", "", "", "p", pemStr, ""); err == nil {
		t.Fatal("expected missing key_id/service_account_id error")
	}
	// token-only setup stays allowed (it just expires)
	if err := CheckAuthMaterial("", "", "", "p", "", "eyJhbGciOi.xx.yy"); err != nil {
		t.Fatalf("token-only rejected: %v", err)
	}
	// project_id is always required (VPC paths and the JWT sub need it)
	if err := CheckAuthMaterial(pemStr, "key-1", "sa-1", "", "", ""); err == nil || !strings.Contains(err.Error(), "project_id") {
		t.Fatalf("missing project_id not named: %v", err)
	}
}

// The user pastes the whole resource path instead of hunting for each id —
// both the IAM form and the console URL must decompose into the three ids.
func TestParseResourcePath(t *testing.T) {
	for _, s := range []string{
		"iam/projects/project-foxday128/serviceAccounts/test/authorizedKeys/access-key",
		"projects/project-foxday128/serviceAccounts/test/authorizedKeys/access-key",
	} {
		p, sa, k, ok := ParseResourcePath(s)
		if !ok || p != "project-foxday128" || sa != "test" || k != "access-key" {
			t.Errorf("ParseResourcePath(%q) = %q,%q,%q,%v", s, p, sa, k, ok)
		}
	}
	// console list URL: no key segment
	p, sa, k, ok := ParseResourcePath("https://console.mws.ru/iam/project-foxday128/service-accounts/test/access-keys")
	if !ok || p != "project-foxday128" || sa != "test" || k != "" {
		t.Errorf("console URL = %q,%q,%q,%v", p, sa, k, ok)
	}
	if _, _, _, ok := ParseResourcePath("-----BEGIN EC PRIVATE KEY-----\nMHcC…"); ok {
		t.Error("PEM must not parse as a resource path")
	}
}

// A full resource path pasted into key_id must satisfy validation and the
// provider (project/sa/key are pulled out of it).
func TestResourcePathInKeyID(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	path := "iam/projects/project-foxday128/serviceAccounts/test/authorizedKeys/access-key"
	if err := CheckAuthMaterial(pemStr, path, "", "", "", ""); err != nil {
		t.Fatalf("path in key_id rejected: %v", err)
	}
	p := New(Config{PrivateKey: pemStr, KeyID: path}, provider.RollCaps{})
	if p.keyID != "access-key" || p.saID != "test" || p.cfg.ProjectID != "project-foxday128" {
		t.Fatalf("New did not expand path: keyID=%q saID=%q project=%q", p.keyID, p.saID, p.cfg.ProjectID)
	}
}

// An authorized key must win over a pasted (possibly stale) token: the bot can
// sign fresh IAM tokens itself.
func TestAuthorizedKeyPreferredOverToken(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	keyJSON, _ := json.Marshal(map[string]string{
		"id": "key-1", "service_account_id": "sa-1", "private_key": pemStr,
	})

	var vpcAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/iam/v2/tokens/:issueServiceAccountToken" {
			_, _ = w.Write([]byte(`{"token":"iam-fresh"}`))
			return
		}
		vpcAuth = r.Header.Get("Authorization")
		name := strings.TrimPrefix(r.URL.Path, "/vpc/v1/projects/p/externalAddresses/")
		_, _ = w.Write([]byte(`{"metadata":{"name":"` + name + `"},"status":{"ipAddress":"89.108.7.7"}}`))
	}))
	defer srv.Close()

	p := New(Config{APIURL: srv.URL, IAMURL: srv.URL, AuthorizedKey: string(keyJSON), Token: "stale-token", ProjectID: "p"}, provider.RollCaps{})
	if _, err := p.Allocate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if vpcAuth != "Bearer iam-fresh" {
		t.Fatalf("vpc auth = %q, want the freshly issued IAM token, not the stale pasted one", vpcAuth)
	}
}
