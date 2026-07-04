package mws

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"ip-roller-bot/internal/provider"
)

// issueTokenPath is the custom method that exchanges a signed JWT for an IAM
// token. Confirmed from mws.ru/docs (iam v1).
const issueTokenPath = "/iam/v1/tokens/:issueServiceAccountToken"

// authorizedKey is the JSON MWS gives you when you create an "Авторизованный"
// key. Field names mirror the downloadable file (snake_case).
type authorizedKey struct {
	ID               string `json:"id"`
	ServiceAccountID string `json:"service_account_id"`
	PrivateKey       string `json:"private_key"`
	// camelCase fallbacks, just in case
	KeyID2 string `json:"keyId"`
	SAID2  string `json:"serviceAccountId"`
	PK2    string `json:"privateKey"`
}

func (k authorizedKey) keyID() string { return firstNonEmpty(k.ID, k.KeyID2) }
func (k authorizedKey) saID() string  { return firstNonEmpty(k.ServiceAccountID, k.SAID2) }
func (k authorizedKey) pem() string   { return firstNonEmpty(k.PrivateKey, k.PK2) }

// issueIAMToken signs an ES256 JWT with the authorized key and exchanges it for
// an IAM token; returns the token and its expiry.
func (p *Provider) issueIAMToken(ctx context.Context) (string, time.Time, error) {
	var k authorizedKey
	if err := json.Unmarshal([]byte(p.authKeyJSON), &k); err != nil {
		return "", time.Time{}, fmt.Errorf("mws: authorized_key должен быть JSON скачанного ключа: %w", err)
	}
	if k.keyID() == "" || k.saID() == "" || k.pem() == "" {
		return "", time.Time{}, fmt.Errorf("mws: в authorized_key нет id / service_account_id / private_key")
	}
	priv, err := parseECPrivateKey(k.pem())
	if err != nil {
		return "", time.Time{}, fmt.Errorf("mws: private_key: %w", err)
	}

	aud := p.iamBase + issueTokenPath
	jwt, err := signES256JWT(priv, k.keyID(), k.saID(), aud)
	if err != nil {
		return "", time.Time{}, err
	}

	// Body field for the JWT is "token" (endpoint schema exposes apiKey/token/secret).
	body, _ := json.Marshal(map[string]any{"token": jwt})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.iamBase+issueTokenPath, strings.NewReader(string(body)))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	var resp struct {
		Token      string `json:"token"`
		IAMToken   string `json:"iamToken"`
		ExpiresAt  string `json:"expiresAt"`
		ExpireTime string `json:"expireTime"`
	}
	if err := provider.DoJSON(p.client, req, p.Name(), &resp); err != nil {
		return "", time.Time{}, fmt.Errorf("mws: обмен JWT→IAM: %w", err)
	}
	tok := firstNonEmpty(resp.Token, resp.IAMToken)
	if tok == "" {
		return "", time.Time{}, fmt.Errorf("mws: пустой IAM-токен в ответе обмена")
	}
	exp := time.Now().Add(50 * time.Minute)
	if t, err := time.Parse(time.RFC3339, firstNonEmpty(resp.ExpiresAt, resp.ExpireTime)); err == nil {
		exp = t
	}
	return tok, exp, nil
}

func parseECPrivateKey(pemStr string) (*ecdsa.PrivateKey, error) {
	// downloaded JSON escapes newlines; tolerate both real and literal "\n"
	pemStr = strings.ReplaceAll(pemStr, "\\n", "\n")
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("не PEM")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ключ не ECDSA (нужен ES256/P-256)")
	}
	return ec, nil
}

func signES256JWT(priv *ecdsa.PrivateKey, kid, iss, aud string) (string, error) {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	header := b64([]byte(fmt.Sprintf(`{"typ":"JWT","alg":"ES256","kid":%q}`, kid)))
	now := time.Now()
	payload := b64([]byte(fmt.Sprintf(`{"iss":%q,"aud":%q,"iat":%d,"exp":%d}`,
		iss, aud, now.Unix(), now.Add(time.Hour).Unix())))
	signingInput := header + "." + payload

	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return "", err
	}
	// JOSE ES256 signature is R||S, each left-padded to 32 bytes (P-256).
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + b64(sig), nil
}
