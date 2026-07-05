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
	PublicKey        string `json:"public_key"`
	// camelCase fallbacks, just in case
	KeyID2 string `json:"keyId"`
	SAID2  string `json:"serviceAccountId"`
	PK2    string `json:"privateKey"`
	Pub2   string `json:"publicKey"`
}

func (k authorizedKey) keyID() string { return firstNonEmpty(k.ID, k.KeyID2) }
func (k authorizedKey) saID() string  { return firstNonEmpty(k.ServiceAccountID, k.SAID2) }
func (k authorizedKey) pem() string   { return firstNonEmpty(k.PrivateKey, k.PK2) }
func (k authorizedKey) pub() string   { return firstNonEmpty(k.PublicKey, k.Pub2) }

// resolveKeyMaterial merges the separate fields with whatever was pasted into
// authorized_key. The console's «Создать» offers three key types (Авторизованный
// / HMAC / API-ключ v1.…) and shows the PUBLIC key in the key list — people
// paste all of those here, so name the mix-up instead of leaking a parse error.
func resolveKeyMaterial(keyID, saID, privPEM, authKey string) (string, string, string, error) {
	if authKey != "" {
		compact := strings.Join(strings.Fields(authKey), "")
		switch {
		case strings.HasPrefix(compact, "{"):
			var k authorizedKey
			if err := json.Unmarshal([]byte(authKey), &k); err != nil {
				return "", "", "", fmt.Errorf("mws: authorized_key не парсится как JSON скачанного ключа: %w", err)
			}
			keyID = firstNonEmpty(keyID, k.keyID())
			saID = firstNonEmpty(saID, k.saID())
			privPEM = firstNonEmpty(privPEM, k.pem())
			if privPEM == "" && k.pub() != "" {
				return "", "", "", fmt.Errorf("mws: в JSON только public_key, а нужен private_key — приватная часть отдаётся ОДИН раз при создании «Авторизованного ключа» (скачанный файл), либо это твой priv.pem, если добавлял существующий ключ")
			}
		case strings.Contains(authKey, "PRIVATE KEY"):
			// tolerate a bare private-key PEM pasted into authorized_key
			privPEM = firstNonEmpty(privPEM, authKey)
		case isPublicKey(authKey):
			return "", "", "", fmt.Errorf("mws: это ПУБЛИЧНЫЙ ключ (MFkw…) из списка в консоли — по нему нельзя подписывать запросы. Нужна приватная часть: JSON, скачанный при создании «Авторизованного ключа», или твой priv.pem (в поле private_key)")
		case strings.HasPrefix(compact, "v1."):
			return "", "", "", fmt.Errorf("mws: это API-ключ (v1.…) — он только для Artifact Registry/GPT, VPC его не принимает. Создай «Авторизованный ключ» и вставь его JSON")
		case strings.HasPrefix(compact, "eyJ"):
			return "", "", "", fmt.Errorf("mws: похоже на готовый IAM-токен — он идёт в поле token (но протухает за ~час; надёжнее авторизованный ключ)")
		default:
			return "", "", "", fmt.Errorf("mws: authorized_key должен быть JSON скачанного «Авторизованного ключа» или PEM приватного ключа. Публичный ключ (MFkw…), HMAC- и API-ключи (v1.…) не подходят")
		}
	}
	if privPEM != "" && isPublicKey(privPEM) {
		return "", "", "", fmt.Errorf("mws: private_key: это ПУБЛИЧНЫЙ ключ — нужен приватный (-----BEGIN PRIVATE KEY----- / priv.pem)")
	}
	var missing []string
	if privPEM == "" {
		missing = append(missing, "private_key")
	}
	if keyID == "" {
		missing = append(missing, "key_id")
	}
	if saID == "" {
		missing = append(missing, "service_account_id")
	}
	if len(missing) > 0 {
		return "", "", "", fmt.Errorf("mws: не хватает полей ключа: %s", strings.Join(missing, ", "))
	}
	return keyID, saID, privPEM, nil
}

// isPublicKey reports whether s is a public key: a PEM PUBLIC KEY block or the
// bare base64 SPKI the console shows in the key list (MFkw… for P-256).
func isPublicKey(s string) bool {
	if strings.Contains(s, "PUBLIC KEY") {
		return true
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		return false
	}
	_, err = x509.ParsePKIXPublicKey(der)
	return err == nil
}

// checkToken rejects things that are definitely not an IAM token (VPC wants a
// signed JWS) before we burn a request on a guaranteed 401.
func checkToken(tok string) error {
	switch {
	case strings.HasPrefix(tok, "v1."):
		return fmt.Errorf("mws: token — это API-ключ (v1.…), он только для Artifact Registry/GPT, VPC его не принимает. Нужен «Авторизованный ключ» (поле authorized_key) или IAM-токен из `mws iam create-token`")
	case strings.HasPrefix(tok, "{"):
		return fmt.Errorf("mws: в token вставлен JSON ключа — он идёт в поле authorized_key")
	}
	return nil
}

// CheckAuthMaterial validates pasted MWS credentials at /addaccount time so
// key-type mix-ups (публичный ключ, API-ключ v1.…, HMAC) surface immediately,
// not on the first roll. A token-only setup is allowed (оно просто протухает).
func CheckAuthMaterial(privateKey, keyID, serviceAccountID, authorizedKey, token string) error {
	if token != "" {
		if err := checkToken(sanitizeToken(token)); err != nil {
			return err
		}
	}
	privateKey, authorizedKey = strings.TrimSpace(privateKey), strings.TrimSpace(authorizedKey)
	if authorizedKey == "" && privateKey == "" {
		if token == "" {
			return fmt.Errorf("mws: нужен «Авторизованный ключ»: весь скачанный JSON в authorized_key, либо private_key + key_id + service_account_id. HMAC- и API-ключи (v1.…) не подходят")
		}
		return nil
	}
	_, _, pemStr, err := resolveKeyMaterial(strings.TrimSpace(keyID), strings.TrimSpace(serviceAccountID), privateKey, authorizedKey)
	if err != nil {
		return err
	}
	if _, err := parseECPrivateKey(pemStr); err != nil {
		return fmt.Errorf("mws: private_key: %w", err)
	}
	return nil
}

// issueIAMToken signs an ES256 JWT with the authorized key and exchanges it for
// an IAM token; returns the token and its expiry.
func (p *Provider) issueIAMToken(ctx context.Context) (string, time.Time, error) {
	keyID, saID, privPEM, err := resolveKeyMaterial(p.keyID, p.saID, p.privPEM, p.authKeyJSON)
	if err != nil {
		return "", time.Time{}, err
	}
	priv, err := parseECPrivateKey(privPEM)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("mws: private_key: %w", err)
	}

	aud := p.iamBase + issueTokenPath
	jwt, err := signES256JWT(priv, keyID, saID, aud)
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
