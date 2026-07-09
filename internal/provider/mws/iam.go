package mws

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"ip-roller-bot/internal/provider"
)

// issueTokenPath is the custom method that exchanges a self-signed JWT for an
// IAM token. MWS Cloud Platform IAM is a Google-/Yandex-style API: the token
// collection is created with POST /iam/v2/tokens (see mws.ru/docs/api/auth),
// and :issueServiceAccountToken is a custom method on that same collection —
// so it is a POST, and the JWT travels in the JSON body {"jwt":"<jwt>"} (как в
// Yandex Cloud IAM POST /iam/v1/tokens), НЕ в заголовке Authorization. Раньше
// код слал GET с JWT в Bearer и пустым телом — сервер не находил JWS в теле и
// отвечал 401 «JWS parsing attempt failed». Сервисный аккаунт дополнительно
// передаётся query-параметром serviceAccount=projects/<p>/serviceAccounts/<sa>
// (path маршрутизировался живьём, поэтому оставлен как есть).
const issueTokenPath = "/iam/v2/tokens/:issueServiceAccountToken"

// issueTokenRequest is the exchange body. The server parses .JWT as a compact
// JWS and swaps it for an IAM token — mirror of Yandex Cloud IAM's {"jwt":...}.
type issueTokenRequest struct {
	JWT string `json:"jwt"`
}

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

var (
	// iam/projects/<p>/serviceAccounts/<sa>[/authorizedKeys/<key>]
	iamPathRe = regexp.MustCompile(`projects/([A-Za-z0-9._-]+)/serviceAccounts/([A-Za-z0-9._-]+)(?:/authorizedKeys/([A-Za-z0-9._-]+))?`)
	// console.mws.ru/iam/<p>/service-accounts/<sa>[/access-keys[/<key>]]
	consolePathRe = regexp.MustCompile(`iam/([A-Za-z0-9._-]+)/service-accounts/([A-Za-z0-9._-]+)(?:/access-keys/([A-Za-z0-9._-]+))?`)
)

// ParseResourcePath pulls (project, service account, key id) out of a pasted
// IAM resource path like
//
//	iam/projects/project-x/serviceAccounts/sa/authorizedKeys/access-key
//
// or a console URL like
//
//	https://console.mws.ru/iam/project-x/service-accounts/sa/access-keys
//
// so the user can paste the whole thing instead of hunting for each id.
// keyID may come back empty (console list URL has no key segment).
func ParseResourcePath(s string) (project, sa, keyID string, ok bool) {
	s = strings.TrimSpace(s)
	if m := iamPathRe.FindStringSubmatch(s); m != nil {
		return m[1], m[2], m[3], true
	}
	if m := consolePathRe.FindStringSubmatch(s); m != nil {
		return m[1], m[2], m[3], true
	}
	return "", "", "", false
}

// expandResourcePaths lets any id field carry the full pasted resource path
// (see ParseResourcePath) and pulls the individual ids out of it. A field that
// held the path itself is replaced by the extracted segment.
func expandResourcePaths(keyID, saID, projectID string) (string, string, string) {
	for _, s := range [...]string{keyID, saID, projectID} {
		p, sa, k, ok := ParseResourcePath(s)
		if !ok {
			continue
		}
		if keyID == "" || keyID == s {
			keyID = k
		}
		if saID == "" || saID == s {
			saID = sa
		}
		if projectID == "" || projectID == s {
			projectID = p
		}
	}
	return keyID, saID, projectID
}

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
// not on the first roll. Any id field may carry the full resource path — it is
// expanded first. A token-only setup is allowed (оно просто протухает).
func CheckAuthMaterial(privateKey, keyID, serviceAccountID, projectID, authorizedKey, token string) error {
	keyID, serviceAccountID, projectID = expandResourcePaths(
		strings.TrimSpace(keyID), strings.TrimSpace(serviceAccountID), strings.TrimSpace(projectID))
	if projectID == "" {
		return fmt.Errorf("mws: не хватает project_id — сегмент URL консоли после /iam/ (напр. project-foxday128)")
	}
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
	_, _, pemStr, err := resolveKeyMaterial(keyID, serviceAccountID, privateKey, authorizedKey)
	if err != nil {
		return err
	}
	if _, err := parseECPrivateKey(pemStr); err != nil {
		return fmt.Errorf("mws: private_key: %w", err)
	}
	return nil
}

// ResolveAuthorizedKeyJSON validates a pasted authorized-key JSON and returns
// the pieces the add-wizard needs to autofill its fields.
func ResolveAuthorizedKeyJSON(s string) (keyID, saID, privPEM string, err error) {
	keyID, saID, privPEM, err = resolveKeyMaterial("", "", "", strings.TrimSpace(s))
	if err != nil {
		return "", "", "", err
	}
	if _, err := parseECPrivateKey(privPEM); err != nil {
		return "", "", "", fmt.Errorf("mws: private_key: %w", err)
	}
	return keyID, saID, privPEM, nil
}

// issueIAMToken signs an ES256 JWT with the authorized key (header kid = id
// ключа, payload sub = projects/<p>/serviceAccounts/<sa> — mws.ru/docs/…/iam/
// sa-get-access-token) and exchanges it for an IAM token:
//
//	POST {iam}/iam/v2/tokens/:issueServiceAccountToken?serviceAccount=<sub>
//	Content-Type: application/json
//	{"jwt":"<self-signed JWT>"}
//
// The self-signed JWT goes in the BODY (сервер парсит его как JWS), NOT in the
// Authorization header — this is a mint endpoint, у нас ещё нет IAM-токена.
func (p *Provider) issueIAMToken(ctx context.Context) (string, time.Time, error) {
	keyID, saID, privPEM, err := resolveKeyMaterial(p.keyID, p.saID, p.privPEM, p.authKeyJSON)
	if err != nil {
		return "", time.Time{}, err
	}
	priv, err := parseECPrivateKey(privPEM)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("mws: private_key: %w", err)
	}

	sub := saID
	if !strings.Contains(sub, "/") {
		if p.cfg.ProjectID == "" {
			return "", time.Time{}, fmt.Errorf("mws: нужен project_id — sub в JWT имеет вид projects/<project>/serviceAccounts/<sa>")
		}
		sub = fmt.Sprintf("projects/%s/serviceAccounts/%s", p.cfg.ProjectID, saID)
	}
	jwtExp := time.Now().Add(time.Hour)
	jwt, err := signES256JWT(priv, keyID, sub, jwtExp)
	if err != nil {
		return "", time.Time{}, err
	}

	// The serviceAccount query wants the full path with RAW slashes — the
	// server routes %2F differently (проверено живьём).
	reqURL := p.iamBase + issueTokenPath + "?serviceAccount=" + sub
	reqBody, err := json.Marshal(issueTokenRequest{JWT: jwt})
	if err != nil {
		return "", time.Time{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(reqBody))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	var resp issueTokenResponse
	if err := p.doDebug(req, &resp); err != nil {
		return "", time.Time{}, fmt.Errorf("mws: выпуск IAM-токена (%s): %w", issueTokenPath, mapIssueErr(err))
	}
	tok := resp.token()
	if tok == "" {
		return "", time.Time{}, fmt.Errorf("mws: пустой IAM-токен в ответе %s", issueTokenPath)
	}
	exp := time.Now().Add(50 * time.Minute)
	if t, ok := resp.expiry(); ok {
		exp = t
	}
	return tok, exp, nil
}

// mapIssueErr turns the IAM endpoint's 401 into an actionable hint. Two shapes:
//   - body «JWS parsing attempt failed» → сервер не смог разобрать JWT как JWS
//     (структура/кодировка запроса) — редко после перехода на тело POST {"jwt":…}.
//   - пустое тело (или grpc-message в заголовке) → JWS распарсился, но НЕ прошёл
//     ПРОВЕРКУ: не тот key_id (kid), публичный ключ в консоли не совпадает с
//     private_key, не тот sub, или не хватает claim'ов (iat/aud) / часы отстали.
func mapIssueErr(err error) error {
	var apiErr *provider.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized {
		if strings.Contains(strings.ToLower(apiErr.Body), "jws parsing") {
			return fmt.Errorf("IAM не смог разобрать JWT как JWS (401). Обычно самоподписанный JWT дошёл, но в неверной форме — запусти MWS_DEBUG=1 и сверь тело запроса {\"jwt\":…} и claims: %w", err)
		}
		return fmt.Errorf("IAM отклонил самоподписанный JWT на ПРОВЕРКЕ (401, JWS уже распарсился). Сверь: key_id = точный ID «Авторизованного ключа»; его публичный ключ в консоли соответствует твоему private_key (ES256/P-256); sub = projects/<project>/serviceAccounts/<sa>; часы не отстают (exp в будущем). Детали — в заголовках ответа (MWS_DEBUG=1: grpc-message/www-authenticate): %w", err)
	}
	return err
}

// issueTokenResponse tolerates the response shapes MWS may use: a flat token
// string under different names, or a nested token object with value+expiry.
type issueTokenResponse struct {
	Token       json.RawMessage `json:"token"`
	IAMToken    string          `json:"iamToken"`
	AccessToken string          `json:"accessToken"`
	Access2     string          `json:"access_token"`
	Value       string          `json:"value"`
	ExpiresAt   string          `json:"expiresAt"`
	ExpireTime  string          `json:"expireTime"`
	ExpiresIn   int64           `json:"expires_in"`

	nested struct {
		Value       string `json:"value"`
		Token       string `json:"token"`
		AccessToken string `json:"accessToken"`
		ExpiresAt   string `json:"expiresAt"`
		ExpireTime  string `json:"expireTime"`
	}
}

func (r *issueTokenResponse) token() string {
	var s string
	if len(r.Token) > 0 {
		if json.Unmarshal(r.Token, &s) != nil || s == "" {
			// token is an object — take its inner value
			_ = json.Unmarshal(r.Token, &r.nested)
			s = firstNonEmpty(r.nested.Value, r.nested.Token, r.nested.AccessToken)
		}
	}
	return firstNonEmpty(s, r.IAMToken, r.AccessToken, r.Access2, r.Value)
}

func (r *issueTokenResponse) expiry() (time.Time, bool) {
	for _, v := range []string{r.ExpiresAt, r.ExpireTime, r.nested.ExpiresAt, r.nested.ExpireTime} {
		if v == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t, true
		}
	}
	if r.ExpiresIn > 0 {
		return time.Now().Add(time.Duration(r.ExpiresIn) * time.Second), true
	}
	return time.Time{}, false
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

// signES256JWT builds the JWT MWS expects (mws.ru/docs/…/iam/
// sa-get-access-token): header {typ JWT, alg ES256, kid = id авторизованного
// ключа}, payload {sub: projects/<p>/serviceAccounts/<sa>, iat, exp}. We include
// iat — почти все JWS-валидаторы его требуют/ждут, и оно безопасно (нет значения,
// которое сервер мог бы «не признать»). iss/aud НЕ шлём: их доки не требуют, а
// лишний aud с неверным URL сервер бы отверг. The signed JWT is then POSTed in
// the {"jwt":…} body by issueIAMToken.
//
// The signature is JOSE ES256: raw R||S, each big-endian left-padded to 32
// bytes (P-256), base64url without padding — NOT a DER/ASN.1 sequence.
func signES256JWT(priv *ecdsa.PrivateKey, kid, sub string, exp time.Time) (string, error) {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	header := b64([]byte(fmt.Sprintf(`{"typ":"JWT","alg":"ES256","kid":%q}`, kid)))
	payload := b64([]byte(fmt.Sprintf(`{"sub":%q,"iat":%d,"exp":%d}`, sub, time.Now().Unix(), exp.Unix())))
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
