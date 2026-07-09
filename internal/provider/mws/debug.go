package mws

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"ip-roller-bot/internal/provider"
)

// Opt-in HTTP tracing for diagnosing MWS auth (the IAM «JWS parsing attempt
// failed» 401 and the VPC calls). Enable with env MWS_DEBUG=1: every MWS request
// and response is dumped to stderr, and a {"jwt":…} body has its JWT header and
// payload decoded (those claims are exactly what the IAM server validates).
//
// ⚠️ The dump contains secrets — the JWT signature and the returned IAM token.
// The decoded JWT header/payload (claims) are safe to share; redact the rest.

var debugHTTP = envTrue("MWS_DEBUG")

// probeMintShapes (MWS_PROBE=1) turns on the one-shot request-shape probe in
// issueIAMToken: on each token issue it tries the plausible mint-request shapes
// and logs the HTTP status of each, so a single roll reveals which form MWS
// accepts — or that ALL 401 (→ the problem is the key/claims, not the shape).
var probeMintShapes = envTrue("MWS_PROBE")

func envTrue(k string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(k))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

var debugBanner sync.Once

func dbg(format string, args ...any) {
	if !debugHTTP {
		return
	}
	debugBanner.Do(func() {
		fmt.Fprintln(os.Stderr, "[mws-debug] ⚠️ вывод содержит секреты (подпись JWT и IAM-токен) — вычисти перед отправкой; JWT.header/JWT.payload безопасны")
	})
	fmt.Fprintf(os.Stderr, "[mws-debug] "+format+"\n", args...)
}

// doDebug is the MWS adapter's replacement for provider.DoJSON: same behavior
// (*APIError on non-2xx, JSON-decode into out on 2xx) plus two diagnostics that
// matter for the IAM 401. (1) On a non-2xx with an EMPTY body it folds useful
// response headers (grpc-message / www-authenticate / …) into the error — MWS is
// gRPC-transcoded, so an empty-body 401 usually carries its real reason in a
// header, not the body. (2) When MWS_DEBUG is on it also dumps the full request
// (method, URL, headers, body, decoded JWT) and the raw response + headers.
func (p *Provider) doDebug(req *http.Request, out any) error {
	if debugHTTP {
		dbg(">>> %s %s", req.Method, req.URL.String())
		for k, v := range req.Header {
			dbg("    %s: %s", k, strings.Join(v, ", "))
		}
		if req.GetBody != nil {
			if rc, err := req.GetBody(); err == nil {
				b, _ := io.ReadAll(io.LimitReader(rc, 1<<20))
				_ = rc.Close()
				if len(b) > 0 {
					dbg("    body: %s", string(b))
					if header, payload, ok := decodeJWTField(b); ok {
						dbg("    JWT.header:  %s", header)
						dbg("    JWT.payload: %s", payload)
					}
				}
			}
		}
	}

	resp, err := p.client.Do(req)
	if err != nil {
		dbg("<<< transport error: %v", err)
		return fmt.Errorf("%s: request failed: %w", p.Name(), err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if debugHTTP {
		dbg("<<< status=%d", resp.StatusCode)
		for k, v := range resp.Header {
			dbg("    %s: %s", k, strings.Join(v, ", "))
		}
		dbg("    body: %s", string(body))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := string(body)
		if strings.TrimSpace(detail) == "" {
			detail = headerDetail(resp.Header)
		}
		return &provider.APIError{Provider: p.Name(), StatusCode: resp.StatusCode, Body: detail}
	}
	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("%s: decode response: %w", p.Name(), err)
		}
	}
	return nil
}

// headerDetail extracts the response headers that gRPC-transcoded APIs use to
// carry an error when the body is empty, so an empty-body 401 still says why.
func headerDetail(h http.Header) string {
	var parts []string
	for _, k := range []string{"Grpc-Message", "Grpc-Status", "Www-Authenticate", "Message", "X-Request-Id"} {
		if v := h.Get(k); v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	if len(parts) == 0 {
		return "(пустое тело ответа, в заголовках нет деталей — запусти MWS_DEBUG=1 и сверь claims JWT/заголовки)"
	}
	return strings.Join(parts, "; ")
}

func plog(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[mws-probe] "+format+"\n", args...)
}

// mintVariant is one candidate shape of the JWT→IAM-token exchange request.
type mintVariant struct {
	name   string
	method string
	url    string
	body   []byte // nil for GET
	bearer bool   // also send Authorization: Bearer <jwt>
}

// mintVariants enumerates the plausible request shapes for the mint endpoint,
// covering the two ways the JWT can travel (body field vs Authorization header),
// the body field-name candidates (jwt/assertion/token), the query vs no-query
// path, and the Yandex-style /iam/v2/tokens collection.
func (p *Provider) mintVariants(jwt, sub string) []mintVariant {
	field := func(name string) []byte {
		b, _ := json.Marshal(map[string]string{name: jwt})
		return b
	}
	q := issueTokenPath + "?serviceAccount=" + sub
	return []mintVariant{
		{"POST :issue?query body{jwt}", http.MethodPost, p.iamBase + q, field("jwt"), false},
		{"POST :issue body{jwt} (no query)", http.MethodPost, p.iamBase + issueTokenPath, field("jwt"), false},
		{"POST /iam/v2/tokens body{jwt}", http.MethodPost, p.iamBase + "/iam/v2/tokens", field("jwt"), false},
		{"GET :issue?query Bearer (original)", http.MethodGet, p.iamBase + q, nil, true},
		{"POST :issue?query body{assertion}", http.MethodPost, p.iamBase + q, field("assertion"), false},
		{"POST :issue?query body{token}", http.MethodPost, p.iamBase + q, field("token"), false},
		{"POST :issue?query body{jwt}+Bearer", http.MethodPost, p.iamBase + q, field("jwt"), true},
	}
}

// probeMint fires each candidate shape once, logs its HTTP status (and short
// body), and returns the first response that carries a token. All-401 means the
// key/claims are wrong, not the request shape.
func (p *Provider) probeMint(ctx context.Context, jwt, sub string) (*issueTokenResponse, string, bool) {
	plog("перебираю формы запроса выпуска IAM-токена (по одному запросу на форму)…")
	for _, v := range p.mintVariants(jwt, sub) {
		var body io.Reader
		if v.body != nil {
			body = bytes.NewReader(v.body)
		}
		req, err := http.NewRequestWithContext(ctx, v.method, v.url, body)
		if err != nil {
			plog("%-38s → ошибка сборки запроса: %v", v.name, err)
			continue
		}
		req.Header.Set("Accept", "application/json")
		if v.body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if v.bearer {
			req.Header.Set("Authorization", "Bearer "+jwt)
		}
		resp, err := p.client.Do(req)
		if err != nil {
			plog("%-38s → transport error: %v", v.name, err)
			continue
		}
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		detail := strings.TrimSpace(string(rb))
		if detail == "" {
			detail = headerDetail(resp.Header)
		}
		plog("%-38s → HTTP %d  %s", v.name, resp.StatusCode, detail)
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			var r issueTokenResponse
			if json.Unmarshal(rb, &r) == nil && r.token() != "" {
				plog("✅ РАБОЧАЯ ФОРМА: %s — зафиксируй её как постоянную", v.name)
				return &r, v.name, true
			}
		}
	}
	plog("⛔ ни одна форма не принята — значит дело в КЛЮЧЕ/CLAIMS (key_id/kid, публичный ключ в консоли ≠ private_key, sub), а не в форме запроса")
	return nil, "", false
}

// decodeJWTField pulls the JWT out of a {"jwt":"..."} request body and returns
// its base64url-decoded header and payload segments (the signature is left out).
func decodeJWTField(body []byte) (header, payload string, ok bool) {
	var wrap struct {
		JWT string `json:"jwt"`
	}
	if json.Unmarshal(body, &wrap) != nil || wrap.JWT == "" {
		return "", "", false
	}
	parts := strings.Split(wrap.JWT, ".")
	if len(parts) < 2 {
		return "", "", false
	}
	dec := func(s string) string {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return "(не декодируется: " + s + ")"
		}
		return string(b)
	}
	return dec(parts[0]), dec(parts[1]), true
}
