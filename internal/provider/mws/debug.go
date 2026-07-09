package mws

import (
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

// doDebug replaces provider.DoJSON for the MWS adapter: identical behavior
// (*APIError on non-2xx, JSON-decode into out on 2xx) but, when MWS_DEBUG is on,
// it dumps the full request (method, URL, headers, body, decoded JWT) and the
// raw response first.
func (p *Provider) doDebug(req *http.Request, out any) error {
	if !debugHTTP {
		return provider.DoJSON(p.client, req, p.Name(), out)
	}

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

	resp, err := p.client.Do(req)
	if err != nil {
		dbg("<<< transport error: %v", err)
		return fmt.Errorf("%s: request failed: %w", p.Name(), err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	dbg("<<< status=%d\n%s", resp.StatusCode, string(body))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &provider.APIError{Provider: p.Name(), StatusCode: resp.StatusCode, Body: string(body)}
	}
	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("%s: decode response: %w", p.Name(), err)
		}
	}
	return nil
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
