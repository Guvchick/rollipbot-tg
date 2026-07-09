package mws

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// «Эмуляция браузера» без headless-Chrome. Instead of driving a real browser,
// we reuse what the browser already produced: (1) a token pasted straight from
// DevTools (extractBearer), or (2) the console's own token request captured as
// "Copy as cURL", which the bot replays to auto-refresh (parseCurl + browserToken).

var authHeaderRe = regexp.MustCompile(`(?i)authorization["']?\s*:\s*(?:bearer\s+)?([A-Za-z0-9._~+/=-]+)`)

// extractBearer pulls a bare token out of material copied from a browser:
//   - a full "Authorization: Bearer <tok>" header line (or inside a cURL),
//   - a leading "Bearer <tok>" value,
//   - or a bare token (returned unchanged).
func extractBearer(s string) string {
	if m := authHeaderRe.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	t := strings.TrimSpace(s)
	if len(t) >= 7 && strings.EqualFold(t[:7], "bearer ") {
		return strings.TrimSpace(t[7:])
	}
	return s
}

// browserAuth is a request captured from the console (DevTools "Copy as cURL")
// that mints/refreshes the IAM token.
type browserAuth struct {
	method string
	url    string
	header http.Header
	body   []byte
}

// browserToken replays the captured console token-request and returns the token
// it yields plus its expiry — the auto-refreshing «browser» path.
func (p *Provider) browserToken(ctx context.Context) (string, time.Time, error) {
	ba, err := parseCurl(p.refreshCurl)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("mws: refresh_curl: %w", err)
	}
	var body io.Reader
	if len(ba.body) > 0 {
		body = bytes.NewReader(ba.body)
	}
	req, err := http.NewRequestWithContext(ctx, ba.method, ba.url, body)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("mws: refresh_curl: %w", err)
	}
	req.Header = ba.header
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	var resp issueTokenResponse
	if err := p.doDebug(req, &resp); err != nil {
		return "", time.Time{}, fmt.Errorf("mws: браузерный запрос токена не удался (обнови refresh_curl из DevTools — сессия могла протухнуть): %w", err)
	}
	tok := resp.token()
	if tok == "" {
		return "", time.Time{}, fmt.Errorf("mws: в ответе браузерного запроса нет токена (проверь, что это именно запрос выпуска/обновления токена)")
	}
	exp := time.Now().Add(50 * time.Minute)
	if t, ok := resp.expiry(); ok {
		exp = t
	}
	return tok, exp, nil
}

// parseCurl turns a DevTools "Copy as cURL" command into a replayable request.
// It understands the flags browsers emit: -X/--request, -H/--header, -b/--cookie,
// -d/--data/--data-raw/--data-binary/--data-ascii/--data-urlencode, --url, and
// ignores no-arg flags (--compressed, -s, -i, -k, …).
func parseCurl(s string) (*browserAuth, error) {
	toks := shellSplit(s)
	if len(toks) == 0 {
		return nil, fmt.Errorf("пустая команда")
	}
	if strings.EqualFold(toks[0], "curl") {
		toks = toks[1:]
	}
	ba := &browserAuth{header: http.Header{}}
	var dataParts []string
	needsArg := map[string]bool{
		"-e": true, "--referer": true, "-A": true, "--user-agent": true, "-u": true, "--user": true,
	}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		next := func() string {
			if i+1 < len(toks) {
				i++
				return toks[i]
			}
			return ""
		}
		switch {
		case t == "-X" || t == "--request":
			ba.method = strings.ToUpper(next())
		case t == "-H" || t == "--header":
			k, v, ok := strings.Cut(next(), ":")
			if ok {
				ba.header.Add(strings.TrimSpace(k), strings.TrimSpace(v))
			}
		case t == "-b" || t == "--cookie":
			ba.header.Set("Cookie", next())
		case t == "-A" || t == "--user-agent":
			ba.header.Set("User-Agent", next())
		case t == "-e" || t == "--referer":
			ba.header.Set("Referer", next())
		case t == "-d" || t == "--data" || t == "--data-raw" || t == "--data-binary" || t == "--data-ascii" || t == "--data-urlencode":
			dataParts = append(dataParts, next())
		case t == "--url":
			ba.url = next()
		case needsArg[t]:
			_ = next() // consume and ignore
		case strings.HasPrefix(t, "-"):
			// unknown no-arg flag (--compressed, -s, -i, -k, -L, …) → skip
		default:
			if ba.url == "" {
				ba.url = t
			}
		}
	}
	if ba.url == "" {
		return nil, fmt.Errorf("в команде нет URL")
	}
	if len(dataParts) > 0 {
		ba.body = []byte(strings.Join(dataParts, "&"))
		if ba.method == "" {
			ba.method = http.MethodPost
		}
	}
	if ba.method == "" {
		ba.method = http.MethodGet
	}
	return ba, nil
}

// shellSplit tokenizes a shell-ish command line: single quotes are literal,
// double quotes honor \" and \\, $'…' is treated like a single-quoted string, a
// backslash escapes the next char (a trailing \\ before a newline continues the
// line), and unquoted whitespace separates tokens.
func shellSplit(s string) []string {
	var out []string
	var cur strings.Builder
	inTok := false
	flush := func() {
		if inTok {
			out = append(out, cur.String())
			cur.Reset()
			inTok = false
		}
	}
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			flush()
		case c == '\\':
			if i+1 < len(rs) {
				n := rs[i+1]
				if n == '\n' || n == '\r' {
					i++ // line continuation
					continue
				}
				cur.WriteRune(n)
				inTok = true
				i++
			}
		case c == '\'':
			inTok = true
			i++
			for i < len(rs) && rs[i] != '\'' {
				cur.WriteRune(rs[i])
				i++
			}
		case c == '"':
			inTok = true
			i++
			for i < len(rs) && rs[i] != '"' {
				if rs[i] == '\\' && i+1 < len(rs) && (rs[i+1] == '"' || rs[i+1] == '\\') {
					i++
				}
				cur.WriteRune(rs[i])
				i++
			}
		case c == '$' && i+1 < len(rs) && rs[i+1] == '\'':
			// $'…' ANSI-C quoting — treat the inside as literal (good enough).
			inTok = true
			i += 2
			for i < len(rs) && rs[i] != '\'' {
				if rs[i] == '\\' && i+1 < len(rs) {
					i++
				}
				cur.WriteRune(rs[i])
				i++
			}
		default:
			cur.WriteRune(c)
			inTok = true
		}
	}
	flush()
	return out
}
