package registry

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	xproxy "golang.org/x/net/proxy"

	"ip-roller-bot/internal/storage"
)

// proxyHTTPClient builds an *http.Client that routes requests through p. HTTP(S)
// proxies use net/http's transport; SOCKS5 uses a golang.org/x/net dialer.
func proxyHTTPClient(p storage.Proxy) (*http.Client, error) {
	addr := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	switch p.Scheme {
	case "http", "https":
		u := &url.URL{Scheme: p.Scheme, Host: addr}
		if p.Username != "" {
			u.User = url.UserPassword(p.Username, p.Password)
		}
		return &http.Client{
			Timeout:   40 * time.Second,
			Transport: &http.Transport{Proxy: http.ProxyURL(u)},
		}, nil
	case "socks5":
		var auth *xproxy.Auth
		if p.Username != "" {
			auth = &xproxy.Auth{User: p.Username, Password: p.Password}
		}
		d, err := xproxy.SOCKS5("tcp", addr, auth, xproxy.Direct)
		if err != nil {
			return nil, err
		}
		cd, ok := d.(xproxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("socks5 dialer без поддержки контекста")
		}
		return &http.Client{
			Timeout:   40 * time.Second,
			Transport: &http.Transport{DialContext: cd.DialContext},
		}, nil
	}
	return nil, fmt.Errorf("неизвестная схема прокси: %q", p.Scheme)
}
