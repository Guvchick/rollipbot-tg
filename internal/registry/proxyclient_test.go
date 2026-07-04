package registry

import (
	"testing"

	"ip-roller-bot/internal/storage"
)

func TestProxyHTTPClient(t *testing.T) {
	// HTTP proxy → transport with a Proxy func
	http, err := proxyHTTPClient(storage.Proxy{Scheme: "http", Host: "1.2.3.4", Port: 8080})
	if err != nil || http == nil {
		t.Fatalf("http proxy client: %v", err)
	}
	// SOCKS5 with auth → dialer-backed transport
	socks, err := proxyHTTPClient(storage.Proxy{Scheme: "socks5", Host: "1.2.3.4", Port: 1080, Username: "u", Password: "p"})
	if err != nil || socks == nil {
		t.Fatalf("socks5 proxy client: %v", err)
	}
	// unknown scheme rejected
	if _, err := proxyHTTPClient(storage.Proxy{Scheme: "ftp", Host: "h", Port: 1}); err == nil {
		t.Error("unknown scheme must be rejected")
	}
}
