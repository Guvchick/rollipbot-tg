package bot

import "testing"

func TestParseProxyLine(t *testing.T) {
	// host:port with the wizard-selected scheme
	p, err := parseProxyLine("socks5", "1.2.3.4:1080")
	if err != nil || p.Scheme != "socks5" || p.Host != "1.2.3.4" || p.Port != 1080 || p.Username != "" {
		t.Fatalf("host:port parse = %+v, %v", p, err)
	}
	// host:port:login:pass
	p, err = parseProxyLine("http", "1.2.3.4:8080:bob:secret")
	if err != nil || p.Scheme != "http" || p.Port != 8080 || p.Username != "bob" || p.Password != "secret" {
		t.Fatalf("host:port:login:pass parse = %+v, %v", p, err)
	}
	// full URL overrides the scheme and carries creds
	p, err = parseProxyLine("http", "socks5://alice:pw@10.0.0.1:9050")
	if err != nil || p.Scheme != "socks5" || p.Host != "10.0.0.1" || p.Port != 9050 || p.Username != "alice" || p.Password != "pw" {
		t.Fatalf("url parse = %+v, %v", p, err)
	}
	// bad forms
	for _, bad := range []string{"", "justhost", "host:notaport", "a:b:c"} {
		if _, err := parseProxyLine("socks5", bad); err == nil {
			t.Errorf("parseProxyLine(%q) should fail", bad)
		}
	}
}
