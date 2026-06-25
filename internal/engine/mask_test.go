package engine

import (
	"net/netip"
	"testing"
)

func TestParseMaskMatch(t *testing.T) {
	cases := []struct {
		mask string
		ip   string
		want bool
	}{
		{"185.12.64.0/18", "185.12.65.7", true},
		{"185.12.64.0/18", "185.12.200.1", false},
		{"95.142.*.*", "95.142.18.3", true},
		{"95.142.*.*", "95.143.18.3", false},
		{"45.10.x.x", "45.10.0.0", true},
		{"95.142.0-50.*", "95.142.50.255", true},
		{"95.142.0-50.*", "95.142.51.0", false},
		{"10.0.0.1", "10.0.0.1", true},
		{"10.0.0.1", "10.0.0.2", false},
	}
	for _, c := range cases {
		m, err := ParseMask(c.mask)
		if err != nil {
			t.Fatalf("ParseMask(%q): %v", c.mask, err)
		}
		addr := netip.MustParseAddr(c.ip)
		if got := m.Match(addr); got != c.want {
			t.Errorf("mask %q vs %s: got %v, want %v", c.mask, c.ip, got, c.want)
		}
	}
}

func TestParseMaskErrors(t *testing.T) {
	for _, bad := range []string{"", "1.2.3", "1.2.3.999", "1.2.3.50-10", "300.0.0.0/8"} {
		if _, err := ParseMask(bad); err == nil {
			t.Errorf("ParseMask(%q): expected error, got nil", bad)
		}
	}
}

func TestParseMasksAnyOf(t *testing.T) {
	m, err := ParseMasks([]string{"185.12.0.0/16", "95.142.*.*"})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match(netip.MustParseAddr("95.142.1.1")) {
		t.Error("expected match on second mask")
	}
	if !m.Match(netip.MustParseAddr("185.12.9.9")) {
		t.Error("expected match on first mask")
	}
	if m.Match(netip.MustParseAddr("8.8.8.8")) {
		t.Error("unexpected match")
	}
}
