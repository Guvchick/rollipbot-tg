package engine

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Matcher decides whether an allocated address satisfies the user's mask.
type Matcher interface{ Match(netip.Addr) bool }

// --- CIDR matcher: 185.12.64.0/18 ---

type cidrMatcher struct{ p netip.Prefix }

func (m cidrMatcher) Match(a netip.Addr) bool { return m.p.Contains(a) }

// --- Octet pattern matcher: 95.142.*.*, 45.10.x.x, 95.142.0-50.* ---

type octetMatcher struct{ octets [4]octetRule }

type octetRule struct {
	any    bool
	lo, hi uint8
}

func (m octetMatcher) Match(a netip.Addr) bool {
	if !a.Is4() {
		return false
	}
	b := a.As4()
	for i := 0; i < 4; i++ {
		r := m.octets[i]
		if r.any {
			continue
		}
		if b[i] < r.lo || b[i] > r.hi {
			return false
		}
	}
	return true
}

// --- anyMatcher: OR over several masks ---

type anyMatcher []Matcher

func (a anyMatcher) Match(addr netip.Addr) bool {
	for _, m := range a {
		if m.Match(addr) {
			return true
		}
	}
	return false
}

// ParseMask parses a single CIDR or octet pattern.
func ParseMask(s string) (Matcher, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("пустая маска")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		return cidrMatcher{p}, nil
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("маска должна иметь 4 октета или быть CIDR: %q", s)
	}
	var m octetMatcher
	for i, p := range parts {
		r, err := parseOctet(p)
		if err != nil {
			return nil, err
		}
		m.octets[i] = r
	}
	return m, nil
}

// ParseMasks parses several masks into an OR-matcher.
func ParseMasks(masks []string) (Matcher, error) {
	if len(masks) == 0 {
		return nil, fmt.Errorf("не задано ни одной маски")
	}
	var ms anyMatcher
	for _, s := range masks {
		m, err := ParseMask(s)
		if err != nil {
			return nil, err
		}
		ms = append(ms, m)
	}
	if len(ms) == 1 {
		return ms[0], nil
	}
	return ms, nil
}

func parseOctet(p string) (octetRule, error) {
	if p == "*" || p == "x" || p == "X" {
		return octetRule{any: true}, nil
	}
	if lo, hi, ok := strings.Cut(p, "-"); ok { // range a-b
		l, err1 := strconv.Atoi(lo)
		h, err2 := strconv.Atoi(hi)
		if err1 != nil || err2 != nil || l < 0 || h > 255 || l > h {
			return octetRule{}, fmt.Errorf("плохой диапазон октета: %q", p)
		}
		return octetRule{lo: uint8(l), hi: uint8(h)}, nil
	}
	v, err := strconv.Atoi(p)
	if err != nil || v < 0 || v > 255 {
		return octetRule{}, fmt.Errorf("плохой октет: %q", p)
	}
	return octetRule{lo: uint8(v), hi: uint8(v)}, nil
}
