package engine

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"

	"ip-roller-bot/internal/provider"
	"ip-roller-bot/internal/storage"
)

// fakeProv is a scripted Provider for exercising the roll loop.
type fakeProv struct {
	caps  provider.RollCaps
	addrs []string

	mu       sync.Mutex
	i        int
	released []string
	failN    int // first failN Allocate calls return a retryable 429
}

func (f *fakeProv) Name() string                                               { return "fake" }
func (f *fakeProv) Caps() provider.RollCaps                                    { return f.caps }
func (f *fakeProv) Attach(context.Context, provider.AllocatedIP, string) error { return nil }

func (f *fakeProv) Allocate(context.Context) (provider.AllocatedIP, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failN > 0 {
		f.failN--
		return provider.AllocatedIP{}, &provider.APIError{Provider: "fake", StatusCode: 429}
	}
	if f.i >= len(f.addrs) {
		return provider.AllocatedIP{}, errors.New("exhausted")
	}
	a := f.addrs[f.i]
	f.i++
	return provider.AllocatedIP{Addr: netip.MustParseAddr(a), ID: a}, nil
}

func (f *fakeProv) Release(_ context.Context, ip provider.AllocatedIP) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released = append(f.released, ip.Addr.String())
	return nil
}

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	st, err := storage.NewSQLite(context.Background(), filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestRollMatchReleasesOthers(t *testing.T) {
	e := newTestEngine(t)
	p := &fakeProv{
		caps:  provider.RollCaps{RateLimitRPS: 1000},
		addrs: []string{"10.0.0.1", "10.0.0.2", "10.0.0.5", "10.0.0.9"},
	}
	m, _ := ParseMask("10.0.0.5")
	res, err := e.Roll(context.Background(), p, m, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Attempts != 3 {
		t.Errorf("attempts = %d, want 3", res.Attempts)
	}
	if res.IP.Addr.String() != "10.0.0.5" {
		t.Errorf("matched ip = %s, want 10.0.0.5", res.IP.Addr)
	}
	if len(p.released) != 2 { // the two non-matches before it
		t.Errorf("released = %v, want 2 addresses", p.released)
	}
}

func TestRollBudgetExhausted(t *testing.T) {
	e := newTestEngine(t)
	p := &fakeProv{caps: provider.RollCaps{RateLimitRPS: 1000}, addrs: []string{"10.0.0.1", "10.0.0.2"}}
	m, _ := ParseMask("99.0.0.0/8")
	_, err := e.Roll(context.Background(), p, m, 2, nil)
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("err = %v, want ErrBudgetExhausted", err)
	}
	if len(p.released) != 2 {
		t.Errorf("released = %d, want all 2 freed", len(p.released))
	}
}

func TestRollDailyCap(t *testing.T) {
	e := newTestEngine(t)
	p := &fakeProv{
		caps:  provider.RollCaps{RateLimitRPS: 1000, DailyCap: 2},
		addrs: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"},
	}
	m, _ := ParseMask("99.99.99.99") // never matches
	_, err := e.Roll(context.Background(), p, m, 10, nil)
	if !errors.Is(err, ErrDailyCap) {
		t.Fatalf("err = %v, want ErrDailyCap", err)
	}
	if p.i != 2 {
		t.Errorf("allocated %d, want exactly DailyCap=2", p.i)
	}
}

func TestRollBackoffRetries(t *testing.T) {
	e := newTestEngine(t)
	p := &fakeProv{caps: provider.RollCaps{RateLimitRPS: 1000}, addrs: []string{"10.0.0.5"}, failN: 2}
	m, _ := ParseMask("10.0.0.5")
	res, err := e.Roll(context.Background(), p, m, 10, nil)
	if err != nil {
		t.Fatalf("retryable 429s should not abort the run: %v", err)
	}
	if res.IP.Addr.String() != "10.0.0.5" {
		t.Errorf("matched ip = %s, want 10.0.0.5", res.IP.Addr)
	}
}

func TestRollMaxRollsPerRunCapsBudget(t *testing.T) {
	e := newTestEngine(t)
	// budget 100 but provider caps runs at 2 → only 2 allocations attempted.
	p := &fakeProv{
		caps:  provider.RollCaps{RateLimitRPS: 1000, MaxRollsPerRun: 2},
		addrs: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
	}
	m, _ := ParseMask("8.8.8.8")
	_, err := e.Roll(context.Background(), p, m, 100, nil)
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("err = %v, want ErrBudgetExhausted", err)
	}
	if p.i != 2 {
		t.Errorf("allocated %d, want capped at MaxRollsPerRun=2", p.i)
	}
}
