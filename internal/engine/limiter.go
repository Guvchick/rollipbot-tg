package engine

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"ip-roller-bot/internal/storage"
)

// dailyCounter enforces per-provider daily caps. Counts are cached in memory and
// written through to storage so they survive restarts within the same day.
type dailyCounter struct {
	mu     sync.Mutex
	store  storage.Storage
	log    *slog.Logger
	day    string
	counts map[string]int
}

func newDailyCounter(store storage.Storage, log *slog.Logger) *dailyCounter {
	return &dailyCounter{
		store:  store,
		log:    log,
		day:    today(),
		counts: make(map[string]int),
	}
}

func today() string { return time.Now().Format("2006-01-02") }

// ensureDay resets the in-memory cache when the calendar day rolls over.
func (d *dailyCounter) ensureDay() {
	t := today()
	if d.day != t {
		d.day = t
		d.counts = make(map[string]int)
	}
}

// get returns the cached count for provider, lazily loading from storage.
func (d *dailyCounter) get(provider string) int {
	d.ensureDay()
	if v, ok := d.counts[provider]; ok {
		return v
	}
	n, err := d.store.DailyCount(context.Background(), provider, d.day)
	if err != nil {
		d.log.Warn("daily count load failed", "provider", provider, "err", err)
		n = 0
	}
	d.counts[provider] = n
	return n
}

// Allow reports whether another roll is permitted under the daily cap.
// cap <= 0 means no daily limit.
func (d *dailyCounter) Allow(provider string, cap int) bool {
	if cap <= 0 {
		return true
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.get(provider) < cap
}

// Inc records one consumed roll.
func (d *dailyCounter) Inc(provider string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ensureDay()
	d.counts[provider] = d.get(provider) + 1
	if err := d.store.IncDaily(context.Background(), provider, d.day); err != nil {
		d.log.Warn("daily inc failed", "provider", provider, "err", err)
	}
}

// Used returns today's consumed count for provider.
func (d *dailyCounter) Used(provider string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.get(provider)
}

// Remaining returns rolls left today; -1 means unlimited (cap <= 0).
func (d *dailyCounter) Remaining(provider string, cap int) int {
	if cap <= 0 {
		return -1
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	r := cap - d.get(provider)
	if r < 0 {
		r = 0
	}
	return r
}
