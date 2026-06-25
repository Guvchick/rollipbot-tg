// Package engine holds the provider-agnostic rolling loop, rate limiting,
// daily caps and backoff.
package engine

import (
	"context"
	"errors"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"ip-roller-bot/internal/provider"
	"ip-roller-bot/internal/storage"
)

var (
	ErrBudgetExhausted = errors.New("исчерпан лимит попыток, совпадений нет")
	ErrDailyCap        = errors.New("достигнут дневной лимит роллов")
)

const maxBackoffAttempts = 5

// Result is a successful roll: a matched address and how many attempts it took.
type Result struct {
	IP       provider.AllocatedIP
	Attempts int
}

// Engine drives the allocate→match→release loop for any Provider.
type Engine struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	daily    *dailyCounter
	store    storage.Storage
	log      *slog.Logger
}

func New(store storage.Storage, log *slog.Logger) *Engine {
	return &Engine{
		limiters: make(map[string]*rate.Limiter),
		daily:    newDailyCounter(store, log),
		store:    store,
		log:      log,
	}
}

func (e *Engine) limiter(name string, rps float64) *rate.Limiter {
	e.mu.Lock()
	defer e.mu.Unlock()
	if l, ok := e.limiters[name]; ok {
		return l
	}
	if rps <= 0 {
		rps = 5
	}
	l := rate.NewLimiter(rate.Limit(rps), 1)
	e.limiters[name] = l
	return l
}

// DailyRemaining returns rolls left today for provider (-1 = unlimited).
func (e *Engine) DailyRemaining(name string, cap int) int { return e.daily.Remaining(name, cap) }

// DailyUsed returns today's consumed rolls for provider.
func (e *Engine) DailyUsed(name string) int { return e.daily.Used(name) }

// Roll rolls provider p until an address matches mask, or until budget /
// daily cap is exhausted. onAttempt (may be nil) reports live progress.
func (e *Engine) Roll(
	ctx context.Context,
	p provider.Provider,
	mask Matcher,
	budget int,
	onAttempt func(n int, ip string, matched bool),
) (Result, error) {

	caps := p.Caps()
	if caps.MaxRollsPerRun > 0 && budget > caps.MaxRollsPerRun {
		budget = caps.MaxRollsPerRun
	}
	lim := e.limiter(p.Name(), caps.RateLimitRPS)

	for i := 1; i <= budget; i++ {
		if !e.daily.Allow(p.Name(), caps.DailyCap) {
			return Result{}, ErrDailyCap
		}
		if err := lim.Wait(ctx); err != nil {
			return Result{}, err
		}

		ip, err := p.Allocate(ctx)
		if err != nil {
			// 429 / transient → exponential backoff and keep going.
			if e.backoff(ctx, i, err) {
				continue
			}
			return Result{}, err
		}
		e.daily.Inc(p.Name())

		matched := mask.Match(ip.Addr)
		if onAttempt != nil {
			onAttempt(i, ip.Addr.String(), matched)
		}
		_ = e.store.LogRoll(ctx, storage.RollLogEntry{
			Provider: p.Name(),
			IP:       ip.Addr.String(),
			Matched:  matched,
			Released: !matched,
		})

		if matched {
			return Result{IP: ip, Attempts: i}, nil // keep it
		}

		// Did not match → release it (otherwise it keeps billing).
		if err := p.Release(ctx, ip); err != nil {
			e.log.Warn("release failed", "provider", p.Name(), "ip", ip.Addr.String(), "err", err)
		}

		// Jitter so create/delete bursts don't look like abuse to anti-fraud.
		sleep(ctx, time.Duration(200+rand.Intn(400))*time.Millisecond)
	}
	return Result{}, ErrBudgetExhausted
}

// backoff waits (with jitter) on retryable provider errors and reports whether
// the loop should continue.
func (e *Engine) backoff(ctx context.Context, attempt int, err error) bool {
	var apiErr *provider.APIError
	if !errors.As(err, &apiErr) || !apiErr.Retryable() {
		return false
	}
	if attempt > maxBackoffAttempts {
		return false
	}
	wait := time.Duration(1<<uint(attempt)) * 200 * time.Millisecond
	if wait > 10*time.Second {
		wait = 10 * time.Second
	}
	wait += time.Duration(rand.Intn(300)) * time.Millisecond
	e.log.Warn("backoff on retryable error", "provider", apiErr.Provider, "attempt", attempt, "wait", wait, "err", err)
	return sleep(ctx, wait)
}

// sleep waits for d unless ctx is cancelled first; returns true if it slept fully.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
