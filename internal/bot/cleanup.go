package bot

import (
	"context"

	"github.com/go-telegram/bot"

	"ip-roller-bot/internal/provider"
)

// Cleanup deletes floating IPs that leaked (created but never released — e.g. an
// interrupted roll) and aren't bound to any service. It runs automatically at
// the start of each roll for the selected account. IPs the user deliberately
// reserved (present in the pool) are protected.

// autoCleanupAccount deletes the account's unbound, non-pool floating IPs and
// returns how many were removed. Best-effort: errors are logged, not fatal.
func (h *Handler) autoCleanupAccount(ctx context.Context, b *bot.Bot, acc *provider.Account) int {
	c, ok := acc.AsCleaner()
	if !ok {
		return 0
	}
	ips, err := c.ListUnused(ctx)
	if err != nil {
		h.log.Warn("auto-cleanup list failed", "acc", acc.Key(), "err", err)
		return 0
	}
	if len(ips) == 0 {
		return 0
	}
	protected := h.protectedResourceIDs(ctx, acc.Key())
	deleted := 0
	for _, ip := range ips {
		if protected[ip.ID] {
			continue // reserved in the pool — keep it
		}
		if err := acc.Release(ctx, provider.AllocatedIP{Addr: ip.Addr, ID: ip.ID}); err != nil {
			h.log.Warn("auto-cleanup release failed", "acc", acc.Key(), "ip", ip.Addr.String(), "err", err)
			continue
		}
		deleted++
	}
	if deleted > 0 {
		h.log.Info("auto-cleanup удалил повисшие IP", "acc", acc.Key(), "count", deleted)
	}
	return deleted
}

// protectedResourceIDs is the set of pool resource ids for one account key.
func (h *Handler) protectedResourceIDs(ctx context.Context, accKey string) map[string]bool {
	out := map[string]bool{}
	pool, err := h.store.ListPoolIPs(ctx)
	if err != nil {
		h.log.Warn("auto-cleanup pool read failed", "err", err)
		return out
	}
	for _, p := range pool {
		if p.Provider == accKey {
			out[p.ResourceID] = true
		}
	}
	return out
}
