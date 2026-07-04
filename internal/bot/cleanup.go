package bot

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-telegram/bot"

	"ip-roller-bot/internal/provider"
)

// Cleanup deletes floating IPs that leaked (created but never released — e.g. an
// interrupted roll) and aren't bound to any service. IPs the user deliberately
// reserved (present in the pool) are protected.

// scanUnused lists, per cleaner-capable account, the unbound IPs that are NOT in
// the reserved pool, i.e. safe to delete.
func (h *Handler) scanUnused(ctx context.Context) (map[*provider.Account][]provider.UnusedIP, int, error) {
	pool, err := h.store.ListPoolIPs(ctx)
	if err != nil {
		return nil, 0, err
	}
	protected := map[string]bool{} // accountKey|resourceID
	for _, p := range pool {
		protected[p.Provider+"|"+p.ResourceID] = true
	}

	res := map[*provider.Account][]provider.UnusedIP{}
	total := 0
	for _, acc := range h.reg.Accounts() {
		c, ok := acc.AsCleaner()
		if !ok {
			continue
		}
		ips, err := c.ListUnused(ctx)
		if err != nil {
			h.log.Warn("list unused failed", "acc", acc.Key(), "err", err)
			continue
		}
		var keep []provider.UnusedIP
		for _, ip := range ips {
			if protected[acc.Key()+"|"+ip.ID] {
				continue // reserved in the pool — don't touch
			}
			keep = append(keep, ip)
		}
		if len(keep) > 0 {
			res[acc] = keep
			total += len(keep)
		}
	}
	return res, total, nil
}

// cbCleanup scans for unused IPs and asks for confirmation before deleting.
func (h *Handler) cbCleanup(ctx context.Context, b *bot.Bot, chatID int64, msgID int) {
	found, total, err := h.scanUnused(ctx)
	if err != nil {
		h.editHTML(ctx, b, chatID, msgID, "⚠️ Не смог получить список IP: "+htmlEsc(err.Error()), accountsBackKeyboard())
		return
	}
	if total == 0 {
		h.editHTML(ctx, b, chatID, msgID, "✨ Неиспользуемых IP нет — всё чисто.", accountsBackKeyboard())
		return
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "🧹 Нашёл <b>%d</b> неиспользуемых IP (не привязаны к сервисам и не в пуле):\n", total)
	sb.WriteString("<blockquote expandable>")
	for acc, ips := range found {
		for _, ip := range ips {
			fmt.Fprintf(&sb, "%s — %s\n", htmlEsc(accountDisplay(acc)), ip.Addr.String())
		}
	}
	sb.WriteString("</blockquote>\n⚠️ Удаление необратимо. Продолжить?")
	h.editHTML(ctx, b, chatID, msgID, sb.String(), cleanupConfirmKeyboard(total))
}

// cbCleanupRun re-scans and deletes the unused IPs, then reports the result.
func (h *Handler) cbCleanupRun(ctx context.Context, b *bot.Bot, chatID int64, msgID int) {
	found, _, err := h.scanUnused(ctx)
	if err != nil {
		h.editHTML(ctx, b, chatID, msgID, "⚠️ Не смог получить список IP: "+htmlEsc(err.Error()), accountsBackKeyboard())
		return
	}
	deleted, failed := 0, 0
	for acc, ips := range found {
		for _, ip := range ips {
			if err := acc.Release(ctx, provider.AllocatedIP{Addr: ip.Addr, ID: ip.ID}); err != nil {
				h.log.Warn("cleanup release failed", "acc", acc.Key(), "ip", ip.Addr.String(), "err", err)
				failed++
				continue
			}
			deleted++
		}
	}
	msg := fmt.Sprintf("🧹 Удалено неиспользуемых IP: <b>%d</b>.", deleted)
	if failed > 0 {
		msg += fmt.Sprintf("\n⚠️ Не удалось удалить: %d (см. логи).", failed)
	}
	h.editHTML(ctx, b, chatID, msgID, msg, accountsBackKeyboard())
}
