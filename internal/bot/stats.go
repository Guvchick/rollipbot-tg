package bot

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-telegram/bot"

	"ip-roller-bot/internal/provider"
	"ip-roller-bot/internal/storage"
)

// showStats renders roll statistics aggregated across all accounts, plus the
// per-account daily limits (which used to live behind the removed "Лимиты"
// button). Rendered in place for the single-screen model.
func (h *Handler) showStats(ctx context.Context, b *bot.Bot, chatID int64, msgID int) {
	stats, err := h.store.RollStats(ctx)
	if err != nil {
		h.edit(ctx, b, chatID, msgID, "Ошибка чтения статистики: "+err.Error(), menuBackKeyboard())
		return
	}
	h.edit(ctx, b, chatID, msgID, h.statsText(ctx, stats), menuBackKeyboard())
}

// statsText builds the statistics body (also reused by the topic auto-update).
func (h *Handler) statsText(ctx context.Context, stats []storage.ProviderStat) string {
	byKey := make(map[string]storage.ProviderStat, len(stats))
	var total, matched, released, today int
	for _, s := range stats {
		byKey[s.Provider] = s
		total += s.Total
		matched += s.Matched
		released += s.Released
		today += s.Today
	}

	var sb strings.Builder
	sb.WriteString("📈 Статистика роллов (со всех аккаунтов)\n")
	fmt.Fprintf(&sb, "Всего: %d · попаданий: %d · освобождено: %d · сегодня: %d\n\n", total, matched, released, today)

	accs := h.reg.Accounts()
	if len(accs) == 0 {
		sb.WriteString("Нет включённых аккаунтов.")
		return sb.String()
	}
	sb.WriteString("По аккаунтам:\n")
	for _, a := range accs {
		s := byKey[a.Key()]
		caps := a.Caps()
		limit := "квота провайдера"
		if caps.DailyCap > 0 {
			limit = fmt.Sprintf("сегодня %d/%d (осталось %d)",
				h.engine.DailyUsed(a.Key()), caps.DailyCap, h.engine.DailyRemaining(a.Key(), caps.DailyCap))
		}
		cd := ""
		if until, ok := h.engine.Cooldown(a.Key()); ok {
			cd = " · ⛔ до " + until.Local().Format("02.01 15:04")
		}
		fmt.Fprintf(&sb, "• %s — роллов %d, поймано %d, сегодня %d\n   лимит: %s%s\n",
			accountDisplay(a), s.Total, s.Matched, s.Today, limit, cd)
	}
	return sb.String()
}

// postLimits maintains an auto-edited limits/quota snapshot in the account's
// forum topic (replaces the removed "Лимиты" button).
func (h *Handler) postLimits(ctx context.Context, b *bot.Bot, acc *provider.Account) {
	if !h.notifier.Enabled() {
		return
	}
	caps := acc.Caps()
	limit := "квота провайдера (без дневного лимита)"
	if caps.DailyCap > 0 {
		limit = fmt.Sprintf("сегодня %d/%d (осталось %d)",
			h.engine.DailyUsed(acc.Key()), caps.DailyCap, h.engine.DailyRemaining(acc.Key(), caps.DailyCap))
	}
	cd := ""
	if until, ok := h.engine.Cooldown(acc.Key()); ok {
		cd = "\n⛔ Квота исчерпана до " + until.Local().Format("02.01.2006 15:04 MST")
	}
	text := fmt.Sprintf("📊 <b>Лимиты · %s</b>\nrps=%.0f · задержка ролла=%s\n%s%s\nОбновлено: %s",
		accountDisplay(acc), caps.RateLimitRPS, caps.RollDelay, limit, cd, time.Now().Format("02.01 15:04:05"))
	h.notifier.UpdateLimits(ctx, b, accountDisplay(acc), text)
}
