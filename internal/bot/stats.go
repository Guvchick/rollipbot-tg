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

// accountStat returns the roll-history aggregate for one account key.
func (h *Handler) accountStat(ctx context.Context, key string) storage.ProviderStat {
	stats, err := h.store.RollStats(ctx)
	if err != nil {
		return storage.ProviderStat{Provider: key}
	}
	for _, s := range stats {
		if s.Provider == key {
			return s
		}
	}
	return storage.ProviderStat{Provider: key}
}

// postLimits maintains ONE auto-edited per-account stats+limits table in the
// account's forum topic (replaces the removed "Лимиты" button). Called at roll
// start and after each roll, so the topic always shows the current picture.
func (h *Handler) postLimits(ctx context.Context, b *bot.Bot, acc *provider.Account) {
	if !h.notifier.Enabled() {
		return
	}
	caps := acc.Caps()
	limit := "по квоте провайдера (без дневного лимита)"
	if caps.DailyCap > 0 {
		limit = fmt.Sprintf("сегодня %d/%d (осталось %d)",
			h.engine.DailyUsed(acc.Key()), caps.DailyCap, h.engine.DailyRemaining(acc.Key(), caps.DailyCap))
	}
	cd := ""
	if until, ok := h.engine.Cooldown(acc.Key()); ok {
		cd = "\n⛔ Квота исчерпана до " + until.Local().Format("02.01.2006 15:04 MST")
	}
	s := h.accountStat(ctx, acc.Key())
	text := fmt.Sprintf(
		"📊 <b>Статистика · %s</b>\n"+
			"<blockquote>"+
			"Всего роллов: %d\n"+
			"Поймано IP: %d\n"+
			"Освобождено: %d\n"+
			"Сегодня роллов: %d\n"+
			"Дневной лимит: %s\n"+
			"rps=%.0f · задержка=%s"+
			"</blockquote>%s\nОбновлено: %s",
		accountDisplay(acc), s.Total, s.Matched, s.Released, s.Today, limit,
		caps.RateLimitRPS, caps.RollDelay, cd, time.Now().Format("02.01 15:04:05"))
	h.notifier.UpdateLimits(ctx, b, accountDisplay(acc), text)
}
