package bot

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"ip-roller-bot/internal/engine"
	"ip-roller-bot/internal/provider"
	"ip-roller-bot/internal/storage"
)

// Auto-roll: a background scheduler re-rolls every account that opted in (per
// account 🔁 toggle) once per configured interval (default 24h), using the
// account's 🎯 IP presets as targets, and reports each run into the account's
// forum topic (the same topics the bot already creates). Survives restarts via
// account_autoroll.last_run in SQLite.

const defaultAutoBudget = 25

// startAutoRoll launches the scheduler loop if auto-roll is globally enabled.
func (h *Handler) startAutoRoll(ctx context.Context, b *bot.Bot) {
	if !h.cfg.AutoRoll.IsEnabled() {
		h.log.Info("авто-ролл выключен глобально (autoroll.enabled: false)")
		return
	}
	go h.autoRollLoop(ctx, b)
	h.log.Info("авто-ролл включён", "interval", h.cfg.AutoRoll.Interval())
}

// autoRollLoop periodically wakes and rolls any account whose interval elapsed.
func (h *Handler) autoRollLoop(ctx context.Context, b *bot.Bot) {
	interval := h.cfg.AutoRoll.Interval()
	// Check more often than the interval so newly-due accounts don't wait a full
	// interval past their mark; clamp to a sane [5m, 1h] window.
	check := interval / 6
	if check < 5*time.Minute {
		check = 5 * time.Minute
	}
	if check > time.Hour {
		check = time.Hour
	}
	timer := time.NewTimer(time.Minute) // small settle delay after startup
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		h.autoRollDue(ctx, b, interval)
		timer.Reset(check)
	}
}

// autoRollDue rolls every enabled account whose last run is older than interval.
func (h *Handler) autoRollDue(ctx context.Context, b *bot.Bot, interval time.Duration) {
	rows, err := h.store.ListAutoRoll(ctx)
	if err != nil {
		h.log.Warn("авто-ролл: чтение конфига", "err", err)
		return
	}
	now := time.Now()
	for _, ar := range rows {
		if !ar.Enabled {
			continue
		}
		if !ar.LastRun.IsZero() && now.Sub(ar.LastRun) < interval {
			continue
		}
		acc := h.accountByID(ar.AccountID)
		if acc == nil {
			continue // account disabled or deleted — skip until re-enabled
		}
		budget := ar.Budget
		if budget <= 0 {
			budget = defaultAutoBudget
		}
		rctx, cancel := context.WithTimeout(ctx, rollTimeout)
		h.log.Info("авто-ролл: запуск", "account", accountDisplay(acc), "budget", budget)
		summary := h.autoRollOnce(rctx, b, acc, budget)
		cancel()
		h.log.Info("авто-ролл: итог", "account", accountDisplay(acc), "summary", summary)
		if err := h.store.TouchAutoRollRun(ctx, ar.AccountID, time.Now()); err != nil {
			h.log.Warn("авто-ролл: не сохранил last_run", "err", err)
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// autoRollOnce runs one headless roll for an account against its preset masks,
// saves a caught IP to the pool, updates the account's stats table and posts a
// summary to its topic. Returns a short human summary (also used by "run now").
func (h *Handler) autoRollOnce(ctx context.Context, b *bot.Bot, acc *provider.Account, budget int) string {
	display := accountDisplay(acc)
	masks, _ := h.store.ListAccountMasks(ctx, acc.ID())
	if len(masks) == 0 {
		s := "нет пресетов-целей — пропускаю (добавь 🎯 Пресеты для этого аккаунта)"
		h.notifier.AutoRoll(ctx, b, display, s, nil)
		return s
	}
	matcher, err := engine.ParseMasks(masks)
	if err != nil {
		s := "некорректные пресеты: " + err.Error()
		h.notifier.AutoRoll(ctx, b, display, s, nil)
		return s
	}
	maskStr := strings.Join(masks, ", ")

	h.autoCleanupAccount(ctx, b, acc)
	h.postLimits(ctx, b, acc)

	var rolled []string
	onAttempt := func(_ int, ip string, matched bool) {
		tag := "❌"
		if matched {
			tag = "✅"
		}
		rolled = append(rolled, tag+" "+ip)
	}

	res, err := h.engine.Roll(ctx, acc, matcher, budget, onAttempt)
	var summary string
	switch {
	case err == nil:
		if _, serr := h.store.AddPoolIP(ctx, storage.PoolIP{
			Provider:    acc.Name(),
			ResourceID:  res.IP.ID,
			IP:          res.IP.Addr.String(),
			MatchedMask: maskStr,
		}); serr != nil {
			h.log.Warn("авто-ролл: сохранение пула", "err", serr)
		}
		summary = fmt.Sprintf("🎯 поймал %s за %d попыт. — в пуле", res.IP.Addr.String(), res.Attempts)
	case isQuotaErr(err):
		summary = "⛔ квота провайдера исчерпана"
	case errors.Is(err, engine.ErrBudgetExhausted):
		summary = fmt.Sprintf("🟡 без совпадений за %d попыт. (цели: %s)", budget, maskStr)
	case errors.Is(err, engine.ErrDailyCap):
		summary = "🚫 дневной лимит роллов исчерпан"
	default:
		summary = "⚠️ ошибка: " + err.Error()
	}
	h.notifier.AutoRoll(ctx, b, display, summary, rolled)
	h.postLimits(ctx, b, acc)
	return summary
}

func isQuotaErr(err error) bool {
	var q *provider.QuotaError
	return errors.As(err, &q)
}

// accountByID finds an enabled account by its accounts-table id, or nil.
func (h *Handler) accountByID(id int64) *provider.Account {
	for _, a := range h.reg.Accounts() {
		if a.ID() == id {
			return a
		}
	}
	return nil
}

// --- auto-roll config UI (🔐 Аккаунты → 🔁) ---

// showAutoRoll renders the per-account auto-roll config screen in place.
func (h *Handler) showAutoRoll(ctx context.Context, b *bot.Bot, chatID int64, msgID int, accountID int64) {
	acc, err := h.store.GetAccount(ctx, accountID)
	if err != nil {
		h.edit(ctx, b, chatID, msgID, "Аккаунт не найден.", nil)
		return
	}
	ar, _, _ := h.store.GetAutoRoll(ctx, accountID)
	if ar.Budget <= 0 {
		ar.Budget = defaultAutoBudget
	}
	masks, _ := h.store.ListAccountMasks(ctx, accountID)
	interval := h.cfg.AutoRoll.Interval()

	var sb strings.Builder
	fmt.Fprintf(&sb, "🔁 Авто-ролл · %s · %s\n", typeName(acc.Provider), acc.Label)
	status := "выключен"
	if ar.Enabled {
		status = "включён ✅"
	}
	fmt.Fprintf(&sb, "Статус: %s\n", status)
	fmt.Fprintf(&sb, "Интервал: раз в %.0f ч\n", interval.Hours())
	fmt.Fprintf(&sb, "Бюджет попыток за прогон: %d\n", ar.Budget)
	fmt.Fprintf(&sb, "Пресетов-целей: %d\n", len(masks))
	if !ar.LastRun.IsZero() {
		fmt.Fprintf(&sb, "Последний авто-ролл: %s\n", ar.LastRun.Local().Format("02.01.2006 15:04 MST"))
		fmt.Fprintf(&sb, "Следующий: ~%s\n", ar.LastRun.Add(interval).Local().Format("02.01.2006 15:04 MST"))
	}
	if len(masks) == 0 {
		sb.WriteString("\n⚠️ Нет пресетов-целей — добавь 🎯, иначе авто-ролл будет пропускать этот аккаунт.")
	}
	if !h.cfg.AutoRoll.IsEnabled() {
		sb.WriteString("\n⚠️ Авто-ролл выключен глобально (autoroll.enabled: false в конфиге) — расписание не работает.")
	}
	if !h.notifier.Enabled() {
		sb.WriteString("\nℹ️ Топики-уведомления не настроены — итоги авто-ролла будут только в логах (задай NOTIFY_CHAT_ID).")
	}
	h.edit(ctx, b, chatID, msgID, sb.String(), autoRollMenu(accountID, ar.Enabled, ar.Budget))
}

// cbAutoRoll handles the auto:* callbacks (toggle / budget / run now).
func (h *Handler) cbAutoRoll(ctx context.Context, b *bot.Bot, u *models.Update) {
	q := u.CallbackQuery
	if !h.requireAdminCB(ctx, b, q) {
		return
	}
	h.ack(ctx, b, q)
	chatID, msgID := cbChatMsg(q)
	data := strings.TrimPrefix(q.Data, "auto:")

	switch {
	case strings.HasPrefix(data, "toggle:"):
		id, err := strconv.ParseInt(strings.TrimPrefix(data, "toggle:"), 10, 64)
		if err != nil {
			return
		}
		ar, _, _ := h.store.GetAutoRoll(ctx, id)
		budget := ar.Budget
		if budget <= 0 {
			budget = defaultAutoBudget
		}
		enabling := !ar.Enabled
		if err := h.store.SetAutoRoll(ctx, storage.AutoRoll{AccountID: id, Enabled: enabling, Budget: budget}); err != nil {
			h.log.Warn("авто-ролл: сохранение", "err", err)
		}
		// On enable, stamp last_run=now so the first scheduled roll is one full
		// interval away (no surprise immediate roll); use «Прогнать сейчас» for now.
		if enabling {
			if err := h.store.TouchAutoRollRun(ctx, id, time.Now()); err != nil {
				h.log.Warn("авто-ролл: last_run", "err", err)
			}
		}
		h.showAutoRoll(ctx, b, chatID, msgID, id)

	case strings.HasPrefix(data, "budget:"):
		idStr, nStr, ok := strings.Cut(strings.TrimPrefix(data, "budget:"), ":")
		if !ok {
			return
		}
		id, err1 := strconv.ParseInt(idStr, 10, 64)
		n, err2 := strconv.Atoi(nStr)
		if err1 != nil || err2 != nil {
			return
		}
		ar, _, _ := h.store.GetAutoRoll(ctx, id)
		if err := h.store.SetAutoRoll(ctx, storage.AutoRoll{AccountID: id, Enabled: ar.Enabled, Budget: n}); err != nil {
			h.log.Warn("авто-ролл: бюджет", "err", err)
		}
		h.showAutoRoll(ctx, b, chatID, msgID, id)

	case strings.HasPrefix(data, "now:"):
		id, err := strconv.ParseInt(strings.TrimPrefix(data, "now:"), 10, 64)
		if err != nil {
			return
		}
		acc := h.accountByID(id)
		if acc == nil {
			h.edit(ctx, b, chatID, msgID, "Аккаунт выключен или удалён — включи его, чтобы прогнать.", autoRollMenu(id, false, defaultAutoBudget))
			return
		}
		ar, _, _ := h.store.GetAutoRoll(ctx, id)
		budget := ar.Budget
		if budget <= 0 {
			budget = defaultAutoBudget
		}
		h.edit(ctx, b, chatID, msgID, "⏳ Прогоняю авто-ролл сейчас…", nil)
		go func() {
			rctx, cancel := context.WithTimeout(context.Background(), rollTimeout)
			defer cancel()
			summary := h.autoRollOnce(rctx, b, acc, budget)
			_ = h.store.TouchAutoRollRun(context.Background(), id, time.Now())
			h.edit(context.Background(), b, chatID, msgID, "🔁 Авто-ролл (вручную): "+summary, autoRollMenu(id, ar.Enabled, budget))
		}()
	}
}
