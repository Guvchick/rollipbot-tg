package bot

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

// Per-account "rolls per day" cap: overrides the provider-type default, set via
// the 📅 button in the accounts view and enforced by the engine's daily counter.

// cbAccountCapPick shows the daily-cap picker for one account (acc:cap:<id>).
func (h *Handler) cbAccountCapPick(ctx context.Context, b *bot.Bot, chatID int64, msgID int, arg string) {
	accountID, err := strconv.ParseInt(arg, 10, 64)
	if err != nil {
		return
	}
	acc, err := h.store.GetAccount(ctx, accountID)
	if err != nil {
		h.editHTML(ctx, b, chatID, msgID, "Аккаунт не найден.", menuBackKeyboard())
		return
	}
	cur := "по умолчанию для типа"
	if cap, ok, _ := h.store.AccountDailyCap(ctx, accountID); ok {
		if cap == 0 {
			cur = "без лимита (♾)"
		} else {
			cur = fmt.Sprintf("%d роллов/сутки", cap)
		}
	}
	text := fmt.Sprintf("📅 Лимит роллов в день для <b>%s · %s</b>\nСейчас: %s\nВыбери новое значение:",
		htmlEsc(typeName(acc.Provider)), htmlEsc(acc.Label), cur)
	h.editHTML(ctx, b, chatID, msgID, text, dailyCapPicker(accountID))
}

// cbAccountCap applies a picked cap (acccap:<accountID>:<value>).
func (h *Handler) cbAccountCap(ctx context.Context, b *bot.Bot, u *models.Update) {
	q := u.CallbackQuery
	if !h.requireAdminCB(ctx, b, q) {
		return
	}
	h.ack(ctx, b, q)
	chatID, msgID := cbChatMsg(q)
	parts := strings.Split(strings.TrimPrefix(q.Data, "acccap:"), ":")
	if len(parts) != 2 {
		return
	}
	accountID, _ := strconv.ParseInt(parts[0], 10, 64)
	switch parts[1] {
	case "custom":
		h.fsm.Update(chatID, func(s *dialogState) {
			*s = dialogState{Step: stepDailyCap, MsgID: msgID, CapAccountID: accountID}
		})
		h.editHTML(ctx, b, chatID, msgID,
			"✏️ Пришли число — сколько роллов в день разрешить (0 = без лимита).", menuBackKeyboard())
		return
	case "default":
		if err := h.store.ClearAccountDailyCap(ctx, accountID); err != nil {
			h.log.Warn("clear daily cap", "err", err)
		}
	default:
		n, err := strconv.Atoi(parts[1])
		if err != nil || n < 0 {
			return
		}
		if err := h.store.SetAccountDailyCap(ctx, accountID, n); err != nil {
			h.log.Warn("set daily cap", "err", err)
		}
	}
	if err := h.reg.Reload(ctx); err != nil {
		h.log.Warn("reload after daily cap", "err", err)
	}
	h.editAccountsMenu(ctx, b, chatID, msgID)
}

// acceptDailyCap handles the custom rolls-per-day number typed by the user.
func (h *Handler) acceptDailyCap(ctx context.Context, b *bot.Bot, chatID int64, text string) {
	st := h.fsm.Get(chatID)
	n, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || n < 0 {
		h.send(ctx, b, chatID, "Нужно целое число ≥ 0 (0 = без лимита). Пришли ещё раз.")
		return
	}
	if err := h.store.SetAccountDailyCap(ctx, st.CapAccountID, n); err != nil {
		h.send(ctx, b, chatID, "Не удалось сохранить: "+err.Error())
		return
	}
	msgID := st.MsgID
	h.fsm.Clear(chatID)
	if err := h.reg.Reload(ctx); err != nil {
		h.log.Warn("reload after custom daily cap", "err", err)
	}
	h.editAccountsMenu(ctx, b, chatID, msgID)
}
