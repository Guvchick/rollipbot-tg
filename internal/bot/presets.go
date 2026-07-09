package bot

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"ip-roller-bot/internal/engine"
	"ip-roller-bot/internal/provider"
)

// Per-account "IP presets": target masks saved on an account. They show up as
// preset buttons in the roll wizard's mask step and are the target masks the
// auto-roll scheduler rolls against. Managed from 🔐 Аккаунты → 🎯.

// showPresets renders the IP-preset manager for one account in place.
func (h *Handler) showPresets(ctx context.Context, b *bot.Bot, chatID int64, msgID int, accountID int64) {
	acc, err := h.store.GetAccount(ctx, accountID)
	if err != nil {
		h.edit(ctx, b, chatID, msgID, "Аккаунт не найден.", nil)
		return
	}
	masks, err := h.store.ListAccountMasks(ctx, accountID)
	if err != nil {
		h.edit(ctx, b, chatID, msgID, "Ошибка чтения пресетов: "+err.Error(), nil)
		return
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "🎯 Пресеты IP · %s · %s\n", typeName(acc.Provider), acc.Label)
	sb.WriteString("Сохранённые маски-цели этого аккаунта: кнопки в мастере ролла и цели авто-ролла.\n")
	if len(masks) == 0 {
		sb.WriteString("\nПока пусто. Нажми «➕ Добавить пресет» и пришли маску (CIDR 185.12.0.0/16 или октет 95.142.*.*).")
	}
	h.edit(ctx, b, chatID, msgID, sb.String(), presetsMenu(accountID, masks))
}

// cbPresets handles the pmask:* callbacks (add / delete / noop label).
func (h *Handler) cbPresets(ctx context.Context, b *bot.Bot, u *models.Update) {
	q := u.CallbackQuery
	if !h.requireAdminCB(ctx, b, q) {
		return
	}
	h.ack(ctx, b, q)
	chatID, msgID := cbChatMsg(q)
	data := strings.TrimPrefix(q.Data, "pmask:")

	switch {
	case data == "noop":
		return
	case strings.HasPrefix(data, "add:"):
		id, err := strconv.ParseInt(strings.TrimPrefix(data, "add:"), 10, 64)
		if err != nil {
			return
		}
		h.fsm.Update(chatID, func(s *dialogState) {
			s.Step = stepAddPreset
			s.PresetAccountID = id
			s.MsgID = msgID
		})
		h.edit(ctx, b, chatID, msgID,
			"🎯 Пришли маску-цель одним сообщением (можно несколько — по одной на строку или через запятую).\n"+
				"Примеры: 185.12.0.0/16 · 95.142.*.* · 92.38.0-50.*",
			presetInputKeyboard(id))
	case strings.HasPrefix(data, "del:"):
		rest := strings.TrimPrefix(data, "del:")
		idStr, mask, ok := strings.Cut(rest, ":")
		if !ok {
			return
		}
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			return
		}
		if err := h.store.RemoveAccountMask(ctx, id, mask); err != nil {
			h.log.Warn("remove preset mask", "err", err)
		}
		h.showPresets(ctx, b, chatID, msgID, id)
	}
}

// acceptPresetMask validates and saves one or more preset masks for the account.
func (h *Handler) acceptPresetMask(ctx context.Context, b *bot.Bot, chatID int64, raw string) {
	st := h.fsm.Get(chatID)
	accountID, msgID := st.PresetAccountID, st.MsgID
	masks := splitMasks(raw)
	if len(masks) == 0 {
		h.send(ctx, b, chatID, "Не вижу ни одной маски. Пришли ещё раз.")
		return
	}
	if _, err := engine.ParseMasks(masks); err != nil {
		h.send(ctx, b, chatID, "Некорректная маска: "+err.Error()+"\nПришли ещё раз.")
		return
	}
	for _, m := range masks {
		if err := h.store.AddAccountMask(ctx, accountID, m); err != nil {
			h.log.Warn("add preset mask", "err", err)
		}
	}
	h.fsm.Update(chatID, func(s *dialogState) { s.Step = stepIdle })
	h.showPresets(ctx, b, chatID, msgID, accountID)
}

// presetInputKeyboard is the cancel row shown while waiting for a preset mask.
func presetInputKeyboard(accountID int64) *models.InlineKeyboardMarkup {
	return &models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{
		{{Text: "⬅️ Назад к пресетам", CallbackData: fmt.Sprintf("acc:masks:%d", accountID)}},
	}}
}

// masksForAccount returns the mask presets offered in the roll wizard: the
// account's own saved presets first, then the provider-type config masks, deduped.
func (h *Handler) masksForAccount(ctx context.Context, acc *provider.Account) []string {
	seen := map[string]bool{}
	var out []string
	add := func(ms []string) {
		for _, m := range ms {
			if m != "" && !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	if presets, err := h.store.ListAccountMasks(ctx, acc.ID()); err == nil {
		add(presets)
	}
	add(h.providerMasks(acc.Type()))
	return out
}
