package bot

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"ip-roller-bot/internal/registry"
	"ip-roller-bot/internal/storage"
)

// The add-account wizard collects one credential field at a time via buttons and
// plain-text replies, so the admin never has to hand-write JSON. It runs inside
// the accounts control-panel message (edited in place) and deletes the user's
// replies that carry secrets.

// startAddWizard shows the provider-type picker (step 0 of the wizard).
func (h *Handler) startAddWizard(ctx context.Context, b *bot.Bot, chatID int64, msgID int) {
	h.fsm.Clear(chatID)
	text := "➕ <b>Добавление аккаунта</b>\nВыбери провайдера — дальше проведу по шагам."
	h.editHTML(ctx, b, chatID, msgID, text, addTypeKeyboard())
}

// cbAddType begins the field-by-field wizard for the chosen provider type.
func (h *Handler) cbAddType(ctx context.Context, b *bot.Bot, u *models.Update) {
	q := u.CallbackQuery
	if !h.requireAdminCB(ctx, b, q) {
		return
	}
	h.ack(ctx, b, q)
	chatID, msgID := cbChatMsg(q)
	typ := strings.TrimPrefix(q.Data, "addtype:")
	if !registry.IsType(typ) {
		h.editHTML(ctx, b, chatID, msgID, "Неизвестный тип. Начни заново.", addTypeKeyboard())
		return
	}
	h.fsm.Update(chatID, func(s *dialogState) {
		*s = dialogState{
			Step:      stepAddLabel,
			MsgID:     msgID,
			AddType:   typ,
			AddFields: registry.Fields(typ),
			AddIdx:    0,
			AddCreds:  map[string]string{},
		}
	})
	h.editHTML(ctx, b, chatID, msgID, h.addLabelPrompt(typ), addCancelKeyboard())
}

// addLabelPrompt builds the "choose a label" step (step 1), with the credential
// guide embedded as an expandable blockquote.
func (h *Handler) addLabelPrompt(typ string) string {
	total := len(registry.Fields(typ)) + 1
	var sb strings.Builder
	fmt.Fprintf(&sb, "➕ <b>Добавление: %s</b>\n", htmlEsc(typeName(typ)))
	if g := guideStepsHTML(typ); g != "" {
		sb.WriteString(g + "\n")
	}
	fmt.Fprintf(&sb, "Шаг 1/%d — придумай короткое название (label), напр. <code>prod</code> или <code>личный</code>.\n", total)
	sb.WriteString("Пришли название одним сообщением.")
	return sb.String()
}

// acceptAddLabel stores the label and asks for the first credential field.
func (h *Handler) acceptAddLabel(ctx context.Context, b *bot.Bot, chatID int64, msgID int, label string) {
	label = strings.TrimSpace(label)
	if label == "" {
		h.send(ctx, b, chatID, "Название не может быть пустым. Пришли ещё раз.")
		return
	}
	if len(label) > 40 {
		h.send(ctx, b, chatID, "Слишком длинное название (макс. 40 символов). Пришли короче.")
		return
	}
	h.fsm.Update(chatID, func(s *dialogState) {
		s.Step = stepAddField
		s.AddLabel = label
		s.AddIdx = 0
	})
	h.promptAddField(ctx, b, chatID, msgID)
}

// promptAddField edits the wizard message to ask for the current field, or
// finalizes the wizard when all fields have been collected.
func (h *Handler) promptAddField(ctx context.Context, b *bot.Bot, chatID int64, msgID int) {
	st := h.fsm.Get(chatID)
	if st.AddIdx >= len(st.AddFields) {
		h.finalizeAddWizard(ctx, b, chatID, msgID)
		return
	}
	f := st.AddFields[st.AddIdx]
	total := len(st.AddFields) + 1
	kind := "обязательное"
	if !f.Required {
		kind = "необязательное"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "➕ <b>%s · %s</b>\n", htmlEsc(typeName(st.AddType)), htmlEsc(st.AddLabel))
	fmt.Fprintf(&sb, "Шаг %d/%d — поле <b>%s</b> (%s)\n", st.AddIdx+2, total, htmlEsc(f.Name), kind)
	fmt.Fprintf(&sb, "💡 %s\n", htmlEsc(fieldHint(st.AddType, f.Name)))
	if f.Secret {
		sb.WriteString("🔒 Сообщение с этим значением я удалю из чата.\n")
	}
	if f.Required {
		sb.WriteString("Пришли значение одним сообщением.")
	} else {
		sb.WriteString("Пришли значение или нажми «Пропустить».")
	}
	h.editHTML(ctx, b, chatID, msgID, sb.String(), addFieldKeyboard(!f.Required))
}

// acceptAddField validates and stores one field value, deleting the source
// message when the field is a secret, then advances to the next field.
func (h *Handler) acceptAddField(ctx context.Context, b *bot.Bot, chatID int64, userMsgID int, value string) {
	st := h.fsm.Get(chatID)
	if st.AddIdx >= len(st.AddFields) {
		h.finalizeAddWizard(ctx, b, chatID, st.MsgID)
		return
	}
	f := st.AddFields[st.AddIdx]
	value = strings.TrimSpace(value)
	if value == "" {
		h.send(ctx, b, chatID, "Пустое значение. Пришли ещё раз или нажми «Пропустить» (если поле необязательное).")
		return
	}
	if st.AddType == "gcore" && f.Name == "region_id" {
		if _, err := strconv.Atoi(value); err != nil {
			h.send(ctx, b, chatID, "region_id должно быть числом (напр. 7). Пришли ещё раз.")
			return
		}
	}
	// Hygiene: drop the user's message when it carried a secret.
	if f.Secret && userMsgID != 0 {
		if _, err := b.DeleteMessage(ctx, &bot.DeleteMessageParams{ChatID: chatID, MessageID: userMsgID}); err != nil {
			h.log.Debug("delete secret field message", "err", err)
		}
	}
	h.fsm.Update(chatID, func(s *dialogState) {
		s.AddCreds[f.Name] = value
		s.AddIdx++
	})
	h.promptAddField(ctx, b, chatID, st.MsgID)
}

// cbAddSkip skips the current optional field.
func (h *Handler) cbAddSkip(ctx context.Context, b *bot.Bot, u *models.Update) {
	q := u.CallbackQuery
	if !h.requireAdminCB(ctx, b, q) {
		return
	}
	h.ack(ctx, b, q)
	chatID, msgID := cbChatMsg(q)
	st := h.fsm.Get(chatID)
	if st.Step != stepAddField || st.AddIdx >= len(st.AddFields) {
		return
	}
	if st.AddFields[st.AddIdx].Required {
		_, _ = b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{
			CallbackQueryID: q.ID, Text: "Это поле обязательное — его нельзя пропустить.", ShowAlert: true,
		})
		return
	}
	h.fsm.Update(chatID, func(s *dialogState) { s.AddIdx++ })
	h.promptAddField(ctx, b, chatID, msgID)
}

// finalizeAddWizard validates the collected credentials, saves the account and
// reloads the registry.
func (h *Handler) finalizeAddWizard(ctx context.Context, b *bot.Bot, chatID int64, msgID int) {
	st := h.fsm.Get(chatID)
	typ, label, creds := st.AddType, st.AddLabel, st.AddCreds
	h.fsm.Clear(chatID)

	if err := registry.ValidateCreds(typ, creds); err != nil {
		h.editHTML(ctx, b, chatID, msgID, "⚠️ Ошибка проверки кред: "+htmlEsc(err.Error())+"\nНачни добавление заново.", addDoneKeyboard())
		return
	}
	id, err := h.store.UpsertAccount(ctx, storage.Account{Provider: typ, Label: label, Enabled: true, Credentials: creds})
	if err != nil {
		h.editHTML(ctx, b, chatID, msgID, "⚠️ Не удалось сохранить: "+htmlEsc(err.Error()), addDoneKeyboard())
		return
	}
	if err := h.reg.Reload(ctx); err != nil {
		h.log.Warn("reload after add wizard", "err", err)
	}
	text := fmt.Sprintf("✅ <b>Аккаунт сохранён</b>\n#%d %s · %s\n<blockquote>%s</blockquote>\nМожно запускать 🎲 Ролл.",
		id, htmlEsc(typeName(typ)), htmlEsc(label), htmlEsc(maskCreds(typ, creds)))
	h.editHTML(ctx, b, chatID, msgID, text, addDoneKeyboard())
}
