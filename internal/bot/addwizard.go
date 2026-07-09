package bot

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"ip-roller-bot/internal/provider/gcore"
	"ip-roller-bot/internal/provider/mws"
	"ip-roller-bot/internal/registry"
	"ip-roller-bot/internal/storage"
)

// The add-account wizard collects the credentials first (one field at a time,
// via plain-text replies) and asks for an optional label last, so the admin can
// pick a provider and immediately paste the token — no JSON, no upfront naming.
// It runs inside the accounts control-panel message (edited in place) and tries
// to delete replies that carry secrets.

// startAddWizard shows the provider-type picker (step 0 of the wizard).
func (h *Handler) startAddWizard(ctx context.Context, b *bot.Bot, chatID int64, msgID int) {
	h.fsm.Clear(chatID)
	text := "➕ <b>Добавление аккаунта</b>\nВыбери провайдера — дальше проведу по шагам."
	h.editHTML(ctx, b, chatID, msgID, text, addTypeKeyboard())
}

// cbAddType begins the field-by-field wizard for the chosen provider type,
// asking for the first credential right away.
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
			Step:      stepAddField,
			MsgID:     msgID,
			AddType:   typ,
			AddFields: registry.WizardFields(typ),
			AddIdx:    0,
			AddCreds:  map[string]string{},
		}
	})
	h.promptAddField(ctx, b, chatID, msgID)
}

// promptAddField edits the wizard message to ask for the current credential
// field, or moves on to the (optional) label step once all fields are done.
func (h *Handler) promptAddField(ctx context.Context, b *bot.Bot, chatID int64, msgID int) {
	st := h.fsm.Get(chatID)
	// Fields may have been autofilled (mws: pasted resource path / key JSON).
	idx := st.AddIdx
	for idx < len(st.AddFields) && st.AddCreds[st.AddFields[idx].Name] != "" {
		idx++
	}
	if idx != st.AddIdx {
		h.fsm.Update(chatID, func(s *dialogState) { s.AddIdx = idx })
		st = h.fsm.Get(chatID)
	}
	if st.AddIdx >= len(st.AddFields) {
		h.promptAddLabel(ctx, b, chatID, msgID)
		return
	}
	f := st.AddFields[st.AddIdx]
	total := len(st.AddFields) + 1
	kind := "обязательное"
	if !f.Required {
		kind = "необязательное"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "➕ <b>Добавление: %s</b>\n", htmlEsc(typeName(st.AddType)))
	// Show the "where to get creds" guide once, on the very first field.
	if st.AddIdx == 0 {
		if g := guideStepsHTML(st.AddType); g != "" {
			sb.WriteString(g + "\n")
		}
	}
	fmt.Fprintf(&sb, "Шаг %d/%d — поле <b>%s</b> (%s)\n", st.AddIdx+1, total, htmlEsc(f.Name), kind)
	fmt.Fprintf(&sb, "💡 %s\n", htmlEsc(fieldHint(st.AddType, f.Name)))
	if f.Secret {
		sb.WriteString("🔒 Это секрет — постараюсь удалить твоё сообщение после ввода.\n")
	}
	if f.Required {
		sb.WriteString("👉 Пришли значение обычным сообщением в чат (можно вставить из буфера).")
	} else {
		sb.WriteString("👉 Пришли значение сообщением или нажми «Пропустить».")
	}
	h.editHTML(ctx, b, chatID, msgID, sb.String(), addFieldKeyboard(!f.Required))
}

// acceptAddField validates and stores one field value, deleting the source
// message when the field is a secret, then advances to the next field.
func (h *Handler) acceptAddField(ctx context.Context, b *bot.Bot, chatID int64, userMsgID int, value string) {
	st := h.fsm.Get(chatID)
	if st.AddIdx >= len(st.AddFields) {
		h.promptAddLabel(ctx, b, chatID, st.MsgID)
		return
	}
	f := st.AddFields[st.AddIdx]
	value = strings.TrimSpace(value)
	if value == "" {
		h.send(ctx, b, chatID, "Пустое значение. Пришли ещё раз или нажми «Пропустить» (если поле необязательное).")
		return
	}
	// mws: паста ресурсного пути или скачанного JSON раскладывается на поля сама.
	if st.AddType == "mws" && h.mwsAutofill(ctx, b, chatID, userMsgID, f, value) {
		return
	}
	// gcore: вставленная ссылка на проект раскладывается на project_id/region_id.
	if st.AddType == "gcore" && h.gcoreAutofill(ctx, b, chatID, f, value) {
		return
	}
	if st.AddType == "gcore" && f.Name == "region_id" {
		if _, err := strconv.Atoi(value); err != nil {
			h.send(ctx, b, chatID, "region_id должно быть числом (напр. 7) — или нажми «Пропустить», чтобы роллить по любому региону.")
			return
		}
	}
	// Hygiene: try to drop the user's message when it carried a secret. In
	// private chats Telegram forbids deleting the user's own messages, so this
	// may fail — that's fine, we just log it.
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

// mwsAutofill handles "вставил одну штуку — заполнилось всё" for mws: the
// downloaded authorized-key JSON or a resource path (iam/projects/…/
// serviceAccounts/…/authorizedKeys/… or a console URL) fills several fields at
// once; promptAddField then skips the filled steps. Returns true when the
// value was consumed (fields filled or a retry was requested).
func (h *Handler) mwsAutofill(ctx context.Context, b *bot.Bot, chatID int64, userMsgID int, f registry.Field, value string) bool {
	st := h.fsm.Get(chatID)
	deleteMsg := func() {
		if userMsgID == 0 {
			return
		}
		if _, err := b.DeleteMessage(ctx, &bot.DeleteMessageParams{ChatID: chatID, MessageID: userMsgID}); err != nil {
			h.log.Debug("delete secret field message", "err", err)
		}
	}
	// «Через браузер»: a pasted DevTools "Copy as cURL" (auto-refresh) or a
	// ready IAM/Bearer token → route to refresh_curl / token and jump to the only
	// other field the browser path needs, project_id.
	trimmed := strings.TrimSpace(value)
	low := strings.ToLower(trimmed)
	if strings.HasPrefix(low, "curl ") || strings.Contains(low, "authorization:") {
		deleteMsg()
		h.setMWSBrowserCred(ctx, b, chatID, "refresh_curl", trimmed, "запрос браузера (refresh_curl) — буду сам обновлять токен")
		return true
	}
	if strings.HasPrefix(trimmed, "eyJ") && strings.Count(trimmed, ".") >= 2 {
		deleteMsg()
		h.setMWSBrowserCred(ctx, b, chatID, "token", trimmed, "готовый IAM-токен из браузера (протухает за ~час)")
		return true
	}
	if strings.HasPrefix(value, "{") {
		keyID, saID, privPEM, err := mws.ResolveAuthorizedKeyJSON(value)
		deleteMsg() // JSON несёт приватный ключ — убираем сообщение в любом случае
		if err != nil {
			h.send(ctx, b, chatID, "⚠️ "+err.Error()+"\nПришли значение ещё раз.")
			return true
		}
		h.fsm.Update(chatID, func(s *dialogState) {
			s.AddCreds["private_key"] = privPEM
			s.AddCreds["key_id"] = keyID
			s.AddCreds["service_account_id"] = saID
		})
		h.send(ctx, b, chatID, fmt.Sprintf("✅ Разобрал JSON ключа: key_id=%s, service_account_id=%s, private_key взял оттуда же.", keyID, saID))
		h.promptAddField(ctx, b, chatID, st.MsgID)
		return true
	}
	project, sa, keyID, ok := mws.ParseResourcePath(value)
	if !ok {
		return false
	}
	if f.Secret {
		deleteMsg()
	}
	var filled []string
	h.fsm.Update(chatID, func(s *dialogState) {
		for name, v := range map[string]string{"project_id": project, "service_account_id": sa, "key_id": keyID} {
			if v != "" {
				s.AddCreds[name] = v
			}
		}
	})
	for _, kv := range []struct{ name, v string }{{"project_id", project}, {"service_account_id", sa}, {"key_id", keyID}} {
		if kv.v != "" {
			filled = append(filled, kv.name+"="+kv.v)
		}
	}
	h.send(ctx, b, chatID, "✅ Распознал путь, подставил: "+strings.Join(filled, ", ")+".")
	h.promptAddField(ctx, b, chatID, st.MsgID)
	return true
}

// gcoreAutofill lets the admin paste a Gcore console URL / project link into the
// project_id (or region_id) step instead of hunting for the ids: it pulls
// project_id — and region_id when the URL carries it — out of the link and skips
// the filled steps. A bare numeric id falls through to the normal path. Returns
// true when the value was consumed (fields filled or a hint shown).
func (h *Handler) gcoreAutofill(ctx context.Context, b *bot.Bot, chatID int64, f registry.Field, value string) bool {
	if f.Name != "project_id" && f.Name != "region_id" {
		return false
	}
	// Only intercept URL-shaped input; plain ids go through the normal path.
	if !strings.Contains(value, "/") && !strings.Contains(value, "gcore") {
		return false
	}
	projectID, regionID, ok := gcore.ParseConsoleURL(value)
	if !ok || projectID == "" {
		h.send(ctx, b, chatID, "⚠️ Не смог вытащить project_id из ссылки. Пришли числовой project_id или полную ссылку на проект (…/projects/<id>/…).")
		return true
	}
	st := h.fsm.Get(chatID)
	h.fsm.Update(chatID, func(s *dialogState) {
		s.AddCreds["project_id"] = projectID
		if regionID > 0 {
			s.AddCreds["region_id"] = strconv.Itoa(regionID)
		}
	})
	msg := "✅ Из ссылки: project_id=" + projectID
	if regionID > 0 {
		msg += ", region_id=" + strconv.Itoa(regionID)
	} else {
		msg += " (region_id не в ссылке — можно пропустить для «любого региона»)"
	}
	h.send(ctx, b, chatID, msg+".")
	h.promptAddField(ctx, b, chatID, st.MsgID)
	return true
}

// setMWSBrowserCred stores a browser-obtained credential (refresh_curl or a
// ready token) and jumps the wizard to project_id — the only other field the
// «через браузер» path needs (the ES256-key steps are skipped).
func (h *Handler) setMWSBrowserCred(ctx context.Context, b *bot.Bot, chatID int64, key, val, human string) {
	st := h.fsm.Get(chatID)
	idx := len(st.AddFields)
	for i, f := range st.AddFields {
		if f.Name == "project_id" {
			idx = i
			break
		}
	}
	h.fsm.Update(chatID, func(s *dialogState) {
		s.AddCreds[key] = val
		s.AddIdx = idx
	})
	h.send(ctx, b, chatID, "✅ Принял "+human+". Осталось указать project_id (ID проекта — сегмент URL консоли после /iam/).")
	h.promptAddField(ctx, b, chatID, st.MsgID)
}

// promptAddLabel asks for an optional human label (last step). It can be skipped
// — the wizard then picks a unique default name.
func (h *Handler) promptAddLabel(ctx context.Context, b *bot.Bot, chatID int64, msgID int) {
	st := h.fsm.Get(chatID)
	total := len(st.AddFields) + 1
	var sb strings.Builder
	fmt.Fprintf(&sb, "➕ <b>Добавление: %s</b> — почти готово!\n", htmlEsc(typeName(st.AddType)))
	fmt.Fprintf(&sb, "Шаг %d/%d — придумай короткое название (label), напр. <code>prod</code> или <code>личный</code>.\n", total, total)
	sb.WriteString("👉 Пришли название сообщением или нажми «Пропустить» — назову сам.")
	h.fsm.Update(chatID, func(s *dialogState) { s.Step = stepAddLabel })
	h.editHTML(ctx, b, chatID, msgID, sb.String(), addLabelKeyboard())
}

// acceptAddLabel stores the chosen label and finalizes the wizard.
func (h *Handler) acceptAddLabel(ctx context.Context, b *bot.Bot, chatID int64, msgID int, label string) {
	label = strings.TrimSpace(label)
	if label == "" {
		h.send(ctx, b, chatID, "Название пустое. Пришли ещё раз или нажми «Пропустить».")
		return
	}
	if len(label) > 40 {
		h.send(ctx, b, chatID, "Слишком длинное название (макс. 40 символов). Пришли короче или нажми «Пропустить».")
		return
	}
	h.fsm.Update(chatID, func(s *dialogState) { s.AddLabel = label })
	h.finalizeAddWizard(ctx, b, chatID, msgID)
}

// cbAddSkip skips the current optional field, or (on the label step) accepts a
// default label and finalizes.
func (h *Handler) cbAddSkip(ctx context.Context, b *bot.Bot, u *models.Update) {
	q := u.CallbackQuery
	if !h.requireAdminCB(ctx, b, q) {
		return
	}
	h.ack(ctx, b, q)
	chatID, msgID := cbChatMsg(q)
	st := h.fsm.Get(chatID)
	switch st.Step {
	case stepAddLabel:
		h.finalizeAddWizard(ctx, b, chatID, msgID) // empty label → auto default
	case stepAddField:
		if st.AddIdx >= len(st.AddFields) {
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
}

// finalizeAddWizard validates the collected credentials, saves the account
// (auto-naming when no label was given) and reloads the registry.
func (h *Handler) finalizeAddWizard(ctx context.Context, b *bot.Bot, chatID int64, msgID int) {
	st := h.fsm.Get(chatID)
	typ, label, creds := st.AddType, st.AddLabel, st.AddCreds
	h.fsm.Clear(chatID)
	if label == "" {
		label = h.uniqueLabel(ctx, typ)
	}

	id, err := h.persistAccount(ctx, typ, label, creds)
	if err != nil {
		h.editHTML(ctx, b, chatID, msgID, "⚠️ Не удалось сохранить: "+htmlEsc(err.Error())+"\nНачни добавление заново.", addDoneKeyboard())
		return
	}
	text := fmt.Sprintf("✅ <b>Аккаунт сохранён</b>\n#%d %s · %s\n<blockquote>%s</blockquote>\nМожно запускать 🎲 Ролл.",
		id, htmlEsc(typeName(typ)), htmlEsc(label), htmlEsc(maskCreds(typ, creds)))
	h.editHTML(ctx, b, chatID, msgID, text, addDoneKeyboard())
}

// persistAccount validates credentials, upserts the account and reloads the
// registry. Shared by the wizard and the /addaccount command.
func (h *Handler) persistAccount(ctx context.Context, typ, label string, creds map[string]string) (int64, error) {
	if err := registry.ValidateCreds(typ, creds); err != nil {
		return 0, err
	}
	id, err := h.store.UpsertAccount(ctx, storage.Account{Provider: typ, Label: label, Enabled: true, Credentials: creds})
	if err != nil {
		return 0, err
	}
	if err := h.reg.Reload(ctx); err != nil {
		h.log.Warn("reload after add account", "err", err)
	}
	return id, nil
}

// uniqueLabel returns a free "default"-style label for a provider type so
// auto-named accounts never collide with (and overwrite) an existing one.
func (h *Handler) uniqueLabel(ctx context.Context, typ string) string {
	used := map[string]bool{}
	if accs, err := h.store.ListAccounts(ctx); err == nil {
		for _, a := range accs {
			if a.Provider == typ {
				used[a.Label] = true
			}
		}
	}
	if !used["default"] {
		return "default"
	}
	for i := 2; i < 1000; i++ {
		c := fmt.Sprintf("default-%d", i)
		if !used[c] {
			return c
		}
	}
	return fmt.Sprintf("default-%d", time.Now().Unix())
}
