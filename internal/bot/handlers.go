// Package bot is the Telegram UI layer: commands, the /roll FSM wizard, inline
// keyboards, and admin management of provider accounts and the user whitelist.
// It knows nothing about provider internals — only the engine and registry.
package bot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"log/slog"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"ip-roller-bot/internal/config"
	"ip-roller-bot/internal/engine"
	"ip-roller-bot/internal/provider"
	"ip-roller-bot/internal/registry"
	"ip-roller-bot/internal/storage"
)

// rollTimeout bounds a single /roll run.
const rollTimeout = 10 * time.Minute

// Handler wires the bot to the engine, storage, the account registry and ACL.
type Handler struct {
	cfg    *config.Config
	engine *engine.Engine
	store  storage.Storage
	reg    *registry.Registry
	acl    *ACL
	fsm    *FSM
	log    *slog.Logger
}

// Run builds the bot and blocks until ctx is cancelled.
func Run(
	ctx context.Context,
	cfg *config.Config,
	eng *engine.Engine,
	store storage.Storage,
	reg *registry.Registry,
	acl *ACL,
	log *slog.Logger,
) error {
	if !acl.Configured() {
		log.Warn("доступ не ограничен (нет admin_user_ids/allowed_user_ids/whitelist) — бот ответит любому")
	}

	h := &Handler{cfg: cfg, engine: eng, store: store, reg: reg, acl: acl, fsm: NewFSM(), log: log}

	opts := []bot.Option{
		bot.WithDefaultHandler(h.onText),
		bot.WithMiddlewares(h.authMiddleware),
		bot.WithMessageTextHandler("/start", bot.MatchTypeExact, h.cmdStart),
		bot.WithMessageTextHandler("/roll", bot.MatchTypeExact, h.cmdRoll),
		bot.WithMessageTextHandler("/pool", bot.MatchTypeExact, h.cmdPool),
		bot.WithMessageTextHandler("/limits", bot.MatchTypeExact, h.cmdLimits),
		bot.WithMessageTextHandler("/cancel", bot.MatchTypeExact, h.cmdCancel),
		bot.WithMessageTextHandler("/attach", bot.MatchTypePrefix, h.cmdAttach),
		// admin: accounts
		bot.WithMessageTextHandler("/accounts", bot.MatchTypeExact, h.cmdAccounts),
		bot.WithMessageTextHandler("/addaccount", bot.MatchTypePrefix, h.cmdAddAccount),
		bot.WithMessageTextHandler("/delaccount", bot.MatchTypePrefix, h.cmdDelAccount),
		bot.WithMessageTextHandler("/enableaccount", bot.MatchTypePrefix, h.cmdEnableAccount),
		bot.WithMessageTextHandler("/disableaccount", bot.MatchTypePrefix, h.cmdDisableAccount),
		// admin: users
		bot.WithMessageTextHandler("/users", bot.MatchTypeExact, h.cmdUsers),
		bot.WithMessageTextHandler("/adduser", bot.MatchTypePrefix, h.cmdAddUser),
		bot.WithMessageTextHandler("/deluser", bot.MatchTypePrefix, h.cmdDelUser),
		// callbacks
		bot.WithCallbackQueryDataHandler("prov:", bot.MatchTypePrefix, h.cbProvider),
		bot.WithCallbackQueryDataHandler("mask:", bot.MatchTypePrefix, h.cbMask),
		bot.WithCallbackQueryDataHandler("budget:", bot.MatchTypePrefix, h.cbBudget),
		bot.WithCallbackQueryDataHandler("attach:", bot.MatchTypePrefix, h.cbAttach),
		bot.WithCallbackQueryDataHandler("run", bot.MatchTypeExact, h.cbRun),
		bot.WithCallbackQueryDataHandler("cancel", bot.MatchTypeExact, h.cbCancel),
		bot.WithCallbackQueryDataHandler("pool", bot.MatchTypeExact, h.cbKeepInPool),
	}

	b, err := bot.New(cfg.Telegram.Token, opts...)
	if err != nil {
		return fmt.Errorf("create bot: %w", err)
	}
	log.Info("bot запущен", "accounts", reg.Len())
	b.Start(ctx)
	return nil
}

// --- middleware / helpers ---

func (h *Handler) authMiddleware(next bot.HandlerFunc) bot.HandlerFunc {
	return func(ctx context.Context, b *bot.Bot, update *models.Update) {
		if !h.acl.IsAllowed(userID(update)) {
			if update.CallbackQuery != nil {
				_, _ = b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{
					CallbackQueryID: update.CallbackQuery.ID, Text: "⛔ Нет доступа", ShowAlert: true,
				})
			} else if update.Message != nil {
				h.send(ctx, b, update.Message.Chat.ID, "⛔ Нет доступа. Обратись к администратору бота.")
			}
			return
		}
		next(ctx, b, update)
	}
}

// requireAdmin replies and returns false when the user is not an admin.
func (h *Handler) requireAdmin(ctx context.Context, b *bot.Bot, u *models.Update) bool {
	if h.acl.IsAdmin(userID(u)) {
		return true
	}
	h.send(ctx, b, u.Message.Chat.ID, "⛔ Команда только для администратора.")
	return false
}

func userID(u *models.Update) int64 {
	if u.Message != nil && u.Message.From != nil {
		return u.Message.From.ID
	}
	if u.CallbackQuery != nil {
		return u.CallbackQuery.From.ID
	}
	return 0
}

func cbChatMsg(q *models.CallbackQuery) (chatID int64, msgID int) {
	if q.Message.Message != nil {
		return q.Message.Message.Chat.ID, q.Message.Message.ID
	}
	return 0, 0
}

func (h *Handler) send(ctx context.Context, b *bot.Bot, chatID int64, text string) *models.Message {
	m, err := b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: text})
	if err != nil {
		h.log.Warn("send message failed", "err", err)
	}
	return m
}

func (h *Handler) edit(ctx context.Context, b *bot.Bot, chatID int64, msgID int, text string, kb models.ReplyMarkup) {
	if msgID == 0 {
		if _, err := b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: text, ReplyMarkup: kb}); err != nil {
			h.log.Warn("send failed", "err", err)
		}
		return
	}
	if _, err := b.EditMessageText(ctx, &bot.EditMessageTextParams{
		ChatID: chatID, MessageID: msgID, Text: text, ReplyMarkup: kb,
	}); err != nil {
		h.log.Debug("edit failed", "err", err)
	}
}

func (h *Handler) ack(ctx context.Context, b *bot.Bot, q *models.CallbackQuery) {
	_, _ = b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{CallbackQueryID: q.ID})
}

// displayKey renders a stored account key as a pretty label (falls back to the
// raw key when the account no longer exists).
func (h *Handler) displayKey(key string) string {
	if a, ok := h.reg.Get(key); ok {
		return accountDisplay(a)
	}
	return key
}

// --- commands ---

func (h *Handler) cmdStart(ctx context.Context, b *bot.Bot, u *models.Update) {
	text := "👋 IP-Roller Bot\n\n" +
		"Роллю публичные/floating IP у облачных провайдеров до попадания в маску.\n\n" +
		"Команды:\n" +
		"/roll — мастер роллинга\n" +
		"/pool — зарезервированные адреса\n" +
		"/attach <ip> <vm_id> — привязать адрес к ВМ\n" +
		"/limits — дневные лимиты по аккаунтам\n" +
		"/cancel — отменить диалог"
	if h.acl.IsAdmin(userID(u)) {
		text += "\n\nАдмин:\n" +
			"/accounts · /addaccount · /delaccount · /enableaccount · /disableaccount\n" +
			"/users · /adduser · /deluser"
	}
	h.send(ctx, b, u.Message.Chat.ID, text)
}

func (h *Handler) cmdRoll(ctx context.Context, b *bot.Bot, u *models.Update) {
	chatID := u.Message.Chat.ID
	accs := h.reg.Accounts()
	if len(accs) == 0 {
		h.send(ctx, b, chatID, "Нет включённых аккаунтов. Админ может добавить: /addaccount")
		return
	}
	m, err := b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID:      chatID,
		Text:        "1/4 — выбери аккаунт:",
		ReplyMarkup: providerKeyboard(accs),
	})
	if err != nil {
		h.log.Warn("cmdRoll send failed", "err", err)
		return
	}
	h.fsm.Update(chatID, func(s *dialogState) { *s = dialogState{Step: stepProvider, MsgID: m.ID} })
}

func (h *Handler) cmdPool(ctx context.Context, b *bot.Bot, u *models.Update) {
	ips, err := h.store.ListPoolIPs(ctx)
	if err != nil {
		h.send(ctx, b, u.Message.Chat.ID, "Ошибка чтения пула: "+err.Error())
		return
	}
	if len(ips) == 0 {
		h.send(ctx, b, u.Message.Chat.ID, "Пул пуст. Сначала запусти /roll.")
		return
	}
	var sb strings.Builder
	sb.WriteString("📦 Зарезервированные адреса:\n")
	for _, p := range ips {
		state := "свободен"
		if p.AttachedVM != "" {
			state = "привязан к " + p.AttachedVM
		}
		fmt.Fprintf(&sb, "• %s — %s [%s] (%s)\n", p.IP, h.displayKey(p.Provider), state, p.MatchedMask)
	}
	h.send(ctx, b, u.Message.Chat.ID, sb.String())
}

func (h *Handler) cmdLimits(ctx context.Context, b *bot.Bot, u *models.Update) {
	accs := h.reg.Accounts()
	if len(accs) == 0 {
		h.send(ctx, b, u.Message.Chat.ID, "Нет включённых аккаунтов.")
		return
	}
	var sb strings.Builder
	sb.WriteString("📊 Дневные лимиты:\n")
	for _, a := range accs {
		caps := a.Caps()
		limit := "без дневного лимита (только квота)"
		if caps.DailyCap > 0 {
			limit = fmt.Sprintf("%d/%d (осталось %d)", h.engine.DailyUsed(a.Key()), caps.DailyCap, h.engine.DailyRemaining(a.Key(), caps.DailyCap))
		}
		fmt.Fprintf(&sb, "• %s — %s, rps=%.0f\n", accountDisplay(a), limit, caps.RateLimitRPS)
	}
	h.send(ctx, b, u.Message.Chat.ID, sb.String())
}

func (h *Handler) cmdCancel(ctx context.Context, b *bot.Bot, u *models.Update) {
	h.fsm.Clear(u.Message.Chat.ID)
	h.send(ctx, b, u.Message.Chat.ID, "Диалог отменён.")
}

// cmdAttach: /attach <ip> <vm_id>
func (h *Handler) cmdAttach(ctx context.Context, b *bot.Bot, u *models.Update) {
	chatID := u.Message.Chat.ID
	fields := strings.Fields(u.Message.Text)
	if len(fields) != 3 {
		h.send(ctx, b, chatID, "Использование: /attach <ip> <vm_id>")
		return
	}
	pool, err := h.store.GetPoolIPByIP(ctx, fields[1])
	if err != nil {
		h.send(ctx, b, chatID, "Адрес не найден в пуле: "+fields[1])
		return
	}
	h.doAttach(ctx, b, chatID, pool, fields[2])
}

// --- admin: accounts ---

func (h *Handler) cmdAccounts(ctx context.Context, b *bot.Bot, u *models.Update) {
	if !h.requireAdmin(ctx, b, u) {
		return
	}
	accs, err := h.store.ListAccounts(ctx)
	if err != nil {
		h.send(ctx, b, u.Message.Chat.ID, "Ошибка: "+err.Error())
		return
	}
	if len(accs) == 0 {
		h.send(ctx, b, u.Message.Chat.ID, "Аккаунтов нет. Добавь: /addaccount <тип> <label> <json>\nТипы: "+strings.Join(registry.Types, ", "))
		return
	}
	var sb strings.Builder
	sb.WriteString("🔐 Аккаунты:\n")
	for _, a := range accs {
		flag := "✅"
		if !a.Enabled {
			flag = "⛔"
		}
		fmt.Fprintf(&sb, "%s #%d %s · %s — %s\n", flag, a.ID, typeName(a.Provider), a.Label, maskCreds(a.Provider, a.Credentials))
	}
	sb.WriteString("\nУправление: /enableaccount <id> · /disableaccount <id> · /delaccount <id>")
	h.send(ctx, b, u.Message.Chat.ID, sb.String())
}

// cmdAddAccount: /addaccount <provider> <label> <json-creds>
func (h *Handler) cmdAddAccount(ctx context.Context, b *bot.Bot, u *models.Update) {
	if !h.requireAdmin(ctx, b, u) {
		return
	}
	chatID := u.Message.Chat.ID
	rest := strings.TrimSpace(strings.TrimPrefix(u.Message.Text, "/addaccount"))
	parts := strings.SplitN(rest, " ", 3)
	if len(parts) < 3 {
		h.send(ctx, b, chatID, addAccountHelp())
		return
	}
	typ, label, raw := parts[0], parts[1], strings.TrimSpace(parts[2])
	if !registry.IsType(typ) {
		h.send(ctx, b, chatID, "Неизвестный тип: "+typ+"\nДоступные: "+strings.Join(registry.Types, ", "))
		return
	}
	var creds map[string]string
	if err := json.Unmarshal([]byte(raw), &creds); err != nil {
		h.send(ctx, b, chatID, "Не удалось разобрать JSON кред: "+err.Error()+"\n\n"+addAccountHelp())
		return
	}
	if err := registry.ValidateCreds(typ, creds); err != nil {
		h.send(ctx, b, chatID, "Ошибка кред: "+err.Error()+"\n\n"+addAccountHelp())
		return
	}
	id, err := h.store.UpsertAccount(ctx, storage.Account{Provider: typ, Label: label, Enabled: true, Credentials: creds})
	if err != nil {
		h.send(ctx, b, chatID, "Не удалось сохранить: "+err.Error())
		return
	}
	if err := h.reg.Reload(ctx); err != nil {
		h.log.Warn("reload after addaccount", "err", err)
	}
	// сообщение содержит секреты — пытаемся удалить его из чата
	hygiene := "\n(исходное сообщение с кредами удалил)"
	if _, err := b.DeleteMessage(ctx, &bot.DeleteMessageParams{ChatID: chatID, MessageID: u.Message.ID}); err != nil {
		h.log.Debug("delete addaccount message", "err", err)
		hygiene = "\n⚠️ не смог удалить твоё сообщение с кредами — удали его вручную"
	}
	h.send(ctx, b, chatID, fmt.Sprintf("✅ Аккаунт сохранён: #%d %s · %s%s", id, typeName(typ), label, hygiene))
}

func (h *Handler) cmdDelAccount(ctx context.Context, b *bot.Bot, u *models.Update) {
	if !h.requireAdmin(ctx, b, u) {
		return
	}
	h.accountByIDAction(ctx, b, u, "/delaccount", func(id int64) error { return h.store.DeleteAccount(ctx, id) }, "удалён")
}

func (h *Handler) cmdEnableAccount(ctx context.Context, b *bot.Bot, u *models.Update) {
	if !h.requireAdmin(ctx, b, u) {
		return
	}
	h.accountByIDAction(ctx, b, u, "/enableaccount", func(id int64) error { return h.store.SetAccountEnabled(ctx, id, true) }, "включён")
}

func (h *Handler) cmdDisableAccount(ctx context.Context, b *bot.Bot, u *models.Update) {
	if !h.requireAdmin(ctx, b, u) {
		return
	}
	h.accountByIDAction(ctx, b, u, "/disableaccount", func(id int64) error { return h.store.SetAccountEnabled(ctx, id, false) }, "выключен")
}

func (h *Handler) accountByIDAction(ctx context.Context, b *bot.Bot, u *models.Update, cmd string, action func(int64) error, verb string) {
	chatID := u.Message.Chat.ID
	id, err := parseIDArg(u.Message.Text, cmd)
	if err != nil {
		h.send(ctx, b, chatID, "Использование: "+cmd+" <id> (см. /accounts)")
		return
	}
	if err := action(id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			h.send(ctx, b, chatID, "Аккаунт не найден: #"+strconv.FormatInt(id, 10))
		} else {
			h.send(ctx, b, chatID, "Ошибка: "+err.Error())
		}
		return
	}
	if err := h.reg.Reload(ctx); err != nil {
		h.log.Warn("reload after account action", "err", err)
	}
	h.send(ctx, b, chatID, fmt.Sprintf("✅ Аккаунт #%d %s.", id, verb))
}

// --- admin: users ---

func (h *Handler) cmdUsers(ctx context.Context, b *bot.Bot, u *models.Update) {
	if !h.requireAdmin(ctx, b, u) {
		return
	}
	var sb strings.Builder
	sb.WriteString("👥 Доступ к боту:\n")
	admins := h.acl.Admins()
	sort.Slice(admins, func(i, j int) bool { return admins[i] < admins[j] })
	for _, id := range admins {
		fmt.Fprintf(&sb, "• %d — админ\n", id)
	}
	for _, id := range h.acl.StaticAllowed() {
		fmt.Fprintf(&sb, "• %d — из конфига\n", id)
	}
	dyn, err := h.store.ListAllowedUsers(ctx)
	if err != nil {
		h.send(ctx, b, u.Message.Chat.ID, "Ошибка: "+err.Error())
		return
	}
	for _, usr := range dyn {
		note := ""
		if usr.Note != "" {
			note = " (" + usr.Note + ")"
		}
		fmt.Fprintf(&sb, "• %d — whitelist%s\n", usr.UserID, note)
	}
	sb.WriteString("\nУправление: /adduser <id> [заметка] · /deluser <id>")
	h.send(ctx, b, u.Message.Chat.ID, sb.String())
}

func (h *Handler) cmdAddUser(ctx context.Context, b *bot.Bot, u *models.Update) {
	if !h.requireAdmin(ctx, b, u) {
		return
	}
	chatID := u.Message.Chat.ID
	fields := strings.Fields(u.Message.Text)
	if len(fields) < 2 {
		h.send(ctx, b, chatID, "Использование: /adduser <telegram_id> [заметка]")
		return
	}
	id, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		h.send(ctx, b, chatID, "id должен быть числом.")
		return
	}
	note := strings.Join(fields[2:], " ")
	if err := h.acl.Add(ctx, id, note); err != nil {
		h.send(ctx, b, chatID, "Ошибка: "+err.Error())
		return
	}
	h.send(ctx, b, chatID, fmt.Sprintf("✅ Пользователь %d добавлен в whitelist.", id))
}

func (h *Handler) cmdDelUser(ctx context.Context, b *bot.Bot, u *models.Update) {
	if !h.requireAdmin(ctx, b, u) {
		return
	}
	chatID := u.Message.Chat.ID
	id, err := parseIDArg(u.Message.Text, "/deluser")
	if err != nil {
		h.send(ctx, b, chatID, "Использование: /deluser <telegram_id>")
		return
	}
	if err := h.acl.Remove(ctx, id); err != nil {
		h.send(ctx, b, chatID, "Ошибка: "+err.Error())
		return
	}
	h.send(ctx, b, chatID, fmt.Sprintf("✅ Пользователь %d удалён из whitelist.", id))
}

// --- callbacks ---

func (h *Handler) cbProvider(ctx context.Context, b *bot.Bot, u *models.Update) {
	q := u.CallbackQuery
	h.ack(ctx, b, q)
	chatID, msgID := cbChatMsg(q)
	key := strings.TrimPrefix(q.Data, "prov:")
	acc, ok := h.reg.Get(key)
	if !ok {
		h.edit(ctx, b, chatID, msgID, "Аккаунт больше недоступен. Запусти /roll заново.", nil)
		return
	}
	h.fsm.Update(chatID, func(s *dialogState) {
		s.Step = stepMask
		s.Provider = key
		s.MsgID = msgID
	})
	masks := h.providerMasks(acc.Type())
	text := fmt.Sprintf("2/4 — %s.\nВведи маску текстом (185.12.0.0/16 или 95.142.*.*)\nили выбери пресет:", accountDisplay(acc))
	h.edit(ctx, b, chatID, msgID, text, maskKeyboard(masks))
}

func (h *Handler) cbMask(ctx context.Context, b *bot.Bot, u *models.Update) {
	q := u.CallbackQuery
	h.ack(ctx, b, q)
	chatID, msgID := cbChatMsg(q)
	h.acceptMask(ctx, b, chatID, msgID, strings.TrimPrefix(q.Data, "mask:"))
}

func (h *Handler) cbBudget(ctx context.Context, b *bot.Bot, u *models.Update) {
	q := u.CallbackQuery
	h.ack(ctx, b, q)
	chatID, msgID := cbChatMsg(q)
	h.acceptBudget(ctx, b, chatID, msgID, strings.TrimPrefix(q.Data, "budget:"))
}

func (h *Handler) cbRun(ctx context.Context, b *bot.Bot, u *models.Update) {
	q := u.CallbackQuery
	h.ack(ctx, b, q)
	chatID, msgID := cbChatMsg(q)
	st := h.fsm.Get(chatID)
	if st.Step != stepConfirm || st.Provider == "" || st.Mask == "" || st.Budget <= 0 {
		h.edit(ctx, b, chatID, msgID, "Сначала пройди мастер /roll заново.", nil)
		return
	}
	prov, mask, budget := st.Provider, st.Mask, st.Budget
	h.fsm.Update(chatID, func(s *dialogState) { s.Step = stepRunning })
	h.edit(ctx, b, chatID, msgID, "⏳ Запускаю роллинг…", nil)
	go h.runRoll(b, chatID, msgID, prov, mask, budget)
}

func (h *Handler) cbCancel(ctx context.Context, b *bot.Bot, u *models.Update) {
	q := u.CallbackQuery
	h.ack(ctx, b, q)
	chatID, msgID := cbChatMsg(q)
	h.fsm.Clear(chatID)
	h.edit(ctx, b, chatID, msgID, "Диалог отменён.", nil)
}

func (h *Handler) cbKeepInPool(ctx context.Context, b *bot.Bot, u *models.Update) {
	q := u.CallbackQuery
	h.ack(ctx, b, q)
	chatID, msgID := cbChatMsg(q)
	st := h.fsm.Get(chatID)
	h.edit(ctx, b, chatID, msgID, fmt.Sprintf("✅ Адрес %s оставлен в пуле. /pool — список.", st.ResultIP), nil)
	h.fsm.Clear(chatID)
}

func (h *Handler) cbAttach(ctx context.Context, b *bot.Bot, u *models.Update) {
	q := u.CallbackQuery
	h.ack(ctx, b, q)
	chatID, msgID := cbChatMsg(q)
	h.fsm.Update(chatID, func(s *dialogState) {
		s.Step = stepAttachVM
		s.MsgID = msgID
	})
	h.edit(ctx, b, chatID, msgID, "Пришли ID ВМ (или Neutron port_id) одним сообщением для привязки адреса.", nil)
}

// --- free-text router (default handler) ---

func (h *Handler) onText(ctx context.Context, b *bot.Bot, u *models.Update) {
	if u.Message == nil || u.Message.Text == "" {
		return
	}
	chatID := u.Message.Chat.ID
	text := strings.TrimSpace(u.Message.Text)
	if strings.HasPrefix(text, "/") {
		h.send(ctx, b, chatID, "Неизвестная команда. /start — список.")
		return
	}
	st := h.fsm.Get(chatID)
	switch st.Step {
	case stepMask:
		h.acceptMask(ctx, b, chatID, st.MsgID, text)
	case stepBudget:
		h.acceptBudget(ctx, b, chatID, st.MsgID, text)
	case stepAttachVM:
		h.acceptAttachVM(ctx, b, chatID, text)
	default:
		h.send(ctx, b, chatID, "Чтобы начать — /roll.")
	}
}

// --- shared step logic ---

func (h *Handler) acceptMask(ctx context.Context, b *bot.Bot, chatID int64, msgID int, mask string) {
	if _, err := engine.ParseMask(mask); err != nil {
		h.send(ctx, b, chatID, "Некорректная маска: "+err.Error()+"\nПопробуй ещё раз.")
		return
	}
	st := h.fsm.Update(chatID, func(s *dialogState) {
		s.Step = stepBudget
		s.Mask = mask
	})
	hint := ""
	if acc, ok := h.reg.Get(st.Provider); ok && acc.Caps().MaxRollsPerRun > 0 {
		hint = fmt.Sprintf(" (макс. за запуск: %d)", acc.Caps().MaxRollsPerRun)
	}
	h.edit(ctx, b, chatID, msgID, "3/4 — сколько попыток?"+hint, budgetKeyboard())
}

func (h *Handler) acceptBudget(ctx context.Context, b *bot.Bot, chatID int64, msgID int, raw string) {
	st := h.fsm.Get(chatID)
	acc, ok := h.reg.Get(st.Provider)
	if !ok {
		h.edit(ctx, b, chatID, msgID, "Аккаунт больше недоступен. Запусти /roll заново.", nil)
		h.fsm.Clear(chatID)
		return
	}
	caps := acc.Caps()

	var budget int
	if raw == "max" || raw == "макс" {
		if budget = caps.MaxRollsPerRun; budget <= 0 {
			budget = 25
		}
	} else {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			h.send(ctx, b, chatID, "Введи положительное число попыток или нажми кнопку.")
			return
		}
		budget = n
	}
	if caps.MaxRollsPerRun > 0 && budget > caps.MaxRollsPerRun {
		budget = caps.MaxRollsPerRun
	}
	st = h.fsm.Update(chatID, func(s *dialogState) {
		s.Step = stepConfirm
		s.Budget = budget
	})
	h.edit(ctx, b, chatID, msgID, h.confirmText(st, acc), confirmKeyboard())
}

func (h *Handler) acceptAttachVM(ctx context.Context, b *bot.Bot, chatID int64, vmID string) {
	st := h.fsm.Get(chatID)
	if st.ResultIP == "" {
		h.send(ctx, b, chatID, "Нет адреса для привязки. Запусти /roll.")
		return
	}
	pool := storage.PoolIP{
		ID:         st.ResultPoolID,
		Provider:   st.Provider,
		ResourceID: st.ResultResID,
		IP:         st.ResultIP,
	}
	h.doAttach(ctx, b, chatID, pool, vmID)
	h.fsm.Clear(chatID)
}

// --- roll execution ---

func (h *Handler) runRoll(b *bot.Bot, chatID int64, msgID int, provKey, mask string, budget int) {
	ctx, cancel := context.WithTimeout(context.Background(), rollTimeout)
	defer cancel()

	acc, ok := h.reg.Get(provKey)
	if !ok {
		h.edit(ctx, b, chatID, msgID, "Аккаунт больше недоступен. Запусти /roll заново.", nil)
		h.fsm.Clear(chatID)
		return
	}
	display := accountDisplay(acc)
	matcher, err := engine.ParseMask(mask)
	if err != nil {
		h.edit(ctx, b, chatID, msgID, "Некорректная маска: "+err.Error(), nil)
		h.fsm.Clear(chatID)
		return
	}

	var lastEdit time.Time
	onAttempt := func(n int, ip string, matched bool) {
		now := time.Now()
		if !matched && now.Sub(lastEdit) < 450*time.Millisecond {
			return // throttle edits
		}
		lastEdit = now
		status := "❌ не совпало, роллю дальше…"
		if matched {
			status = "✅ совпало! адрес зарезервирован."
		}
		h.edit(ctx, b, chatID, msgID, fmt.Sprintf("🎲 %s\nМаска: %s\nПопытка %d/%d: %s\n%s",
			display, mask, n, budget, ip, status), nil)
	}

	res, err := h.engine.Roll(ctx, acc, matcher, budget, onAttempt)
	if err != nil {
		h.edit(ctx, b, chatID, msgID, h.rollErrText(display, err), nil)
		h.fsm.Clear(chatID)
		return
	}

	id, serr := h.store.AddPoolIP(ctx, storage.PoolIP{
		Provider:    acc.Name(), // account key
		ResourceID:  res.IP.ID,
		IP:          res.IP.Addr.String(),
		MatchedMask: mask,
	})
	if serr != nil {
		h.log.Warn("save pool ip failed", "err", serr)
	}
	h.fsm.Update(chatID, func(s *dialogState) {
		s.Step = stepResult
		s.Provider = provKey
		s.ResultIP = res.IP.Addr.String()
		s.ResultResID = res.IP.ID
		s.ResultPoolID = id
	})
	h.edit(ctx, b, chatID, msgID, fmt.Sprintf("✅ Готово!\nАккаунт: %s\nАдрес: %s\nСовпал за %d попыт.\nID ресурса: %s",
		display, res.IP.Addr.String(), res.Attempts, res.IP.ID), resultKeyboard(id))
}

func (h *Handler) doAttach(ctx context.Context, b *bot.Bot, chatID int64, pool storage.PoolIP, vmID string) {
	acc, ok := h.reg.Get(pool.Provider)
	if !ok {
		h.send(ctx, b, chatID, "Аккаунт недоступен: "+h.displayKey(pool.Provider))
		return
	}
	addr, err := netip.ParseAddr(pool.IP)
	if err != nil {
		h.send(ctx, b, chatID, "Некорректный адрес в пуле: "+pool.IP)
		return
	}
	if err := acc.Attach(ctx, provider.AllocatedIP{Addr: addr, ID: pool.ResourceID}, vmID); err != nil {
		h.send(ctx, b, chatID, "Не удалось привязать: "+err.Error())
		return
	}
	if pool.ID != 0 {
		if err := h.store.MarkAttached(ctx, pool.ID, vmID); err != nil {
			h.log.Warn("mark attached failed", "err", err)
		}
	}
	h.send(ctx, b, chatID, fmt.Sprintf("🔗 %s привязан к %s.", pool.IP, vmID))
}

// --- text builders ---

func (h *Handler) confirmText(st *dialogState, acc *provider.Account) string {
	caps := acc.Caps()
	cost := caps.CostPerRoll
	if cost == "" {
		cost = "—"
	}
	daily := "без дневного лимита"
	if caps.DailyCap > 0 {
		daily = fmt.Sprintf("осталось сегодня: %d", h.engine.DailyRemaining(acc.Key(), caps.DailyCap))
	}
	return fmt.Sprintf(
		"4/4 — подтверждение:\nАккаунт: %s\nМаска: %s\nПопыток: %d\nЦена за ролл: %s\n%s\n\nЗапускаем?",
		accountDisplay(acc), st.Mask, st.Budget, cost, daily,
	)
}

func (h *Handler) rollErrText(display string, err error) string {
	switch {
	case errors.Is(err, engine.ErrBudgetExhausted):
		return fmt.Sprintf("🚫 %s: совпадений нет — исчерпан лимит попыток. Увеличь budget или ослабь маску.", display)
	case errors.Is(err, engine.ErrDailyCap):
		return fmt.Sprintf("🚫 %s: достигнут дневной лимит роллов. Счётчик сбросится в полночь.", display)
	case errors.Is(err, provider.ErrNotImplemented):
		return fmt.Sprintf("⚠️ %s: %v", display, err)
	default:
		var apiErr *provider.APIError
		if errors.As(err, &apiErr) {
			return fmt.Sprintf("⚠️ %s: ошибка API (HTTP %d). Проверь токен/квоты.", display, apiErr.StatusCode)
		}
		return fmt.Sprintf("⚠️ %s: %v", display, err)
	}
}

// providerMasks returns configured preset masks for a provider type.
func (h *Handler) providerMasks(typ string) []string {
	if pc := h.cfg.Providers.Get(typ); pc != nil {
		return pc.Masks
	}
	return nil
}

// --- misc helpers ---

func parseIDArg(text, cmd string) (int64, error) {
	rest := strings.TrimSpace(strings.TrimPrefix(text, cmd))
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return 0, fmt.Errorf("нет аргумента")
	}
	return strconv.ParseInt(fields[0], 10, 64)
}

// maskCreds renders credentials for listings, masking secret fields.
func maskCreds(typ string, creds map[string]string) string {
	secret := map[string]bool{}
	for _, f := range registry.Fields(typ) {
		secret[f.Name] = f.Secret
	}
	keys := make([]string, 0, len(creds))
	for k := range creds {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		v := creds[k]
		if secret[k] {
			v = maskSecret(v)
		}
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ", ")
}

func maskSecret(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + "***" + s[len(s)-2:]
}

func addAccountHelp() string {
	var sb strings.Builder
	sb.WriteString("Использование: /addaccount <тип> <label> <json>\n")
	sb.WriteString("Тип повторно с тем же label обновляет аккаунт.\n\nПоля по типам:\n")
	for _, t := range registry.Types {
		var fs []string
		for _, f := range registry.Fields(t) {
			name := f.Name
			if f.Required {
				name = "*" + name
			}
			fs = append(fs, name)
		}
		fmt.Fprintf(&sb, "• %s: %s\n", t, strings.Join(fs, ", "))
	}
	sb.WriteString("\n(* — обязательное; все значения в JSON — строками, region_id тоже: \"7\")\n")
	sb.WriteString("Пример:\n/addaccount timeweb prod {\"token\":\"xxx\",\"availability_zone\":\"spb-1\"}")
	return sb.String()
}
