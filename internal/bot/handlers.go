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
	"sync"
	"time"

	"log/slog"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"ip-roller-bot/internal/config"
	"ip-roller-bot/internal/engine"
	"ip-roller-bot/internal/notify"
	"ip-roller-bot/internal/provider"
	"ip-roller-bot/internal/registry"
	"ip-roller-bot/internal/storage"
)

// rollTimeout bounds a single /roll run.
const rollTimeout = 10 * time.Minute

// Handler wires the bot to the engine, storage, the account registry, ACL and
// the forum-group notifier.
type Handler struct {
	cfg      *config.Config
	engine   *engine.Engine
	store    storage.Storage
	reg      *registry.Registry
	acl      *ACL
	notifier *notify.Notifier
	fsm      *FSM
	log      *slog.Logger

	// pinned main-menu message id per chat, so re-opening the menu unpins the
	// stale one instead of stacking pins.
	menuMu  sync.Mutex
	menuMsg map[int64]int
}

// Run builds the bot and blocks until ctx is cancelled.
func Run(
	ctx context.Context,
	cfg *config.Config,
	eng *engine.Engine,
	store storage.Storage,
	reg *registry.Registry,
	acl *ACL,
	notifier *notify.Notifier,
	log *slog.Logger,
) error {
	if !acl.Configured() {
		log.Warn("доступ не ограничен (нет admin_user_ids/allowed_user_ids/whitelist) — бот ответит любому")
	}

	h := &Handler{cfg: cfg, engine: eng, store: store, reg: reg, acl: acl, notifier: notifier, fsm: NewFSM(), log: log, menuMsg: map[int64]int{}}

	opts := []bot.Option{
		bot.WithDefaultHandler(h.onText),
		bot.WithMiddlewares(h.authMiddleware),
		bot.WithMessageTextHandler("/start", bot.MatchTypeExact, h.cmdStart),
		bot.WithMessageTextHandler("/menu", bot.MatchTypeExact, h.cmdMenu),
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
		// menu + account management callbacks
		bot.WithCallbackQueryDataHandler("menu:", bot.MatchTypePrefix, h.cbMenu),
		bot.WithCallbackQueryDataHandler("acc:", bot.MatchTypePrefix, h.cbAccount),
		// add-account wizard callbacks
		bot.WithCallbackQueryDataHandler("addtype:", bot.MatchTypePrefix, h.cbAddType),
		bot.WithCallbackQueryDataHandler("addskip", bot.MatchTypeExact, h.cbAddSkip),
		// proxy callbacks
		bot.WithCallbackQueryDataHandler("px:", bot.MatchTypePrefix, h.cbProxy),
		bot.WithCallbackQueryDataHandler("pxscheme:", bot.MatchTypePrefix, h.cbProxyScheme),
		bot.WithCallbackQueryDataHandler("accpx:", bot.MatchTypePrefix, h.cbAccountProxyBind),
		// roll wizard callbacks
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
	// Keep the "/" hint list short — the primary UI is the pinned button menu.
	if _, err := b.SetMyCommands(ctx, &bot.SetMyCommandsParams{Commands: []models.BotCommand{
		{Command: "start", Description: "Открыть меню (закрепить)"},
		{Command: "menu", Description: "Показать меню"},
		{Command: "roll", Description: "Запустить ролл IP"},
		{Command: "cancel", Description: "Отменить текущий диалог"},
	}}); err != nil {
		log.Debug("set my commands failed", "err", err)
	}
	log.Info("bot запущен", "accounts", reg.Len())
	b.Start(ctx)
	return nil
}

// --- middleware / helpers ---

func (h *Handler) authMiddleware(next bot.HandlerFunc) bot.HandlerFunc {
	return func(ctx context.Context, b *bot.Bot, update *models.Update) {
		if !h.acl.IsAllowed(userID(update)) {
			// Silently ignore unauthorized users (no reply). Callback queries are
			// acked quietly so the client stops its loading spinner.
			if update.CallbackQuery != nil {
				_, _ = b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{
					CallbackQueryID: update.CallbackQuery.ID,
				})
			}
			h.log.Info("отклонён неавторизованный пользователь", "user", userID(update))
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

// requireAdminCB gates a callback on admin rights, answering with an alert.
func (h *Handler) requireAdminCB(ctx context.Context, b *bot.Bot, q *models.CallbackQuery) bool {
	if h.acl.IsAdmin(q.From.ID) {
		return true
	}
	_, _ = b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{
		CallbackQueryID: q.ID, Text: "⛔ Только для администратора", ShowAlert: true,
	})
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

// sendHTML sends a Telegram HTML-formatted message, falling back to plain text
// (tags stripped) if Telegram rejects the markup.
func (h *Handler) sendHTML(ctx context.Context, b *bot.Bot, chatID int64, text string) {
	_, err := b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: chatID, Text: text, ParseMode: models.ParseModeHTML,
	})
	if err != nil {
		h.log.Warn("send html failed, falling back to plain", "err", err)
		h.send(ctx, b, chatID, stripTags(text))
	}
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

// editHTML edits a message with HTML markup, falling back to a plain-text edit
// (tags stripped) if Telegram rejects the markup.
func (h *Handler) editHTML(ctx context.Context, b *bot.Bot, chatID int64, msgID int, text string, kb models.ReplyMarkup) {
	if msgID == 0 {
		h.sendHTML(ctx, b, chatID, text)
		return
	}
	if _, err := b.EditMessageText(ctx, &bot.EditMessageTextParams{
		ChatID: chatID, MessageID: msgID, Text: text, ParseMode: models.ParseModeHTML, ReplyMarkup: kb,
	}); err != nil {
		h.log.Debug("edit html failed, retrying plain", "err", err)
		h.edit(ctx, b, chatID, msgID, stripTags(text), kb)
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
	h.sendMenu(ctx, b, u.Message.Chat.ID)
}

func (h *Handler) cmdMenu(ctx context.Context, b *bot.Bot, u *models.Update) {
	h.sendMenu(ctx, b, u.Message.Chat.ID)
}

// menuText is the main-menu body (HTML), shared by the pinned message and the
// "back to menu" navigation.
func (h *Handler) menuText() string {
	text := "👋 <b>IP-Roller</b> — главное меню\n" +
		"Роллю публичные/floating IP до попадания в маску.\n\n" +
		"Всё управление — кнопками ниже. Это меню закреплено — открывай его в " +
		"любой момент из закреплённого сообщения."
	if h.notifier.Enabled() {
		text += "\n\n🔔 Уведомления о ловле идут в форум-группу (по топикам на аккаунт)."
	}
	return text
}

func (h *Handler) sendMenu(ctx context.Context, b *bot.Bot, chatID int64) {
	m, err := b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: chatID, Text: h.menuText(), ParseMode: models.ParseModeHTML, ReplyMarkup: mainMenu(),
	})
	if err != nil {
		h.log.Warn("sendMenu failed", "err", err)
		return
	}
	h.pinMenu(ctx, b, chatID, m.ID)
}

// pinMenu pins the new menu message and unpins the previous one so the pinned
// control panel stays fresh instead of stacking. Pinning failures (e.g. missing
// rights in a group) are non-fatal — the menu still works from the message.
func (h *Handler) pinMenu(ctx context.Context, b *bot.Bot, chatID int64, msgID int) {
	h.menuMu.Lock()
	prev := h.menuMsg[chatID]
	h.menuMsg[chatID] = msgID
	h.menuMu.Unlock()

	if _, err := b.PinChatMessage(ctx, &bot.PinChatMessageParams{
		ChatID: chatID, MessageID: msgID, DisableNotification: true,
	}); err != nil {
		h.log.Debug("pin menu failed", "err", err)
		return
	}
	if prev != 0 && prev != msgID {
		if _, err := b.UnpinChatMessage(ctx, &bot.UnpinChatMessageParams{ChatID: chatID, MessageID: prev}); err != nil {
			h.log.Debug("unpin previous menu failed", "err", err)
		}
	}
}

func (h *Handler) cmdRoll(ctx context.Context, b *bot.Bot, u *models.Update) {
	h.sendRollStart(ctx, b, u.Message.Chat.ID, 0)
}

// sendRollStart kicks off the /roll wizard. When msgID != 0 (menu button) it
// runs inside that message (single live screen); from /roll it opens a new one.
func (h *Handler) sendRollStart(ctx context.Context, b *bot.Bot, chatID int64, msgID int) {
	accs := h.reg.Accounts()
	if len(accs) == 0 {
		h.edit(ctx, b, chatID, msgID, "Нет включённых аккаунтов. Добавь через меню → 🔐 Аккаунты.", menuBackKeyboard())
		return
	}
	if msgID == 0 {
		m, err := b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: chatID, Text: "1/4 — выбери аккаунт:", ReplyMarkup: providerKeyboard(accs),
		})
		if err != nil {
			h.log.Warn("sendRollStart failed", "err", err)
			return
		}
		msgID = m.ID
	} else {
		h.edit(ctx, b, chatID, msgID, "1/4 — выбери аккаунт:", providerKeyboard(accs))
	}
	h.fsm.Update(chatID, func(s *dialogState) { *s = dialogState{Step: stepProvider, MsgID: msgID} })
}

func (h *Handler) cmdPool(ctx context.Context, b *bot.Bot, u *models.Update) {
	h.showPool(ctx, b, u.Message.Chat.ID, 0)
}

// showPool lists reserved addresses. Pool rows are persisted at match time and
// are independent of any in-progress roll, so a caught IP shows here even while
// another roll is running or the result screen is still "pending".
func (h *Handler) showPool(ctx context.Context, b *bot.Bot, chatID int64, msgID int) {
	ips, err := h.store.ListPoolIPs(ctx)
	if err != nil {
		h.edit(ctx, b, chatID, msgID, "Ошибка чтения пула: "+err.Error(), menuBackKeyboard())
		return
	}
	if len(ips) == 0 {
		h.edit(ctx, b, chatID, msgID, "📦 Пул пуст. Запусти 🎲 Ролл — пойманные адреса появятся здесь.", menuBackKeyboard())
		return
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "📦 Зарезервированные адреса (%d):\n", len(ips))
	for _, p := range ips {
		state := "🟢 свободен (в ожидании привязки)"
		if p.AttachedVM != "" {
			state = "🔗 привязан к " + p.AttachedVM
		}
		fmt.Fprintf(&sb, "• %s — %s\n   %s · маска %s\n", p.IP, h.displayKey(p.Provider), state, p.MatchedMask)
	}
	h.edit(ctx, b, chatID, msgID, sb.String(), menuBackKeyboard())
}

func (h *Handler) cmdLimits(ctx context.Context, b *bot.Bot, u *models.Update) {
	h.showLimits(ctx, b, u.Message.Chat.ID)
}

func (h *Handler) showLimits(ctx context.Context, b *bot.Bot, chatID int64) {
	accs := h.reg.Accounts()
	if len(accs) == 0 {
		h.send(ctx, b, chatID, "Нет включённых аккаунтов.")
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
	h.send(ctx, b, chatID, sb.String())
}

func (h *Handler) cmdCancel(ctx context.Context, b *bot.Bot, u *models.Update) {
	chatID := u.Message.Chat.ID
	h.fsm.Clear(chatID)
	// Fold back into the pinned menu if we know it, else just reopen the menu.
	h.menuMu.Lock()
	msgID := h.menuMsg[chatID]
	h.menuMu.Unlock()
	if msgID != 0 {
		h.editHTML(ctx, b, chatID, msgID, h.menuText(), mainMenu())
	} else {
		h.sendMenu(ctx, b, chatID)
	}
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
	text, kb := h.accountsView(ctx)
	if _, err := b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: u.Message.Chat.ID, Text: text, ReplyMarkup: kb,
	}); err != nil {
		h.log.Warn("cmdAccounts send failed", "err", err)
	}
}

// accountsView builds the accounts list text + management keyboard.
func (h *Handler) accountsView(ctx context.Context) (string, *models.InlineKeyboardMarkup) {
	accs, err := h.store.ListAccounts(ctx)
	if err != nil {
		return "Ошибка: " + err.Error(), accountsMenu(nil)
	}
	if len(accs) == 0 {
		return "🔐 Аккаунтов нет.\nНажми «➕ Добавить аккаунт» — проведу по шагам.", accountsMenu(nil)
	}
	rows := make([]accountRow, 0, len(accs))
	var sb strings.Builder
	sb.WriteString("🔐 Аккаунты (слева — вкл/выкл, 🌐 — прокси, 🗑 — удалить):\n")
	for _, a := range accs {
		flag := "✅вкл"
		if !a.Enabled {
			flag = "⛔выкл"
		}
		disp := typeName(a.Provider) + " · " + a.Label
		pxLabel := ""
		if px, ok, _ := h.store.AccountProxy(ctx, a.ID); ok {
			pxLabel = px.Scheme + "·" + px.Label
		}
		pxNote := ""
		if pxLabel != "" {
			pxNote = " 🌐" + pxLabel
		}
		fmt.Fprintf(&sb, "• #%d %s [%s] — %s%s\n", a.ID, disp, flag, maskCreds(a.Provider, a.Credentials), pxNote)
		rows = append(rows, accountRow{ID: a.ID, Display: disp, Enabled: a.Enabled, Proxy: pxLabel})
	}
	return sb.String(), accountsMenu(rows)
}

// cmdAddAccount handles the text command. Accepted shapes:
//
//	/addaccount                          → general help
//	/addaccount <type>                   → per-type "where to get creds" guide
//	/addaccount <type> <token>           → bare secret (types with one required field)
//	/addaccount <type> <label> <token>   → bare secret with an explicit label
//	/addaccount <type> <label> <json>    → full JSON credentials
//
// The button wizard (🔐 Аккаунты → ➕) is the friendlier path; this stays for
// power users and old muscle memory.
func (h *Handler) cmdAddAccount(ctx context.Context, b *bot.Bot, u *models.Update) {
	if !h.requireAdmin(ctx, b, u) {
		return
	}
	chatID := u.Message.Chat.ID
	rest := strings.TrimSpace(strings.TrimPrefix(u.Message.Text, "/addaccount"))
	if rest == "" {
		h.sendHTML(ctx, b, chatID, generalAddHelpHTML())
		return
	}
	parts := strings.SplitN(rest, " ", 3)
	typ := parts[0]
	if !registry.IsType(typ) {
		h.send(ctx, b, chatID, "Неизвестный тип: "+typ+"\nДоступные: "+strings.Join(registry.Types, ", "))
		return
	}

	var label, credsArg string
	switch len(parts) {
	case 1:
		// just the type → walkthrough. If it only needs a token, say so.
		h.sendHTML(ctx, b, chatID, guideHTML(typ))
		if f := singleRequiredField(typ); f != "" {
			h.send(ctx, b, chatID, fmt.Sprintf("Проще всего: 🔐 Аккаунты → ➕, либо пришли одним сообщением:\n/addaccount %s <твой_%s>", typ, f))
		}
		return
	case 2:
		// type + one arg: treat it as a pasted token only if it looks like one,
		// otherwise it's a label with no creds yet → show the guide.
		if f := singleRequiredField(typ); f != "" && looksLikeToken(parts[1]) {
			label, credsArg = h.uniqueLabel(ctx, typ), parts[1]
		} else {
			h.sendHTML(ctx, b, chatID, guideHTML(typ))
			return
		}
	default:
		label, credsArg = parts[1], strings.TrimSpace(parts[2])
	}

	creds, err := parseCredsArg(typ, credsArg)
	if err != nil {
		h.send(ctx, b, chatID, "Ошибка кред: "+err.Error())
		h.sendHTML(ctx, b, chatID, guideHTML(typ))
		return
	}
	id, err := h.persistAccount(ctx, typ, label, creds)
	if err != nil {
		h.send(ctx, b, chatID, "Не удалось сохранить: "+err.Error())
		h.sendHTML(ctx, b, chatID, guideHTML(typ))
		return
	}
	// The message carried secrets — try to delete it from the chat.
	hygiene := "\n(исходное сообщение с кредами удалил)"
	if _, err := b.DeleteMessage(ctx, &bot.DeleteMessageParams{ChatID: chatID, MessageID: u.Message.ID}); err != nil {
		h.log.Debug("delete addaccount message", "err", err)
		hygiene = "\n⚠️ не смог удалить твоё сообщение с кредами — удали его вручную"
	}
	h.send(ctx, b, chatID, fmt.Sprintf("✅ Аккаунт сохранён: #%d %s · %s%s", id, typeName(typ), label, hygiene))
}

// singleRequiredField returns the sole required credential field for a type, or
// "" when it needs zero or several required fields.
func singleRequiredField(typ string) string {
	var req []string
	for _, f := range registry.Fields(typ) {
		if f.Required {
			req = append(req, f.Name)
		}
	}
	if len(req) == 1 {
		return req[0]
	}
	return ""
}

// looksLikeToken heuristically tells a pasted secret from a short label.
func looksLikeToken(s string) bool {
	return len(s) > 40 || strings.Contains(s, ".")
}

// parseCredsArg interprets the credential argument: a JSON object, or a single
// bare value when the type has exactly one required field.
func parseCredsArg(typ, arg string) (map[string]string, error) {
	arg = strings.TrimSpace(arg)
	if strings.HasPrefix(arg, "{") {
		var creds map[string]string
		if err := json.Unmarshal([]byte(arg), &creds); err != nil {
			return nil, fmt.Errorf("не удалось разобрать JSON: %w", err)
		}
		return creds, nil
	}
	field := singleRequiredField(typ)
	if field == "" {
		return nil, fmt.Errorf("для %s нужно несколько полей — пришли JSON или добавь через меню 🔐 → ➕", typ)
	}
	return map[string]string{field: arg}, nil
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

// --- menu + account callbacks ---

func (h *Handler) cbMenu(ctx context.Context, b *bot.Bot, u *models.Update) {
	q := u.CallbackQuery
	h.ack(ctx, b, q)
	chatID, msgID := cbChatMsg(q)
	switch strings.TrimPrefix(q.Data, "menu:") {
	case "roll":
		h.sendRollStart(ctx, b, chatID, msgID)
	case "pool":
		h.showPool(ctx, b, chatID, msgID)
	case "stats":
		h.showStats(ctx, b, chatID, msgID)
	case "accounts":
		if !h.requireAdminCB(ctx, b, q) {
			return
		}
		h.editAccountsMenu(ctx, b, chatID, msgID)
	case "proxies":
		if !h.requireAdminCB(ctx, b, q) {
			return
		}
		h.editProxiesMenu(ctx, b, chatID, msgID)
	case "back":
		h.fsm.Clear(chatID)
		h.editHTML(ctx, b, chatID, msgID, h.menuText(), mainMenu())
	}
}

func (h *Handler) cbAccount(ctx context.Context, b *bot.Bot, u *models.Update) {
	q := u.CallbackQuery
	if !h.requireAdminCB(ctx, b, q) {
		return
	}
	h.ack(ctx, b, q)
	chatID, msgID := cbChatMsg(q)
	data := strings.TrimPrefix(q.Data, "acc:")

	switch {
	case data == "add":
		h.startAddWizard(ctx, b, chatID, msgID)
		return
	case data == "list", data == "cancel":
		h.fsm.Clear(chatID)
		h.editAccountsMenu(ctx, b, chatID, msgID)
		return
	case strings.HasPrefix(data, "proxy:"):
		h.cbAccountProxyPick(ctx, b, chatID, msgID, strings.TrimPrefix(data, "proxy:"))
		return
	case data == "addhelp": // legacy: text /addaccount help
		h.sendHTML(ctx, b, chatID, generalAddHelpHTML())
		return
	case strings.HasPrefix(data, "toggle:"):
		id, err := strconv.ParseInt(strings.TrimPrefix(data, "toggle:"), 10, 64)
		if err != nil {
			return
		}
		acc, err := h.store.GetAccount(ctx, id)
		if err != nil {
			h.edit(ctx, b, chatID, msgID, "Аккаунт не найден.", nil)
			return
		}
		if err := h.store.SetAccountEnabled(ctx, id, !acc.Enabled); err != nil {
			h.log.Warn("toggle account", "err", err)
		}
	case strings.HasPrefix(data, "del:"):
		id, err := strconv.ParseInt(strings.TrimPrefix(data, "del:"), 10, 64)
		if err != nil {
			return
		}
		if err := h.store.DeleteAccount(ctx, id); err != nil {
			h.log.Warn("delete account", "err", err)
		}
	}
	if err := h.reg.Reload(ctx); err != nil {
		h.log.Warn("reload after account change", "err", err)
	}
	h.editAccountsMenu(ctx, b, chatID, msgID)
}

// editAccountsMenu re-renders the accounts management view in place.
func (h *Handler) editAccountsMenu(ctx context.Context, b *bot.Bot, chatID int64, msgID int) {
	text, kb := h.accountsView(ctx)
	h.edit(ctx, b, chatID, msgID, text, kb)
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
	text := fmt.Sprintf("2/4 — %s.\nВведи маску текстом (185.12.0.0/16 или 95.142.*.*).\n"+
		"Можно сразу несколько — по одной на строку или через запятую, поймаю попадание в любую.\n"+
		"Или выбери пресет:", accountDisplay(acc))
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
	// Single live screen: fold back into the main menu instead of a dead notice.
	h.editHTML(ctx, b, chatID, msgID, h.menuText(), mainMenu())
}

func (h *Handler) cbKeepInPool(ctx context.Context, b *bot.Bot, u *models.Update) {
	q := u.CallbackQuery
	h.ack(ctx, b, q)
	chatID, msgID := cbChatMsg(q)
	st := h.fsm.Get(chatID)
	h.edit(ctx, b, chatID, msgID, fmt.Sprintf("✅ Адрес %s оставлен в пуле.", st.ResultIP), menuBackKeyboard())
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
	case stepAddLabel:
		h.acceptAddLabel(ctx, b, chatID, st.MsgID, text)
	case stepAddField:
		h.acceptAddField(ctx, b, chatID, u.Message.ID, text)
	case stepProxyLine:
		h.acceptProxyLine(ctx, b, chatID, u.Message.ID, text)
	default:
		h.send(ctx, b, chatID, "Открой меню кнопкой ниже или пришли /start.")
	}
}

// --- shared step logic ---

func (h *Handler) acceptMask(ctx context.Context, b *bot.Bot, chatID int64, msgID int, raw string) {
	masks := splitMasks(raw)
	if len(masks) == 0 {
		h.send(ctx, b, chatID, "Не вижу ни одной маски. Введи хотя бы одну.")
		return
	}
	if _, err := engine.ParseMasks(masks); err != nil {
		h.send(ctx, b, chatID, "Некорректная маска: "+err.Error()+"\nПопробуй ещё раз (по одной на строку, или через запятую/пробел).")
		return
	}
	st := h.fsm.Update(chatID, func(s *dialogState) {
		s.Step = stepBudget
		s.Mask = strings.Join(masks, ", ")
	})
	hint := ""
	if acc, ok := h.reg.Get(st.Provider); ok && acc.Caps().MaxRollsPerRun > 0 {
		hint = fmt.Sprintf(" (макс. за запуск: %d)", acc.Caps().MaxRollsPerRun)
	}
	extra := ""
	if len(masks) > 1 {
		extra = fmt.Sprintf(" Ловлю попадание в любую из %d масок.", len(masks))
	}
	h.edit(ctx, b, chatID, msgID, "3/4 — сколько попыток?"+hint+extra, budgetKeyboard())
}

// splitMasks breaks a free-text reply into individual masks. Users paste them
// one per line, comma-, semicolon- or space-separated — all are accepted.
func splitMasks(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == '\r' || r == '\t' || r == ' ' || r == ',' || r == ';'
	})
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
	matcher, err := engine.ParseMasks(splitMasks(mask))
	if err != nil {
		h.edit(ctx, b, chatID, msgID, "Некорректная маска: "+err.Error(), nil)
		h.fsm.Clear(chatID)
		return
	}

	// Auto-clean any leaked, unbound (non-pool) IPs before rolling so quota is
	// not wasted on orphans from an interrupted run.
	if n := h.autoCleanupAccount(ctx, b, acc); n > 0 {
		h.edit(ctx, b, chatID, msgID, fmt.Sprintf("🧹 Подчистил %d повисших IP. Начинаю ролл…", n), nil)
	}

	var lastEdit time.Time
	var rolled []string // every address seen this run, for the forum topic
	onAttempt := func(n int, ip string, matched bool) {
		tag := "❌"
		if matched {
			tag = "✅"
		}
		rolled = append(rolled, fmt.Sprintf("%s %s", tag, ip))

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
		h.edit(ctx, b, chatID, msgID, h.rollErrText(display, err), menuBackKeyboard())
		h.fsm.Clear(chatID)
		// Surface to docker logs and the forum group.
		var q *provider.QuotaError
		switch {
		case errors.As(err, &q):
			h.log.Warn("ролл: квота исчерпана", "account", display, "until", q.AvailableAt)
			h.notifier.QuotaExceeded(ctx, b, display, q.AvailableAt, rolled)
		case errors.Is(err, engine.ErrBudgetExhausted):
			h.log.Info("ролл: без совпадений", "account", display, "mask", mask, "budget", budget)
			h.notifier.NoMatch(ctx, b, display, mask, budget, rolled)
		default:
			h.log.Error("ролл: ошибка", "account", display, "err", err)
			h.notifier.Failed(ctx, b, display, err.Error(), rolled)
		}
		h.postLimits(ctx, b, acc)
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
	h.log.Info("ролл: поймал IP", "account", display, "ip", res.IP.Addr.String(), "attempts", res.Attempts)
	h.edit(ctx, b, chatID, msgID, fmt.Sprintf("✅ Готово!\nАккаунт: %s\nАдрес: %s\nСовпал за %d попыт.\nID ресурса: %s",
		display, res.IP.Addr.String(), res.Attempts, res.IP.ID), resultKeyboard(id))
	h.notifier.Caught(ctx, b, display, res.IP.Addr.String(), mask, res.Attempts, rolled)
	h.postLimits(ctx, b, acc)
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
	h.notifier.Attached(ctx, b, h.displayKey(pool.Provider), pool.IP, vmID)
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
	cooldown := ""
	if until, ok := h.engine.Cooldown(acc.Key()); ok {
		cooldown = fmt.Sprintf("\n⛔ Квота исчерпана — ролл будет доступен с %s", until.Local().Format("02.01.2006 15:04 MST"))
	}
	return fmt.Sprintf(
		"4/4 — подтверждение:\nАккаунт: %s\nМаска: %s\nПопыток: %d\nЦена за ролл: %s\n%s%s\n\nЗапускаем?",
		accountDisplay(acc), st.Mask, st.Budget, cost, daily, cooldown,
	)
}

func (h *Handler) rollErrText(display string, err error) string {
	var quota *provider.QuotaError
	switch {
	case errors.As(err, &quota):
		when := "через ~24 часа"
		if !quota.AvailableAt.IsZero() {
			when = quota.AvailableAt.Local().Format("02.01.2006 15:04 MST")
		}
		lim := ""
		if quota.Limit > 0 {
			lim = fmt.Sprintf(" (лимит %d/сутки)", quota.Limit)
		}
		return fmt.Sprintf("⛔ %s: дневная квота исчерпана%s.\nСледующий ролл возможен: %s", display, lim, when)
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
