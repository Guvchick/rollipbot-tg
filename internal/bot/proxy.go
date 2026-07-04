package bot

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"ip-roller-bot/internal/storage"
)

// Proxy management: the bot can route each account's provider API calls through
// an outbound SOCKS5 or HTTP proxy. Proxies are stored and bound per account; a
// binding takes effect on the next registry reload (done here after each change).

// editProxiesMenu renders the proxies control panel in place.
func (h *Handler) editProxiesMenu(ctx context.Context, b *bot.Bot, chatID int64, msgID int) {
	proxies, err := h.store.ListProxies(ctx)
	if err != nil {
		h.editHTML(ctx, b, chatID, msgID, "⚠️ Ошибка чтения прокси: "+htmlEsc(err.Error()), menuBackKeyboard())
		return
	}
	var sb strings.Builder
	sb.WriteString("🌐 <b>Прокси</b>\n")
	if len(proxies) == 0 {
		sb.WriteString("Пока пусто. Через прокси идут запросы к API провайдера при ролле.\nЖми «➕ Добавить прокси».")
	} else {
		sb.WriteString("Список прокси (привязываются к аккаунтам в 🔐 Аккаунты → 🌐):\n<blockquote expandable>")
		for _, p := range proxies {
			fmt.Fprintf(&sb, "#%d %s · %s — %s\n", p.ID, htmlEsc(p.Scheme), htmlEsc(p.Label), htmlEsc(p.URL()))
		}
		sb.WriteString("</blockquote>")
	}
	h.editHTML(ctx, b, chatID, msgID, sb.String(), proxiesMenu(proxies))
}

// cbProxy handles the px:* callbacks (list/add/delete).
func (h *Handler) cbProxy(ctx context.Context, b *bot.Bot, u *models.Update) {
	q := u.CallbackQuery
	if !h.requireAdminCB(ctx, b, q) {
		return
	}
	h.ack(ctx, b, q)
	chatID, msgID := cbChatMsg(q)
	data := strings.TrimPrefix(q.Data, "px:")
	switch {
	case data == "list":
		h.fsm.Clear(chatID)
		h.editProxiesMenu(ctx, b, chatID, msgID)
	case data == "add":
		h.fsm.Update(chatID, func(s *dialogState) { *s = dialogState{MsgID: msgID} })
		text := "🌐 <b>Новый прокси</b>\nВыбери тип — через него бот будет ходить в API провайдера."
		h.editHTML(ctx, b, chatID, msgID, text, proxySchemeKeyboard())
	case strings.HasPrefix(data, "del:"):
		id, err := strconv.ParseInt(strings.TrimPrefix(data, "del:"), 10, 64)
		if err == nil {
			if err := h.store.DeleteProxy(ctx, id); err != nil {
				h.log.Warn("delete proxy", "err", err)
			}
			if err := h.reg.Reload(ctx); err != nil {
				h.log.Warn("reload after proxy delete", "err", err)
			}
		}
		h.editProxiesMenu(ctx, b, chatID, msgID)
	}
}

// cbProxyScheme sets the chosen scheme and asks for the connection line.
func (h *Handler) cbProxyScheme(ctx context.Context, b *bot.Bot, u *models.Update) {
	q := u.CallbackQuery
	if !h.requireAdminCB(ctx, b, q) {
		return
	}
	h.ack(ctx, b, q)
	chatID, msgID := cbChatMsg(q)
	scheme := strings.TrimPrefix(q.Data, "pxscheme:")
	if scheme != "socks5" && scheme != "http" {
		return
	}
	h.fsm.Update(chatID, func(s *dialogState) {
		s.Step = stepProxyLine
		s.MsgID = msgID
		s.ProxyScheme = scheme
	})
	var sb strings.Builder
	fmt.Fprintf(&sb, "🌐 <b>%s-прокси</b>\n", strings.ToUpper(scheme))
	sb.WriteString("👉 Пришли строку подключения одним сообщением, любой из форматов:\n")
	sb.WriteString("<blockquote>host:port\nhost:port:login:pass\n")
	fmt.Fprintf(&sb, "%s://login:pass@host:port</blockquote>", scheme)
	h.editHTML(ctx, b, chatID, msgID, sb.String(), proxyLineKeyboard())
}

// acceptProxyLine parses and saves the proxy, then returns to the proxies view.
func (h *Handler) acceptProxyLine(ctx context.Context, b *bot.Bot, chatID int64, userMsgID int, line string) {
	st := h.fsm.Get(chatID)
	msgID := st.MsgID
	p, err := parseProxyLine(st.ProxyScheme, line)
	if err != nil {
		h.send(ctx, b, chatID, "Не разобрал прокси: "+err.Error()+"\nПришли ещё раз (host:port или host:port:login:pass).")
		return
	}
	// hygiene: drop the message — it may hold proxy credentials
	if userMsgID != 0 {
		if _, derr := b.DeleteMessage(ctx, &bot.DeleteMessageParams{ChatID: chatID, MessageID: userMsgID}); derr != nil {
			h.log.Debug("delete proxy message", "err", derr)
		}
	}
	if _, err := h.store.AddProxy(ctx, p); err != nil {
		h.send(ctx, b, chatID, "Не удалось сохранить прокси: "+err.Error())
		return
	}
	h.fsm.Clear(chatID)
	h.editProxiesMenu(ctx, b, chatID, msgID)
}

// cbAccountProxyPick shows the proxy picker for one account (acc:proxy:<id>).
func (h *Handler) cbAccountProxyPick(ctx context.Context, b *bot.Bot, chatID int64, msgID int, arg string) {
	accountID, err := strconv.ParseInt(arg, 10, 64)
	if err != nil {
		return
	}
	proxies, err := h.store.ListProxies(ctx)
	if err != nil {
		h.editHTML(ctx, b, chatID, msgID, "⚠️ Ошибка: "+htmlEsc(err.Error()), menuBackKeyboard())
		return
	}
	if len(proxies) == 0 {
		h.editHTML(ctx, b, chatID, msgID, "Сначала добавь прокси: 🌐 Прокси → ➕.", menuBackKeyboard())
		return
	}
	var current int64
	if px, ok, _ := h.store.AccountProxy(ctx, accountID); ok {
		current = px.ID
	}
	acc, _ := h.store.GetAccount(ctx, accountID)
	text := fmt.Sprintf("🌐 Прокси для аккаунта <b>%s · %s</b>\nВыбери прокси или отключи.",
		htmlEsc(typeName(acc.Provider)), htmlEsc(acc.Label))
	h.editHTML(ctx, b, chatID, msgID, text, accountProxyPicker(accountID, proxies, current))
}

// cbAccountProxyBind binds/unbinds a proxy to an account (accpx:<acc>:<proxy>).
func (h *Handler) cbAccountProxyBind(ctx context.Context, b *bot.Bot, u *models.Update) {
	q := u.CallbackQuery
	if !h.requireAdminCB(ctx, b, q) {
		return
	}
	h.ack(ctx, b, q)
	chatID, msgID := cbChatMsg(q)
	parts := strings.Split(strings.TrimPrefix(q.Data, "accpx:"), ":")
	if len(parts) != 2 {
		return
	}
	accountID, _ := strconv.ParseInt(parts[0], 10, 64)
	proxyID, _ := strconv.ParseInt(parts[1], 10, 64)
	if proxyID == 0 {
		if err := h.store.UnbindProxy(ctx, accountID); err != nil {
			h.log.Warn("unbind proxy", "err", err)
		}
	} else {
		if err := h.store.BindProxy(ctx, accountID, proxyID); err != nil {
			h.log.Warn("bind proxy", "err", err)
		}
	}
	if err := h.reg.Reload(ctx); err != nil {
		h.log.Warn("reload after proxy bind", "err", err)
	}
	h.editAccountsMenu(ctx, b, chatID, msgID)
}

// parseProxyLine accepts host:port, host:port:login:pass, or a full URL.
func parseProxyLine(scheme, line string) (storage.Proxy, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return storage.Proxy{}, fmt.Errorf("пустая строка")
	}
	// Full URL form: scheme://[user:pass@]host:port
	if strings.Contains(line, "://") {
		u, err := url.Parse(line)
		if err != nil {
			return storage.Proxy{}, err
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil {
			return storage.Proxy{}, fmt.Errorf("нет порта")
		}
		p := storage.Proxy{Scheme: u.Scheme, Host: u.Hostname(), Port: port}
		if u.User != nil {
			p.Username = u.User.Username()
			p.Password, _ = u.User.Password()
		}
		p.Label = p.Host
		return p, nil
	}
	// host:port[:login:pass]
	parts := strings.Split(line, ":")
	if len(parts) != 2 && len(parts) != 4 {
		return storage.Proxy{}, fmt.Errorf("ожидаю host:port или host:port:login:pass")
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil || port <= 0 || port > 65535 {
		return storage.Proxy{}, fmt.Errorf("плохой порт: %q", parts[1])
	}
	p := storage.Proxy{Scheme: scheme, Host: parts[0], Port: port, Label: parts[0]}
	if len(parts) == 4 {
		p.Username, p.Password = parts[2], parts[3]
	}
	return p, nil
}
