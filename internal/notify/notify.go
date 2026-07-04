// Package notify pushes roll/catch logs to a separate Telegram forum supergroup,
// auto-creating one topic per provider account so events are sorted by account.
// If the target chat is not a forum (or topic creation is not permitted),
// messages still go to the group root — they just aren't threaded.
package notify

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

// maxRolledLines caps how many rolled addresses we list in one message so we
// stay under Telegram's 4096-char limit even on long runs.
const maxRolledLines = 40

// TopicStore persists name → message_thread_id so topics survive restarts.
type TopicStore interface {
	GetForumTopic(ctx context.Context, name string) (threadID int, ok bool, err error)
	SetForumTopic(ctx context.Context, name string, threadID int) error
}

// Notifier posts notifications to a forum supergroup.
type Notifier struct {
	chatID  int64
	enabled bool
	store   TopicStore
	log     *slog.Logger

	mu    sync.Mutex
	cache map[string]int // topic name → thread id (0 = group root)
}

func New(chatID int64, enabled bool, store TopicStore, log *slog.Logger) *Notifier {
	return &Notifier{
		chatID:  chatID,
		enabled: enabled && chatID != 0,
		store:   store,
		log:     log,
		cache:   make(map[string]int),
	}
}

// Enabled reports whether notifications are configured.
func (n *Notifier) Enabled() bool { return n != nil && n.enabled }

// Caught logs a successful match, listing every address rolled on the way.
func (n *Notifier) Caught(ctx context.Context, b *bot.Bot, account, ip, mask string, attempts int, rolled []string) {
	n.post(ctx, b, account, fmt.Sprintf(
		"🎯 <b>Поймал IP</b>\nАккаунт: %s\nIP: <code>%s</code>\nМаска: %s\nПопыток: %d%s",
		esc(account), esc(ip), esc(mask), attempts, rolledBlock(rolled)))
}

// NoMatch logs a run that exhausted its budget without a match.
func (n *Notifier) NoMatch(ctx context.Context, b *bot.Bot, account, mask string, attempts int, rolled []string) {
	n.post(ctx, b, account, fmt.Sprintf(
		"🟡 <b>Без совпадений</b>\nАккаунт: %s\nМаска: %s\nПопыток: %d%s",
		esc(account), esc(mask), attempts, rolledBlock(rolled)))
}

// Attached logs binding an address to a VM.
func (n *Notifier) Attached(ctx context.Context, b *bot.Bot, account, ip, vm string) {
	n.post(ctx, b, account, fmt.Sprintf(
		"🔗 <b>Привязан IP</b>\nАккаунт: %s\nIP: <code>%s</code>\nВМ: %s",
		esc(account), esc(ip), esc(vm)))
}

// Failed logs a run error.
func (n *Notifier) Failed(ctx context.Context, b *bot.Bot, account, reason string, rolled []string) {
	n.post(ctx, b, account, fmt.Sprintf(
		"⚠️ <b>Ошибка прогона</b>\nАккаунт: %s\n%s%s", esc(account), esc(reason), rolledBlock(rolled)))
}

// QuotaExceeded logs that the account hit its daily creation quota and when it
// may roll again.
func (n *Notifier) QuotaExceeded(ctx context.Context, b *bot.Bot, account string, availableAt time.Time, rolled []string) {
	when := "через ~24 часа"
	if !availableAt.IsZero() {
		when = availableAt.Local().Format("02.01.2006 15:04 MST")
	}
	n.post(ctx, b, account, fmt.Sprintf(
		"⛔ <b>Квота исчерпана</b>\nАккаунт: %s\nСледующий ролл возможен: %s%s",
		esc(account), esc(when), rolledBlock(rolled)))
}

// rolledBlock renders the rolled addresses as an expandable blockquote, capping
// the list so the message stays within Telegram limits.
func rolledBlock(rolled []string) string {
	if len(rolled) == 0 {
		return ""
	}
	shown := rolled
	extra := 0
	if len(shown) > maxRolledLines {
		extra = len(shown) - maxRolledLines
		shown = shown[len(shown)-maxRolledLines:]
	}
	var sb strings.Builder
	sb.WriteString("\n<blockquote expandable>Роллы:\n")
	if extra > 0 {
		fmt.Fprintf(&sb, "…(ещё %d выше)\n", extra)
	}
	for _, r := range shown {
		sb.WriteString(esc(r) + "\n")
	}
	sb.WriteString("</blockquote>")
	return sb.String()
}

// UpdateLimits maintains ONE auto-edited limits/quota message in the account's
// topic, so limits stay visible and current without spamming. The message id is
// stored (keyed by "limits:"+account) and edited in place; if the edit fails
// (message deleted) it is re-sent.
func (n *Notifier) UpdateLimits(ctx context.Context, b *bot.Bot, account, text string) {
	if !n.Enabled() {
		return
	}
	threadID := n.ensureTopic(ctx, b, account)
	key := "limits:" + account
	if msgID, ok, err := n.store.GetForumTopic(ctx, key); err == nil && ok {
		if _, eerr := b.EditMessageText(ctx, &bot.EditMessageTextParams{
			ChatID: n.chatID, MessageID: msgID, Text: text, ParseMode: models.ParseModeHTML,
		}); eerr == nil {
			return
		}
		// edit failed (likely deleted) — fall through and re-send
	}
	params := &bot.SendMessageParams{ChatID: n.chatID, Text: text, ParseMode: models.ParseModeHTML}
	if threadID != 0 {
		params.MessageThreadID = threadID
	}
	m, err := b.SendMessage(ctx, params)
	if err != nil {
		n.log.Warn("limits message send failed", "topic", account, "err", err)
		return
	}
	if err := n.store.SetForumTopic(ctx, key, m.ID); err != nil {
		n.log.Warn("limits message id save failed", "err", err)
	}
}

func (n *Notifier) post(ctx context.Context, b *bot.Bot, topic, text string) {
	if !n.Enabled() {
		return
	}
	threadID := n.ensureTopic(ctx, b, topic)
	params := &bot.SendMessageParams{ChatID: n.chatID, Text: text, ParseMode: models.ParseModeHTML}
	if threadID != 0 {
		params.MessageThreadID = threadID
	}
	if _, err := b.SendMessage(ctx, params); err != nil {
		n.log.Warn("notify send failed", "topic", topic, "err", err)
	}
}

// ensureTopic resolves (or creates) the thread id for a topic name. On any
// failure it caches 0 so it falls back to the group root without retrying.
func (n *Notifier) ensureTopic(ctx context.Context, b *bot.Bot, name string) int {
	n.mu.Lock()
	defer n.mu.Unlock()

	if id, ok := n.cache[name]; ok {
		return id
	}
	if id, ok, err := n.store.GetForumTopic(ctx, name); err == nil && ok {
		n.cache[name] = id
		return id
	}
	ft, err := b.CreateForumTopic(ctx, &bot.CreateForumTopicParams{ChatID: n.chatID, Name: topicName(name)})
	if err != nil {
		n.log.Warn("создание топика не удалось — пишу в корень группы", "name", name, "err", err)
		n.cache[name] = 0
		return 0
	}
	id := ft.MessageThreadID
	if err := n.store.SetForumTopic(ctx, name, id); err != nil {
		n.log.Warn("не сохранил id топика", "name", name, "err", err)
	}
	n.cache[name] = id
	return id
}

// topicName clamps to Telegram's 128-char forum topic name limit.
func topicName(s string) string {
	if len(s) > 128 {
		return s[:128]
	}
	return s
}

func esc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
