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

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

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

// Caught logs a successful match.
func (n *Notifier) Caught(ctx context.Context, b *bot.Bot, account, ip, mask string, attempts int) {
	n.post(ctx, b, account, fmt.Sprintf(
		"🎯 <b>Поймал IP</b>\nАккаунт: %s\nIP: <code>%s</code>\nМаска: %s\nПопыток: %d",
		esc(account), esc(ip), esc(mask), attempts))
}

// NoMatch logs a run that exhausted its budget without a match.
func (n *Notifier) NoMatch(ctx context.Context, b *bot.Bot, account, mask string, attempts int) {
	n.post(ctx, b, account, fmt.Sprintf(
		"🟡 <b>Без совпадений</b>\nАккаунт: %s\nМаска: %s\nПопыток: %d",
		esc(account), esc(mask), attempts))
}

// Attached logs binding an address to a VM.
func (n *Notifier) Attached(ctx context.Context, b *bot.Bot, account, ip, vm string) {
	n.post(ctx, b, account, fmt.Sprintf(
		"🔗 <b>Привязан IP</b>\nАккаунт: %s\nIP: <code>%s</code>\nВМ: %s",
		esc(account), esc(ip), esc(vm)))
}

// Failed logs a run error.
func (n *Notifier) Failed(ctx context.Context, b *bot.Bot, account, reason string) {
	n.post(ctx, b, account, fmt.Sprintf(
		"⚠️ <b>Ошибка прогона</b>\nАккаунт: %s\n%s", esc(account), esc(reason)))
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
