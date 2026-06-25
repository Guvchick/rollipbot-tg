package bot

import (
	"context"
	"log/slog"
	"sync"

	"ip-roller-bot/internal/storage"
)

// ACL decides who may use the bot and who may administer it. Admins and the
// static allow-list come from config (bootstrap); additional allowed users live
// in the database and can be managed at runtime by admins.
type ACL struct {
	store storage.Storage
	log   *slog.Logger

	mu      sync.RWMutex
	admins  map[int64]bool
	static  map[int64]bool
	dynamic map[int64]bool
}

func NewACL(store storage.Storage, log *slog.Logger, admins, static []int64) *ACL {
	a := &ACL{
		store:   store,
		log:     log,
		admins:  toSet(admins),
		static:  toSet(static),
		dynamic: map[int64]bool{},
	}
	return a
}

// Reload loads the dynamic whitelist from storage.
func (a *ACL) Reload(ctx context.Context) error {
	users, err := a.store.ListAllowedUsers(ctx)
	if err != nil {
		return err
	}
	dyn := make(map[int64]bool, len(users))
	for _, u := range users {
		dyn[u.UserID] = true
	}
	a.mu.Lock()
	a.dynamic = dyn
	a.mu.Unlock()
	return nil
}

// IsAdmin reports whether uid is a configured admin.
func (a *ACL) IsAdmin(uid int64) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.admins[uid]
}

// IsAllowed reports whether uid may use the bot. If no admins, static or dynamic
// users are configured at all, access is open (with a startup warning).
func (a *ACL) IsAllowed(uid int64) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.admins[uid] || a.static[uid] || a.dynamic[uid] {
		return true
	}
	return len(a.admins) == 0 && len(a.static) == 0 && len(a.dynamic) == 0
}

// Configured reports whether any access rule exists (used for the open-access warning).
func (a *ACL) Configured() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.admins) > 0 || len(a.static) > 0 || len(a.dynamic) > 0
}

// Add adds a user to the dynamic whitelist.
func (a *ACL) Add(ctx context.Context, uid int64, note string) error {
	if err := a.store.AddAllowedUser(ctx, storage.AllowedUser{UserID: uid, Note: note}); err != nil {
		return err
	}
	a.mu.Lock()
	a.dynamic[uid] = true
	a.mu.Unlock()
	return nil
}

// Remove deletes a user from the dynamic whitelist (config-static/admins persist).
func (a *ACL) Remove(ctx context.Context, uid int64) error {
	if err := a.store.RemoveAllowedUser(ctx, uid); err != nil {
		return err
	}
	a.mu.Lock()
	delete(a.dynamic, uid)
	a.mu.Unlock()
	return nil
}

// Admins returns the configured admin ids.
func (a *ACL) Admins() []int64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return setKeys(a.admins)
}

// StaticAllowed returns the config static allow-list ids.
func (a *ACL) StaticAllowed() []int64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return setKeys(a.static)
}

func toSet(ids []int64) map[int64]bool {
	m := make(map[int64]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

func setKeys(m map[int64]bool) []int64 {
	out := make([]int64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
