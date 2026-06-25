// Package storage persists the reserved-IP pool, roll history and daily counters.
package storage

import (
	"context"
	"time"
)

// PoolIP is a reserved, matched address that has not been released.
type PoolIP struct {
	ID          int64
	Provider    string
	ResourceID  string // provider-side resource id (for attach/release)
	IP          string
	MatchedMask string
	AttachedVM  string // empty until bound to a VM
	CreatedAt   time.Time
}

// RollLogEntry is one audit record of an allocate attempt.
type RollLogEntry struct {
	Provider string
	IP       string
	Matched  bool
	Released bool
}

// Account is one set of provider credentials. There can be several accounts per
// provider type (e.g. two Timeweb accounts). Credentials are per-provider
// connection fields (token, secrets, ids) stored as a JSON blob.
type Account struct {
	ID          int64
	Provider    string // provider type: timeweb, vkcloud, ...
	Label       string // human label, unique within a provider type
	Enabled     bool
	Credentials map[string]string
	CreatedAt   time.Time
}

// AllowedUser is a Telegram user permitted to use the bot.
type AllowedUser struct {
	UserID  int64
	Note    string
	AddedAt time.Time
}

// Storage is the persistence contract.
type Storage interface {
	AddPoolIP(ctx context.Context, ip PoolIP) (int64, error)
	ListPoolIPs(ctx context.Context) ([]PoolIP, error)
	GetPoolIPByIP(ctx context.Context, ip string) (PoolIP, error)
	MarkAttached(ctx context.Context, id int64, vmID string) error
	RemovePoolIP(ctx context.Context, id int64) error

	LogRoll(ctx context.Context, e RollLogEntry) error

	DailyCount(ctx context.Context, provider, day string) (int, error)
	IncDaily(ctx context.Context, provider, day string) error

	// Provider accounts (credentials)
	ListAccounts(ctx context.Context) ([]Account, error)
	ListEnabledAccounts(ctx context.Context) ([]Account, error)
	GetAccount(ctx context.Context, id int64) (Account, error)
	UpsertAccount(ctx context.Context, a Account) (int64, error)
	SetAccountEnabled(ctx context.Context, id int64, enabled bool) error
	DeleteAccount(ctx context.Context, id int64) error
	CountAccounts(ctx context.Context) (int, error)

	// User whitelist
	ListAllowedUsers(ctx context.Context) ([]AllowedUser, error)
	AddAllowedUser(ctx context.Context, u AllowedUser) error
	RemoveAllowedUser(ctx context.Context, userID int64) error

	// Forum topic id cache (name → message_thread_id) for notifications
	GetForumTopic(ctx context.Context, name string) (threadID int, ok bool, err error)
	SetForumTopic(ctx context.Context, name string, threadID int) error

	Close() error
}
