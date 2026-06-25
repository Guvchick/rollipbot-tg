package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no CGO
)

// ErrNotFound is returned when a lookup matches no row.
var ErrNotFound = errors.New("не найдено")

const schema = `
CREATE TABLE IF NOT EXISTS pool_ips (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    provider     TEXT NOT NULL,
    resource_id  TEXT NOT NULL,
    ip           TEXT NOT NULL,
    matched_mask TEXT,
    attached_vm  TEXT,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS roll_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    provider   TEXT NOT NULL,
    ip         TEXT NOT NULL,
    matched    BOOLEAN NOT NULL,
    released   BOOLEAN NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS daily_counters (
    provider TEXT NOT NULL,
    day      DATE NOT NULL,
    count    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (provider, day)
);
CREATE TABLE IF NOT EXISTS accounts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    provider    TEXT NOT NULL,
    label       TEXT NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT 1,
    credentials TEXT NOT NULL DEFAULT '{}',
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (provider, label)
);
CREATE TABLE IF NOT EXISTS allowed_users (
    user_id  INTEGER PRIMARY KEY,
    note     TEXT,
    added_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

// SQLite is a modernc.org/sqlite-backed Storage.
type SQLite struct {
	db *sql.DB
}

// NewSQLite opens (and migrates) the database at dsn (a file path).
func NewSQLite(ctx context.Context, dsn string) (*SQLite, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite: serialize writers to avoid "database is locked"
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &SQLite{db: db}, nil
}

func (s *SQLite) Close() error { return s.db.Close() }

func (s *SQLite) AddPoolIP(ctx context.Context, ip PoolIP) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO pool_ips (provider, resource_id, ip, matched_mask, attached_vm)
		 VALUES (?, ?, ?, ?, ?)`,
		ip.Provider, ip.ResourceID, ip.IP, ip.MatchedMask, nullStr(ip.AttachedVM))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *SQLite) ListPoolIPs(ctx context.Context) ([]PoolIP, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, provider, resource_id, ip, COALESCE(matched_mask,''),
		        COALESCE(attached_vm,''), created_at
		 FROM pool_ips ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PoolIP
	for rows.Next() {
		var p PoolIP
		if err := rows.Scan(&p.ID, &p.Provider, &p.ResourceID, &p.IP,
			&p.MatchedMask, &p.AttachedVM, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLite) GetPoolIPByIP(ctx context.Context, ip string) (PoolIP, error) {
	var p PoolIP
	err := s.db.QueryRowContext(ctx,
		`SELECT id, provider, resource_id, ip, COALESCE(matched_mask,''),
		        COALESCE(attached_vm,''), created_at
		 FROM pool_ips WHERE ip = ? ORDER BY created_at DESC LIMIT 1`, ip).
		Scan(&p.ID, &p.Provider, &p.ResourceID, &p.IP, &p.MatchedMask, &p.AttachedVM, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return PoolIP{}, ErrNotFound
	}
	return p, err
}

func (s *SQLite) MarkAttached(ctx context.Context, id int64, vmID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE pool_ips SET attached_vm = ? WHERE id = ?`, vmID, id)
	return err
}

func (s *SQLite) RemovePoolIP(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM pool_ips WHERE id = ?`, id)
	return err
}

func (s *SQLite) LogRoll(ctx context.Context, e RollLogEntry) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO roll_log (provider, ip, matched, released) VALUES (?, ?, ?, ?)`,
		e.Provider, e.IP, e.Matched, e.Released)
	return err
}

func (s *SQLite) DailyCount(ctx context.Context, provider, day string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT count FROM daily_counters WHERE provider = ? AND day = ?`,
		provider, day).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n, err
}

func (s *SQLite) IncDaily(ctx context.Context, provider, day string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO daily_counters (provider, day, count) VALUES (?, ?, 1)
		 ON CONFLICT(provider, day) DO UPDATE SET count = count + 1`,
		provider, day)
	return err
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// --- accounts ---

func scanAccount(scan func(dest ...any) error) (Account, error) {
	var a Account
	var blob string
	if err := scan(&a.ID, &a.Provider, &a.Label, &a.Enabled, &blob, &a.CreatedAt); err != nil {
		return Account{}, err
	}
	a.Credentials = map[string]string{}
	if blob != "" {
		if err := json.Unmarshal([]byte(blob), &a.Credentials); err != nil {
			return Account{}, fmt.Errorf("decode credentials for account %d: %w", a.ID, err)
		}
	}
	return a, nil
}

const accountCols = `id, provider, label, enabled, credentials, created_at`

func (s *SQLite) listAccounts(ctx context.Context, where string) ([]Account, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+accountCols+` FROM accounts `+where+` ORDER BY provider, label`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *SQLite) ListAccounts(ctx context.Context) ([]Account, error) {
	return s.listAccounts(ctx, "")
}

func (s *SQLite) ListEnabledAccounts(ctx context.Context) ([]Account, error) {
	return s.listAccounts(ctx, "WHERE enabled = 1")
}

func (s *SQLite) GetAccount(ctx context.Context, id int64) (Account, error) {
	a, err := scanAccount(s.db.QueryRowContext(ctx,
		`SELECT `+accountCols+` FROM accounts WHERE id = ?`, id).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, ErrNotFound
	}
	return a, err
}

func (s *SQLite) UpsertAccount(ctx context.Context, a Account) (int64, error) {
	blob, err := json.Marshal(a.Credentials)
	if err != nil {
		return 0, err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO accounts (provider, label, enabled, credentials) VALUES (?, ?, ?, ?)
		 ON CONFLICT(provider, label) DO UPDATE SET enabled = excluded.enabled, credentials = excluded.credentials`,
		a.Provider, a.Label, a.Enabled, string(blob))
	if err != nil {
		return 0, err
	}
	var id int64
	err = s.db.QueryRowContext(ctx,
		`SELECT id FROM accounts WHERE provider = ? AND label = ?`, a.Provider, a.Label).Scan(&id)
	return id, err
}

func (s *SQLite) SetAccountEnabled(ctx context.Context, id int64, enabled bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE accounts SET enabled = ? WHERE id = ?`, enabled, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) DeleteAccount(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM accounts WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) CountAccounts(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM accounts`).Scan(&n)
	return n, err
}

// --- allowed users ---

func (s *SQLite) ListAllowedUsers(ctx context.Context) ([]AllowedUser, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT user_id, COALESCE(note,''), added_at FROM allowed_users ORDER BY added_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AllowedUser
	for rows.Next() {
		var u AllowedUser
		if err := rows.Scan(&u.UserID, &u.Note, &u.AddedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *SQLite) AddAllowedUser(ctx context.Context, u AllowedUser) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO allowed_users (user_id, note) VALUES (?, ?)
		 ON CONFLICT(user_id) DO UPDATE SET note = excluded.note`,
		u.UserID, nullStr(u.Note))
	return err
}

func (s *SQLite) RemoveAllowedUser(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM allowed_users WHERE user_id = ?`, userID)
	return err
}

// compile-time check
var _ Storage = (*SQLite)(nil)
