package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadExpandsEnv(t *testing.T) {
	t.Setenv("TELEGRAM_TOKEN", "secret-token")
	t.Setenv("TIMEWEB_TOKEN", "tw-123")
	p := writeCfg(t, `
telegram:
  token: ${TELEGRAM_TOKEN}
  admin_user_ids: [42]
providers:
  timeweb:
    enabled: true
    token: ${TIMEWEB_TOKEN}
    daily_cap: 10
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Telegram.Token != "secret-token" {
		t.Errorf("token = %q, want expanded", cfg.Telegram.Token)
	}
	if len(cfg.Telegram.AdminUserIDs) != 1 || cfg.Telegram.AdminUserIDs[0] != 42 {
		t.Errorf("admins = %v", cfg.Telegram.AdminUserIDs)
	}
	if cfg.Providers.Timeweb == nil || cfg.Providers.Timeweb.Token != "tw-123" {
		t.Errorf("timeweb token not expanded: %+v", cfg.Providers.Timeweb)
	}
	if cfg.Storage.DSN != "./ip-roller.db" {
		t.Errorf("default dsn = %q", cfg.Storage.DSN)
	}
}

func TestStorageDSNEnvOverride(t *testing.T) {
	t.Setenv("TELEGRAM_TOKEN", "x")
	t.Setenv("STORAGE_DSN", "/data/roller.db")
	p := writeCfg(t, "telegram:\n  token: ${TELEGRAM_TOKEN}\nstorage:\n  dsn: ./local.db\n")
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Storage.DSN != "/data/roller.db" {
		t.Errorf("dsn = %q, want env override", cfg.Storage.DSN)
	}
}

func TestLoadMissingTokenFails(t *testing.T) {
	t.Setenv("TELEGRAM_TOKEN", "")
	p := writeCfg(t, "telegram:\n  token: ${TELEGRAM_TOKEN}\n")
	if _, err := Load(p); err == nil {
		t.Error("expected error for empty telegram token")
	}
}

func TestAdminAllowedFromEnv(t *testing.T) {
	t.Setenv("TELEGRAM_TOKEN", "x")
	t.Setenv("TELEGRAM_ADMIN_IDS", "123, 456 789")
	t.Setenv("TELEGRAM_ALLOWED_IDS", "42;43")
	p := writeCfg(t, "telegram:\n  token: ${TELEGRAM_TOKEN}\n  admin_user_ids: [1]\n")
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	admins := map[int64]bool{}
	for _, id := range cfg.Telegram.AdminUserIDs {
		admins[id] = true
	}
	for _, want := range []int64{1, 123, 456, 789} { // config + env merged
		if !admins[want] {
			t.Errorf("admin %d missing; got %v", want, cfg.Telegram.AdminUserIDs)
		}
	}
	allowed := map[int64]bool{}
	for _, id := range cfg.Telegram.AllowedUserIDs {
		allowed[id] = true
	}
	if !allowed[42] || !allowed[43] {
		t.Errorf("allowed env not parsed: %v", cfg.Telegram.AllowedUserIDs)
	}
}

func TestParseIDListIgnoresGarbage(t *testing.T) {
	got := parseIDList("1, ,abc,2  3;x;4")
	want := []int64{1, 2, 3, 4}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestCapsOfNilBlock(t *testing.T) {
	caps := CapsOf(nil)
	if caps.RateLimitRPS <= 0 {
		t.Errorf("nil block must get a default rate limit, got %v", caps.RateLimitRPS)
	}
}
