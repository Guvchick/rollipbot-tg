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

func TestCapsOfNilBlock(t *testing.T) {
	caps := CapsOf(nil)
	if caps.RateLimitRPS <= 0 {
		t.Errorf("nil block must get a default rate limit, got %v", caps.RateLimitRPS)
	}
}
