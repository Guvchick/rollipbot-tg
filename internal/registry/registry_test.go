package registry

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strconv"
	"testing"

	"ip-roller-bot/internal/config"
	"ip-roller-bot/internal/storage"
)

func testStore(t *testing.T) storage.Storage {
	t.Helper()
	st, err := storage.NewSQLite(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func timewebCfg() *config.Config {
	return &config.Config{
		Providers: config.ProvidersConfig{
			Timeweb: &config.ProviderConfig{
				Enabled: true, Token: "seed-token", AvailabilityZone: "spb-1",
				RateLimitRPS: 15, MaxRollsPerRun: 10, DailyCap: 10, Strategy: "floating",
			},
		},
	}
}

func TestSeedAndMultipleAccounts(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	cfg := timewebCfg()

	// First run: seed one account from config/env.
	if err := SeedFromConfig(ctx, store, cfg, quietLog()); err != nil {
		t.Fatal(err)
	}
	reg := New(cfg, store, quietLog())
	if err := reg.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 1 {
		t.Fatalf("after seed want 1 account, got %d", reg.Len())
	}
	acc := reg.Accounts()[0]
	if acc.Type() != "timeweb" || acc.Key() != "timeweb#1" {
		t.Fatalf("unexpected account: type=%s key=%s", acc.Type(), acc.Key())
	}
	if acc.Caps().DailyCap != 10 {
		t.Errorf("caps not taken from config: %+v", acc.Caps())
	}

	// Seeding again must be a no-op (table not empty).
	if err := SeedFromConfig(ctx, store, cfg, quietLog()); err != nil {
		t.Fatal(err)
	}

	// Add a SECOND timeweb account — multiple accounts per type.
	id2, err := store.UpsertAccount(ctx, storage.Account{
		Provider: "timeweb", Label: "prod", Enabled: true,
		Credentials: map[string]string{"token": "second-token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 2 {
		t.Fatalf("want 2 accounts, got %d", reg.Len())
	}
	keys := map[string]bool{}
	for _, a := range reg.Accounts() {
		keys[a.Key()] = true
	}
	if !keys["timeweb#1"] || !keys["timeweb#"+strconv.FormatInt(id2, 10)] {
		t.Fatalf("distinct keys missing: %v", keys)
	}

	// Disable the second account → drops out of the live registry.
	if err := store.SetAccountEnabled(ctx, id2, false); err != nil {
		t.Fatal(err)
	}
	if err := reg.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 1 {
		t.Fatalf("after disable want 1, got %d", reg.Len())
	}
}

func TestValidateCreds(t *testing.T) {
	if err := ValidateCreds("timeweb", map[string]string{"availability_zone": "x"}); err == nil {
		t.Error("expected error for missing required token")
	}
	if err := ValidateCreds("timeweb", map[string]string{"token": "x", "bogus": "y"}); err == nil {
		t.Error("expected error for unknown field")
	}
	if err := ValidateCreds("gcore", map[string]string{"api_token": "x", "project_id": "p", "region_id": "abc"}); err == nil {
		t.Error("expected error for non-numeric region_id")
	}
	if err := ValidateCreds("timeweb", map[string]string{"token": "x"}); err != nil {
		t.Errorf("valid creds rejected: %v", err)
	}
}
