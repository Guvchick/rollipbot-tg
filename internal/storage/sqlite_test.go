package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newStore(t *testing.T) *SQLite {
	t.Helper()
	st, err := NewSQLite(context.Background(), filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestProxiesCRUDAndBinding(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)

	id, err := st.AddProxy(ctx, Proxy{Label: "p1", Scheme: "socks5", Host: "1.2.3.4", Port: 1080, Username: "u", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	list, err := st.ListProxies(ctx)
	if err != nil || len(list) != 1 || list[0].Host != "1.2.3.4" || list[0].Username != "u" {
		t.Fatalf("list proxies = %v, %v", list, err)
	}
	if url := list[0].URL(); url != "socks5://u:pw@1.2.3.4:1080" {
		t.Errorf("proxy URL = %q", url)
	}

	// bind to an account, read it back
	accID, err := st.UpsertAccount(ctx, Account{Provider: "timeweb", Label: "a", Enabled: true, Credentials: map[string]string{"token": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.AccountProxy(ctx, accID); ok {
		t.Fatal("no proxy should be bound yet")
	}
	if err := st.BindProxy(ctx, accID, id); err != nil {
		t.Fatal(err)
	}
	px, ok, err := st.AccountProxy(ctx, accID)
	if err != nil || !ok || px.ID != id {
		t.Fatalf("bound proxy = %+v ok=%v err=%v", px, ok, err)
	}
	// deleting the proxy also clears the binding
	if err := st.DeleteProxy(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.AccountProxy(ctx, accID); ok {
		t.Error("binding should be gone after proxy delete")
	}
}

func TestAccountDailyCapOverride(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	accID, err := st.UpsertAccount(ctx, Account{Provider: "timeweb", Label: "a", Enabled: true, Credentials: map[string]string{"token": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.AccountDailyCap(ctx, accID); ok {
		t.Fatal("no override should exist initially")
	}
	if err := st.SetAccountDailyCap(ctx, accID, 7); err != nil {
		t.Fatal(err)
	}
	if cap, ok, _ := st.AccountDailyCap(ctx, accID); !ok || cap != 7 {
		t.Fatalf("override = %d ok=%v, want 7", cap, ok)
	}
	// 0 is a valid override (unlimited), distinct from "not set"
	if err := st.SetAccountDailyCap(ctx, accID, 0); err != nil {
		t.Fatal(err)
	}
	if cap, ok, _ := st.AccountDailyCap(ctx, accID); !ok || cap != 0 {
		t.Fatalf("override = %d ok=%v, want 0/true", cap, ok)
	}
	if err := st.ClearAccountDailyCap(ctx, accID); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.AccountDailyCap(ctx, accID); ok {
		t.Error("override should be gone after clear")
	}
}

func TestAccountMasksPresets(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	accID, err := st.UpsertAccount(ctx, Account{Provider: "gcore", Label: "a", Enabled: true, Credentials: map[string]string{"api_token": "x", "project_id": "1"}})
	if err != nil {
		t.Fatal(err)
	}
	if ms, _ := st.ListAccountMasks(ctx, accID); len(ms) != 0 {
		t.Fatalf("fresh presets = %v, want none", ms)
	}
	for _, m := range []string{"92.38.0.0/16", "5.188.*.*"} {
		if err := st.AddAccountMask(ctx, accID, m); err != nil {
			t.Fatal(err)
		}
	}
	// duplicate add is a no-op (no error, no dup row)
	if err := st.AddAccountMask(ctx, accID, "92.38.0.0/16"); err != nil {
		t.Fatal(err)
	}
	ms, err := st.ListAccountMasks(ctx, accID)
	if err != nil || len(ms) != 2 {
		t.Fatalf("presets = %v (err %v), want 2", ms, err)
	}
	if err := st.RemoveAccountMask(ctx, accID, "5.188.*.*"); err != nil {
		t.Fatal(err)
	}
	ms, _ = st.ListAccountMasks(ctx, accID)
	if len(ms) != 1 || ms[0] != "92.38.0.0/16" {
		t.Fatalf("after remove = %v, want [92.38.0.0/16]", ms)
	}
	// deleting the account clears its presets
	if err := st.DeleteAccount(ctx, accID); err != nil {
		t.Fatal(err)
	}
	if ms, _ := st.ListAccountMasks(ctx, accID); len(ms) != 0 {
		t.Errorf("presets after account delete = %v, want none", ms)
	}
}

func TestAutoRollConfig(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	accID, err := st.UpsertAccount(ctx, Account{Provider: "timeweb", Label: "a", Enabled: true, Credentials: map[string]string{"token": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.GetAutoRoll(ctx, accID); ok {
		t.Fatal("no auto-roll config should exist initially")
	}
	if err := st.SetAutoRoll(ctx, AutoRoll{AccountID: accID, Enabled: true, Budget: 30}); err != nil {
		t.Fatal(err)
	}
	ar, ok, err := st.GetAutoRoll(ctx, accID)
	if err != nil || !ok || !ar.Enabled || ar.Budget != 30 {
		t.Fatalf("auto-roll = %+v ok=%v err=%v", ar, ok, err)
	}
	if !ar.LastRun.IsZero() {
		t.Errorf("LastRun should be zero before first run, got %v", ar.LastRun)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err := st.TouchAutoRollRun(ctx, accID, now); err != nil {
		t.Fatal(err)
	}
	// touch must not clobber enabled/budget
	ar, _, _ = st.GetAutoRoll(ctx, accID)
	if !ar.Enabled || ar.Budget != 30 || ar.LastRun.Unix() != now.Unix() {
		t.Fatalf("after touch = %+v, want enabled budget=30 lastrun=%v", ar, now)
	}
	list, err := st.ListAutoRoll(ctx)
	if err != nil || len(list) != 1 || list[0].AccountID != accID {
		t.Fatalf("ListAutoRoll = %+v (err %v), want one row", list, err)
	}
}

func TestRollStats(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	// two matched (one of them released=false), one released miss
	_ = st.LogRoll(ctx, RollLogEntry{Provider: "timeweb#1", IP: "1.1.1.1", Matched: true, Released: false})
	_ = st.LogRoll(ctx, RollLogEntry{Provider: "timeweb#1", IP: "1.1.1.2", Matched: false, Released: true})
	_ = st.LogRoll(ctx, RollLogEntry{Provider: "vkcloud#2", IP: "2.2.2.2", Matched: true, Released: false})

	stats, err := st.RollStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]ProviderStat{}
	for _, s := range stats {
		by[s.Provider] = s
	}
	if s := by["timeweb#1"]; s.Total != 2 || s.Matched != 1 || s.Released != 1 || s.Today != 2 {
		t.Errorf("timeweb stat = %+v", s)
	}
	if s := by["vkcloud#2"]; s.Total != 1 || s.Matched != 1 {
		t.Errorf("vkcloud stat = %+v", s)
	}
}

func TestAccountsCRUD(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)

	id, err := st.UpsertAccount(ctx, Account{
		Provider: "timeweb", Label: "prod", Enabled: true,
		Credentials: map[string]string{"token": "abc", "availability_zone": "spb-1"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Upsert with same provider+label updates in place (same id), not a new row.
	id2, err := st.UpsertAccount(ctx, Account{
		Provider: "timeweb", Label: "prod", Enabled: true,
		Credentials: map[string]string{"token": "xyz"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if id != id2 {
		t.Fatalf("upsert created a new row: %d vs %d", id, id2)
	}

	got, err := st.GetAccount(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Credentials["token"] != "xyz" {
		t.Errorf("credentials not updated: %v", got.Credentials)
	}

	n, err := st.CountAccounts(ctx)
	if err != nil || n != 1 {
		t.Fatalf("count = %d (err %v), want 1", n, err)
	}

	// disabled accounts excluded from ListEnabledAccounts
	if err := st.SetAccountEnabled(ctx, id, false); err != nil {
		t.Fatal(err)
	}
	enabled, err := st.ListEnabledAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(enabled) != 0 {
		t.Errorf("ListEnabledAccounts = %d, want 0", len(enabled))
	}
	all, _ := st.ListAccounts(ctx)
	if len(all) != 1 {
		t.Errorf("ListAccounts = %d, want 1", len(all))
	}

	if err := st.DeleteAccount(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetAccount(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete err = %v, want ErrNotFound", err)
	}
}

func TestAccountNotFoundOps(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	if err := st.SetAccountEnabled(ctx, 999, true); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetAccountEnabled missing: %v", err)
	}
	if err := st.DeleteAccount(ctx, 999); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteAccount missing: %v", err)
	}
}

func TestAllowedUsers(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)

	if err := st.AddAllowedUser(ctx, AllowedUser{UserID: 42, Note: "me"}); err != nil {
		t.Fatal(err)
	}
	// idempotent upsert
	if err := st.AddAllowedUser(ctx, AllowedUser{UserID: 42, Note: "updated"}); err != nil {
		t.Fatal(err)
	}
	users, err := st.ListAllowedUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].UserID != 42 || users[0].Note != "updated" {
		t.Fatalf("users = %+v, want one user 42 note=updated", users)
	}

	if err := st.RemoveAllowedUser(ctx, 42); err != nil {
		t.Fatal(err)
	}
	users, _ = st.ListAllowedUsers(ctx)
	if len(users) != 0 {
		t.Errorf("after remove len = %d, want 0", len(users))
	}
}

func TestDailyCounter(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const day = "2026-06-25"
	if n, _ := st.DailyCount(ctx, "timeweb#1", day); n != 0 {
		t.Fatalf("fresh count = %d, want 0", n)
	}
	for i := 0; i < 3; i++ {
		if err := st.IncDaily(ctx, "timeweb#1", day); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := st.DailyCount(ctx, "timeweb#1", day); n != 3 {
		t.Errorf("count = %d, want 3", n)
	}
	// different account/day are independent
	if n, _ := st.DailyCount(ctx, "timeweb#2", day); n != 0 {
		t.Errorf("other account count = %d, want 0", n)
	}
}
