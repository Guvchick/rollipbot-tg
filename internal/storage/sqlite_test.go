package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
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
