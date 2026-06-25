package bot

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"ip-roller-bot/internal/storage"
)

func aclStore(t *testing.T) storage.Storage {
	t.Helper()
	st, err := storage.NewSQLite(context.Background(), filepath.Join(t.TempDir(), "acl.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestACLAdminsAndStatic(t *testing.T) {
	ctx := context.Background()
	acl := NewACL(aclStore(t), quiet(), []int64{1}, []int64{2})
	if err := acl.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if !acl.IsAdmin(1) {
		t.Error("1 should be admin")
	}
	if acl.IsAdmin(2) {
		t.Error("2 is static-allowed, not admin")
	}
	if !acl.IsAllowed(1) || !acl.IsAllowed(2) {
		t.Error("admin and static must be allowed")
	}
	if acl.IsAllowed(3) {
		t.Error("3 must be denied when access is configured")
	}
	if !acl.Configured() {
		t.Error("should be configured")
	}
}

func TestACLDynamicAddRemove(t *testing.T) {
	ctx := context.Background()
	store := aclStore(t)
	acl := NewACL(store, quiet(), []int64{1}, nil)
	if err := acl.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if acl.IsAllowed(7) {
		t.Fatal("7 not yet allowed")
	}
	if err := acl.Add(ctx, 7, "friend"); err != nil {
		t.Fatal(err)
	}
	if !acl.IsAllowed(7) {
		t.Error("7 should be allowed after Add")
	}
	// persisted: a fresh ACL reload from the same store sees it
	acl2 := NewACL(store, quiet(), nil, nil)
	if err := acl2.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if !acl2.IsAllowed(7) {
		t.Error("7 should persist across reload")
	}
	if err := acl.Remove(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if acl.IsAllowed(7) {
		t.Error("7 should be denied after Remove")
	}
}

func TestACLOpenWhenUnconfigured(t *testing.T) {
	ctx := context.Background()
	acl := NewACL(aclStore(t), quiet(), nil, nil)
	if err := acl.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if acl.Configured() {
		t.Error("should not be configured")
	}
	if !acl.IsAllowed(12345) {
		t.Error("unconfigured ACL must allow everyone")
	}
}
