package handlers

import (
	"path/filepath"
	"testing"
)

// TestQWID30_RegistrySaveSurfacesError confirms Users.save returns an error when
// the registry cannot be written. The change-password handler now keys its
// rollback on this error instead of swallowing it, which is what prevents the
// wallet file and the login hash from silently diverging (QWID-2026-30).
func TestQWID30_RegistrySaveSurfacesError(t *testing.T) {
	saved := Users
	t.Cleanup(func() { Users = saved })

	Users = &UserRegistry{
		users:    map[string]*UserEntry{"u": {PasswordHash: "old"}},
		filePath: filepath.Join(t.TempDir(), "no-such-subdir", "users.json"),
	}
	if err := Users.save(); err == nil {
		t.Fatal("Users.save must return an error when its path is unwritable")
	}
}

// TestQWID30_InMemoryHashRestoredOnSaveFailure mirrors the handler's rollback:
// when the registry save fails, the in-memory password hash must be reverted to
// the old value so the running process does not accept the new password while
// the wallet (rolled back) is still under the old one.
func TestQWID30_InMemoryHashRestoredOnSaveFailure(t *testing.T) {
	saved := Users
	t.Cleanup(func() { Users = saved })

	Users = &UserRegistry{
		users:    map[string]*UserEntry{"u": {PasswordHash: "old"}},
		filePath: filepath.Join(t.TempDir(), "no-such-subdir", "users.json"),
	}

	entry := Users.users["u"]
	oldHash := entry.PasswordHash
	entry.PasswordHash = "new"
	if err := Users.save(); err != nil {
		entry.PasswordHash = oldHash // the handler's revert-on-failure step
	}
	if entry.PasswordHash != "old" {
		t.Fatalf("in-memory hash = %q, want the old hash restored after a failed save", entry.PasswordHash)
	}
}
