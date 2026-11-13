package handlers

import (
	"testing"
	"time"

	"github.com/qwid-org/qwid-node/wallet"
)

// Audit 2026-11-12: a session found expired on access is wiped like one the
// cleanup loop removes - its wallet's password and keys leave memory.
func TestExpiredSessionWipesItsWallet(t *testing.T) {
	w := wallet.EmptyWallet(0, "", "")
	w.SetPassword("correct horse")
	if !w.VerifyPassword("correct horse") {
		t.Fatal("setup: password not set")
	}
	store := &SessionStore{sessions: map[string]*Session{}}
	token, err := store.Create("alice", &w)
	if err != nil {
		t.Fatal(err)
	}
	store.sessions[token].LastAccess = time.Now().Add(-2 * sessionTimeout)
	if store.Get(token) != nil {
		t.Fatal("an expired session was returned")
	}
	if w.VerifyPassword("correct horse") {
		t.Fatal("the expired session's wallet still holds its password")
	}
}
