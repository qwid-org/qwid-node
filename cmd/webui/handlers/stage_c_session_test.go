package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func withCookieFrom(rec *httptest.ResponseRecorder) *http.Request {
	r := httptest.NewRequest("GET", "/api/account", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	return r
}

// S8-03: an unlocked session does not live forever.
func TestSessionExpiresWhenIdle(t *testing.T) {
	saved := sessionIdleTimeout
	sessionIdleTimeout = 50 * time.Millisecond
	defer func() { sessionIdleTimeout = saved; endSession() }()

	rec := httptest.NewRecorder()
	startSession(rec)
	if !isAuthed(withCookieFrom(rec)) {
		t.Fatal("fresh session not accepted")
	}
	time.Sleep(80 * time.Millisecond)
	if isAuthed(withCookieFrom(rec)) {
		t.Fatal("idle session still accepted")
	}
	if sessionActive() {
		t.Fatal("expired session still counts as active")
	}
}

// S8-03: logout ends the session.
func TestLogoutEndsSession(t *testing.T) {
	defer endSession()
	rec := httptest.NewRecorder()
	startSession(rec)
	r := withCookieFrom(rec)
	r.Method = "POST"
	Logout(httptest.NewRecorder(), r)
	if isAuthed(withCookieFrom(rec)) {
		t.Fatal("session survived logout")
	}
}

// S8-03: another local process may not replace the wallet of a live session.
func TestLoadWalletRefusesToReplaceAnotherLiveSession(t *testing.T) {
	defer endSession()
	startSession(httptest.NewRecorder())
	for _, h := range []http.HandlerFunc{LoadWallet, CreateWallet} {
		r := httptest.NewRequest("POST", "/api/wallet/load", bytes.NewBufferString(`{"walletNumber":0,"password":"whatever123"}`))
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != http.StatusConflict {
			t.Fatalf("got %d, want 409 while another session is live", w.Code)
		}
	}
}

// S8-03: past the cap, attempts are slowed down rather than refused, so a
// local process cannot lock the operator out, yet guessing stays bounded.
func TestLoadWalletGateDelaysInsteadOfLocking(t *testing.T) {
	loadWalletThrottleReset()
	defer loadWalletThrottleReset()
	saved := loadWalletPenalty
	loadWalletPenalty = 40 * time.Millisecond
	defer func() { loadWalletPenalty = saved }()

	now := time.Now()
	for i := 0; i < loadWalletMaxAttempts; i++ {
		if !loadWalletGate(context.Background(), now) {
			t.Fatal("attempt within the cap refused")
		}
	}
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !loadWalletGate(context.Background(), now) {
				t.Error("an attempt past the cap must be delayed, not refused")
			}
		}()
	}
	wg.Wait()
	if el := time.Since(start); el < 80*time.Millisecond {
		t.Fatalf("two penalised attempts took %s; they must be serialised", el)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if loadWalletGate(ctx, now) {
		t.Fatal("a cancelled request must not proceed")
	}
}
