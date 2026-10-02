package handlers

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// WH-C3: the WebUI previously had no authentication on any endpoint. Because it
// holds an unlocked wallet in-process, any local page/process able to reach the
// port could send funds or read the mnemonic. A session token is minted when the
// wallet is unlocked (LoadWallet/CreateWallet) and required on state-changing and
// sensitive endpoints. The cookie is HttpOnly + SameSite=Strict so other origins
// and non-browser scripts cannot read or forge it.

const sessionCookieName = "qwid_webui_session"

var (
	sessionToken    string
	sessionLastSeen time.Time
	sessionMu       sync.RWMutex
	// sessionIdleTimeout ends an unlocked session nobody uses (S8-03).
	sessionIdleTimeout = 30 * time.Minute
)

func newSessionToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// startSession mints a new session token, invalidating any previous one, and
// sets it as a cookie.
func startSession(w http.ResponseWriter) {
	token := newSessionToken()
	sessionMu.Lock()
	sessionToken = token
	sessionLastSeen = time.Now()
	sessionMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// isAuthed reports whether the request carries the current, unexpired session
// token, and refreshes its idle clock.
func isAuthed(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	sessionMu.Lock()
	defer sessionMu.Unlock()
	if !sessionLiveLocked() {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(sessionToken)) != 1 {
		return false
	}
	sessionLastSeen = time.Now()
	return true
}

// sessionLiveLocked reports whether a session exists and has not idled out,
// ending it if it has. The caller holds sessionMu.
func sessionLiveLocked() bool {
	if sessionToken == "" {
		return false
	}
	if time.Since(sessionLastSeen) > sessionIdleTimeout {
		sessionToken = ""
		return false
	}
	return true
}

// sessionActive reports whether some browser holds a live session.
func sessionActive() bool {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	return sessionLiveLocked()
}

func endSession() {
	sessionMu.Lock()
	sessionToken = ""
	sessionMu.Unlock()
}

// Logout ends the current session (S8-03).
func Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if isAuthed(r) {
		endSession()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	jsonResponse(w, map[string]string{"success": "true"})
}

// refuseIfAnotherSession stops a wallet load or creation from replacing the
// wallet of a live session held by another browser or process (S8-03).
func refuseIfAnotherSession(w http.ResponseWriter, r *http.Request) bool {
	if sessionActive() && !isAuthed(r) {
		jsonError(w, "Another session has the wallet unlocked; log out there or wait for it to expire", http.StatusConflict)
		return true
	}
	return false
}

// RequireAuth wraps a handler so it only runs for an authenticated session.
func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isAuthed(r) {
			jsonError(w, "Authentication required: unlock the wallet first", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}
