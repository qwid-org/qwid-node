package handlers

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"sync"
)

// WH-C3: the WebUI previously had no authentication on any endpoint. Because it
// holds an unlocked wallet in-process, any local page/process able to reach the
// port could send funds or read the mnemonic. A session token is minted when the
// wallet is unlocked (LoadWallet/CreateWallet) and required on state-changing and
// sensitive endpoints. The cookie is HttpOnly + SameSite=Strict so other origins
// and non-browser scripts cannot read or forge it.

const sessionCookieName = "qwid_webui_session"

var (
	sessionToken string
	sessionMu    sync.RWMutex
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
	sessionMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// isAuthed reports whether the request carries the current session token.
func isAuthed(r *http.Request) bool {
	sessionMu.RLock()
	want := sessionToken
	sessionMu.RUnlock()
	if want == "" {
		return false
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(want)) == 1
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
