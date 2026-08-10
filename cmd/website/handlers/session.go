package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/qwid-org/qwid-node/wallet"
)

const (
	sessionCookieName = "qwid_session"
	sessionTimeout    = 30 * time.Minute
	cleanupInterval   = 5 * time.Minute
)

type Session struct {
	Username   string
	Wallet     *wallet.Wallet
	LastAccess time.Time
}

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

var Sessions = &SessionStore{
	sessions: make(map[string]*Session),
}

func init() {
	go Sessions.cleanupLoop()
}

func (s *SessionStore) Create(username string, w *wallet.Wallet) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = &Session{
		Username:   username,
		Wallet:     w,
		LastAccess: time.Now(),
	}
	return token, nil
}

func (s *SessionStore) Get(token string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return nil
	}
	if time.Since(sess.LastAccess) > sessionTimeout {
		delete(s.sessions, token)
		return nil
	}
	sess.LastAccess = time.Now()
	return sess
}

func (s *SessionStore) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[token]; ok {
		wipeSessionWallet(sess) // WH-M9
		delete(s.sessions, token)
	}
}

// DeleteByUsername removes any existing sessions for a user (WH-H8): a fresh
// login invalidates prior sessions so a stolen/leaked token cannot outlive it.
func (s *SessionStore) DeleteByUsername(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, sess := range s.sessions {
		if sess.Username == username {
			wipeSessionWallet(sess)
			delete(s.sessions, token)
		}
	}
}

// wipeSessionWallet zeroes the wallet's key material (WH-M9). Caller holds s.mu.
func wipeSessionWallet(sess *Session) {
	if sess != nil && sess.Wallet != nil {
		sess.Wallet.Wipe()
	}
}

func (s *SessionStore) GetFromRequest(r *http.Request) *Session {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil
	}
	return s.Get(cookie.Value)
}

func (s *SessionStore) SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		// WH-H4: mark the session cookie Secure (HTTPS-only) by default. Set
		// COOKIE_INSECURE=true only for local HTTP development.
		Secure:   os.Getenv("COOKIE_INSECURE") != "true",
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTimeout.Seconds()),
	})
}

func (s *SessionStore) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func (s *SessionStore) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for token, sess := range s.sessions {
			if now.Sub(sess.LastAccess) > sessionTimeout {
				wipeSessionWallet(sess) // WH-M9
				delete(s.sessions, token)
			}
		}
		s.mu.Unlock()
	}
}
