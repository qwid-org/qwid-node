package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qwid-org/qwid-node/wallet"
)

// TestGetMnemonicIsDisabledOverHTTP: this server is multi-user and
// network-facing, so the recovery phrase — which gives full control of every
// signature scheme in a user's wallet — must never travel over HTTP for any
// request shape: any method, and regardless of whether the request carries an
// authenticated session with a loaded wallet, or no session at all.
func TestGetMnemonicIsDisabledOverHTTP(t *testing.T) {
	sessionVariants := map[string]*Session{
		"no session":                nil,
		"authenticated with wallet": {Username: "alice", Wallet: &wallet.Wallet{}},
	}

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for sessName, sess := range sessionVariants {
			t.Run(method+"/"+sessName, func(t *testing.T) {
				req := httptest.NewRequest(method, "/api/wallet/mnemonic", strings.NewReader(`{"password":"x"}`))
				if sess != nil {
					req = req.WithContext(contextWithSession(req.Context(), sess))
				}
				rec := httptest.NewRecorder()
				GetMnemonic(rec, req)

				if rec.Code == http.StatusOK {
					t.Fatalf("endpoint responded 200 — phrase material may have leaked")
				}
				body := rec.Body.String()
				if !strings.Contains(strings.ToLower(body), "local") {
					t.Fatalf("response %q does not explain the phrase is available only locally", body)
				}
			})
		}
	}
}
