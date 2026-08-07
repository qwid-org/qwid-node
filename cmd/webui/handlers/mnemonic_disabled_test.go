package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGetMnemonicIsDisabledOverHTTP: the recovery phrase gives full control of
// the wallet, so it must never travel over the network — not even to localhost,
// where it would land in browser history and caches.
func TestGetMnemonicIsDisabledOverHTTP(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			rec := httptest.NewRecorder()
			GetMnemonic(rec, httptest.NewRequest(method, "/api/wallet/mnemonic", strings.NewReader(`{"password":"x"}`)))

			if rec.Code == http.StatusOK {
				t.Fatalf("endpoint odpowiedział 200 — fraza mogła wyciec")
			}
			body := rec.Body.String()
			if !strings.Contains(strings.ToLower(body), "local") {
				t.Fatalf("odpowiedź %q nie tłumaczy, że fraza jest dostępna tylko lokalnie", body)
			}
		})
	}
}
