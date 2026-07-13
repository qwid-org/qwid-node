package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRegisterDoesNotDiscloseUsernameExists verifies WH-H3: registering an
// already-taken username returns the same generic 400 as other registration
// failures, not a distinct "Username already taken" 409 enumeration oracle.
// The taken path returns at the Exists check, before any wallet/oqs work, so
// this test needs no CGO.
func TestRegisterDoesNotDiscloseUsernameExists(t *testing.T) {
	// Save and restore the package globals this test mutates.
	savedUsers, savedLimiter := Users, registerLimiter
	defer func() { Users, registerLimiter = savedUsers, savedLimiter }()

	// Seed a registry with an existing username (direct map write; no file I/O).
	Users = &UserRegistry{users: map[string]*UserEntry{"takenuser": {}}}
	// Fresh limiter so a single request is never throttled.
	registerLimiter = &rateLimiter{entries: make(map[string][]time.Time)}

	body := strings.NewReader(`{"username":"takenuser","password":"password123"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/register", body)
	req.RemoteAddr = "203.0.113.5:40000"
	rr := httptest.NewRecorder()

	Register(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("taken username: status = %d, want 400 (must not be a distinct 409)", rr.Code)
	}
	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	msg := resp["error"]
	for _, leak := range []string{"taken", "Taken", "exist", "Exist"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("response leaks existence: %q contains %q", msg, leak)
		}
	}
	if msg != "Registration could not be completed. Please try different details." {
		t.Fatalf("unexpected message: %q", msg)
	}
}
