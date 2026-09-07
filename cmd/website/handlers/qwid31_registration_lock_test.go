package handlers

import (
	"testing"
	"time"
)

// TestQWID31_RegistrationLockSerializesSameUsername verifies the per-username
// lock that closes the registration TOCTOU: the same username maps to one lock,
// and while it is held a second registration of that username blocks (so it
// cannot write the same wallet file concurrently) (QWID-2026-31).
func TestQWID31_RegistrationLockSerializesSameUsername(t *testing.T) {
	if registrationLock("alice") != registrationLock("alice") {
		t.Fatal("same username must map to the same lock")
	}

	lk := registrationLock("bob")
	lk.Lock()

	entered := make(chan struct{})
	go func() {
		l2 := registrationLock("bob")
		l2.Lock()
		close(entered)
		l2.Unlock()
	}()

	select {
	case <-entered:
		t.Fatal("second registration acquired the same-username lock while it was held")
	case <-time.After(50 * time.Millisecond):
		// expected: the second holder is blocked
	}

	lk.Unlock()

	select {
	case <-entered:
		// expected: it proceeds once the lock is released
	case <-time.After(time.Second):
		t.Fatal("second registration never acquired the lock after release")
	}
}
