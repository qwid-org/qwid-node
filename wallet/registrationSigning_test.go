package wallet

import "testing"

// TestRegistrationSigningPrimary pins the signing-slot rule for key-carrying
// registration transactions (incident 2026-09-08): bootstrap self-signs with
// the enclosed key, a lone registered key authorizes, both-registered keeps the
// default.
func TestRegistrationSigningPrimary(t *testing.T) {
	cases := []struct {
		name                                              string
		hasP, hasS, registerPrimary, defaultPrimary, want bool
	}{
		// Bootstrap (nothing registered): sign with the enclosed key's slot,
		// regardless of the default. This is node 2's tx#1 (Falcon key enclosed,
		// default MAYO-2 → must sign Falcon).
		{"bootstrap primary key", false, false, true, false, true},
		{"bootstrap secondary key", false, false, false, true, false},
		// One slot registered: that key authorizes. Node 2's tx#2 (enclose
		// MAYO-2, Falcon registered, default MAYO-2 → must sign Falcon).
		{"only primary registered", true, false, false, false, true},
		{"only primary registered, registering primary again", true, false, true, false, true},
		{"only secondary registered", false, true, true, true, false},
		// Both registered: the default (active scheme) is verifiable — keep it.
		{"both registered keep default primary", true, true, false, true, true},
		{"both registered keep default secondary", true, true, true, false, false},
	}
	for _, c := range cases {
		if got := RegistrationSigningPrimary(c.hasP, c.hasS, c.registerPrimary, c.defaultPrimary); got != c.want {
			t.Errorf("%s: RegistrationSigningPrimary(%v,%v,%v,%v)=%v, want %v",
				c.name, c.hasP, c.hasS, c.registerPrimary, c.defaultPrimary, got, c.want)
		}
	}
}
