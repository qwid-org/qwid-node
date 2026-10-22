package wallet

import "testing"

func TestParsePUBACountsKeysOfAnyScheme(t *testing.T) {
	// After a scheme replacement the superseded primary is still registered:
	// not the current scheme's, but a key the dual-key rule counts.
	k, err := ParsePUBA([]byte(`{"hasPrimary":false,"hasSecondary":true,
		"addresses":[{"address":"aa","primary":true},{"address":"bb","primary":false}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if k.HasPrimary || !k.AnyPrimary || !k.AnySecondary {
		t.Fatalf("unexpected %+v", k)
	}
}

func TestSendRefusal(t *testing.T) {
	none := RegisteredKeys{}
	primaryOnly := RegisteredKeys{HasPrimary: true, AnyPrimary: true}
	both := RegisteredKeys{HasPrimary: true, HasSecondary: true, AnyPrimary: true, AnySecondary: true}

	cases := []struct {
		name                     string
		keys                     RegisteredKeys
		carriesKey, pure, paused bool
		refused                  bool
	}{
		{"first key bootstraps", none, true, true, false, false},
		{"first key bootstraps under a pause", none, true, true, true, false},
		{"transfer before any key", none, false, false, false, true},
		{"spare registered by live primary", primaryOnly, true, true, false, false},
		{"spare registered by PAUSED primary", primaryOnly, true, true, true, true},
		{"transfer with only the primary", primaryOnly, false, false, false, true},
		{"spare riding along a transfer", primaryOnly, true, false, false, true},
		{"transfer with both keys", both, false, false, false, false},
		{"new key via paused scheme with both keys", both, true, true, true, true},
	}
	for _, c := range cases {
		got := SendRefusal(c.keys, c.carriesKey, c.pure, c.paused) != ""
		if got != c.refused {
			t.Errorf("%s: refused=%v, want %v", c.name, got, c.refused)
		}
	}
}

func TestParsePUBAReadsCommitments(t *testing.T) {
	k, err := ParsePUBA([]byte(`{"hasPrimary":true,"hasSecondary":true,
		"recoveryCommit":"0101010101010101010101010101010101010101",
		"recoveryPending":"0202020202020202020202020202020202020202"}`))
	if err != nil {
		t.Fatal(err)
	}
	if k.RecoveryCommit.ByteValue[0] != 1 || k.RecoveryPending.ByteValue[19] != 2 {
		t.Fatalf("commitments not parsed: %+v", k)
	}
}
