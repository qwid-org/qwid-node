package common

// Lock-in tests for the smart-contract return-data decoders (QWID-2026-09).
// The inputs are contract-controlled; malformed data must decode to
// zero-values deterministically, never panic. Fix already applied — keep green.

import "testing"

func TestQWID09_GetUintFromSCByteToleratesShortInput(t *testing.T) {
	for _, n := range []int{0, 1, 7, 24, 31} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("GetUintFromSCByte panicked on %d-byte contract return (%v) — "+
						"this is on the block-application path (QWID-2026-09)", n, r)
				}
			}()
			if got := GetUintFromSCByte(make([]byte, n)); got != 0 {
				t.Fatalf("short input returned %d, want 0", got)
			}
		}()
	}
}

func TestQWID09_GetStringFromSCBytesToleratesMalformed(t *testing.T) {
	cases := [][]byte{
		nil,
		make([]byte, 10),                 // shorter than one word
		make([]byte, 32),                 // length word present, no data
		func() []byte {                   // declares a huge length
			b := make([]byte, 64)
			for i := 24; i < 32; i++ {
				b[i] = 0xff
			}
			return b
		}(),
	}
	for i, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("GetStringFromSCBytes panicked on malformed case %d (%v) (QWID-2026-09)", i, r)
				}
			}()
			_ = GetStringFromSCBytes(c, 0) // any deterministic result; must not panic
		}()
	}
}

// TestQWID16_IsValidPubKeyLengthGatesRegistration verifies the QWID-2026-16
// gate: a registered key's byte length must match an active scheme's public-key
// length for its slot (current or the superseded one). Arbitrary lengths — the
// vector for bloating the pubkey trie and decode cache with unverifiable bytes
// — are rejected, and zero/negative lengths never validate.
func TestQWID16_IsValidPubKeyLengthGatesRegistration(t *testing.T) {
	// Snapshot and restore the process-global encryption config so this test
	// does not perturb others in the package.
	prim := GetEncryptionConfigInstance()
	primName, primPub, primPriv, primSig := prim.sigName, int(prim.pubKeyLength), int(prim.privateKeyLength), int(prim.signatureLength)
	sec := GetEncryptionConfigInstance()
	secName, secPub, secPriv, secSig := sec.sigName2, int(sec.pubKeyLength2), int(sec.privateKeyLength2), int(sec.signatureLength2)

	const curPrimLen, curSecLen = 897, 5554
	SetEncryption("falcon-cur", curPrimLen, 1281, 752, false, true)
	SetEncryption("mayo-cur", curSecLen, 24, 964, false, false)
	t.Cleanup(func() {
		SetEncryption(primName, primPub, primPriv, primSig, false, true)
		SetEncryption(secName, secPub, secPriv, secSig, false, false)
	})

	if got := PubKeyLength(false); got != curPrimLen {
		t.Fatalf("test setup: PubKeyLength(false)=%d, want %d", got, curPrimLen)
	}
	if got := PubKeyLength2(false); got != curSecLen {
		t.Fatalf("test setup: PubKeyLength2(false)=%d, want %d", got, curSecLen)
	}

	cases := []struct {
		name    string
		n       int
		primary bool
		want    bool
	}{
		{"current primary length accepted", curPrimLen, true, true},
		{"current secondary length accepted", curSecLen, false, true},
		{"primary length wrong slot rejected", curPrimLen, false, false},
		{"secondary length wrong slot rejected", curSecLen, true, false},
		{"arbitrary large junk rejected (primary)", 1 << 20, true, false},
		{"arbitrary large junk rejected (secondary)", 1 << 20, false, false},
		{"off-by-one rejected", curPrimLen + 1, true, false},
		{"zero length rejected", 0, true, false},
		{"negative length rejected", -1, false, false},
	}
	for _, c := range cases {
		if got := IsValidPubKeyLength(c.n, c.primary); got != c.want {
			t.Errorf("%s: IsValidPubKeyLength(%d, primary=%v)=%v, want %v", c.name, c.n, c.primary, got, c.want)
		}
	}
}
