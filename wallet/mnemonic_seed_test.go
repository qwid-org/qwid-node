package wallet

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewMnemonic24ReturnsTwentyFourWords(t *testing.T) {
	m, err := NewMnemonic24()
	if err != nil {
		t.Fatalf("NewMnemonic24() returned an error: %v", err)
	}
	words := strings.Fields(string(m))
	if len(words) != MnemonicWordCount {
		t.Fatalf("word count = %d, expected %d", len(words), MnemonicWordCount)
	}
}

func TestNewMnemonic24IsDifferentEveryTime(t *testing.T) {
	a, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two consecutive phrases are identical — the entropy does not come from crypto/rand")
	}
}

func TestSeedFromMnemonicIsDeterministic(t *testing.T) {
	m, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	s1, err := SeedFromMnemonic(m)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := SeedFromMnemonic(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s1, s2) {
		t.Fatal("the same phrase produced different seeds")
	}
	if len(s1) != 64 {
		t.Fatalf("seed length = %d, expected 64", len(s1))
	}
}

func TestSeedFromMnemonicRejectsBadInput(t *testing.T) {
	valid, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	words := strings.Fields(string(valid))

	cases := []struct {
		name     string
		mnemonic string
		wantMsg  string
	}{
		{"pusta", "", "24"},
		{"twelve words", strings.Join(words[:12], " "), "24"},
		{"word outside the list", strings.Join(append(append([]string{}, words[:23]...), "qwidqwid"), " "), "invalid"},
		// Fixed vector, not a corrupted random phrase. Replacing the last word of
		// a random phrase with another valid word restores a valid checksum about
		// 1 run in 256 (the checksum is 8 bits), so that version of this subtest
		// failed sporadically — and a suite whose job is catching derivation drift
		// must never teach anyone to just re-run it. This one is deterministic:
		// all-zero entropy's valid 24-word phrase ends in "art" (that is the
		// katPhrase in mnemonic_kat_test.go); ending it in a 24th "abandon"
		// encodes checksum byte 0x00 where SHA-256(0^32)'s first byte is required,
		// so the checksum is always wrong.
		{"bad checksum", strings.Repeat("abandon ", 23) + "abandon", "invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SeedFromMnemonic([]byte(tc.mnemonic))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("message %q does not contain %q", err.Error(), tc.wantMsg)
			}
		})
	}
}

func TestDeriveKeySeedSeparatesDomains(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 64)

	falconPrimary := DeriveKeySeed(seed, "Falcon-512", true)
	falconSecondary := DeriveKeySeed(seed, "Falcon-512", false)
	mayoPrimary := DeriveKeySeed(seed, "MAYO-5", true)

	if len(falconPrimary) != 64 {
		t.Fatalf("key seed length = %d, expected 64", len(falconPrimary))
	}
	if bytes.Equal(falconPrimary, falconSecondary) {
		t.Fatal("the primary and secondary roles produced the same seed")
	}
	if bytes.Equal(falconPrimary, mayoPrimary) {
		t.Fatal("different schemes produced the same seed")
	}
	if !bytes.Equal(falconPrimary, DeriveKeySeed(seed, "Falcon-512", true)) {
		t.Fatal("derivation is not deterministic")
	}
}

func TestZeroBytesClears(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	ZeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d = %d, expected 0", i, v)
		}
	}
}
