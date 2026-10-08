package wallet

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/wonabru/bip39"
)

// S5-05: github.com/wonabru/bip39 is a fork of the vanished tyler-smith
// package. Its own tests could change with it, so it is pinned here against
// values taken from outside it: the SHA-256 of the official english.txt
// (github.com/bitcoin/bips, bip-0039) and seeds computed with Python's
// hashlib.pbkdf2_hmac, the TREZOR one being the published BIP39 vector.
func TestBip39ForkMatchesTheStandard(t *testing.T) {
	list := strings.Join(bip39.WordList, "\n") + "\n"
	sum := sha256.Sum256([]byte(list))
	if got := hex.EncodeToString(sum[:]); got != "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda" {
		t.Fatalf("the word list differs from the official BIP39 english.txt: sha256 %s", got)
	}

	m, err := bip39.NewMnemonic(make([]byte, 32))
	if err != nil || m != katPhrase {
		t.Fatalf("zero entropy must give the standard 24-word vector, got %q (%v)", m, err)
	}
	if got := hex.EncodeToString(bip39.NewSeed(katPhrase, "TREZOR")); got !=
		"bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8" {
		t.Fatalf("seed differs from the published BIP39 vector: %s", got)
	}
	seed, err := SeedFromMnemonic([]byte(katPhrase))
	if err != nil || hex.EncodeToString(seed) !=
		"408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840" {
		t.Fatalf("wallet seed differs from PBKDF2-HMAC-SHA512 with an empty passphrase (%v)", err)
	}
	bad := strings.Replace(katPhrase, " art", " abandon", 1)
	if _, err := SeedFromMnemonic([]byte(bad)); err == nil {
		t.Fatal("a phrase with a wrong checksum was accepted")
	}
}
