package wallet

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"
	"strings"

	"github.com/wonabru/bip39"
	"golang.org/x/crypto/hkdf"
)

// MnemonicWordCount is the only accepted phrase length. 24 words carry 256 bits
// of entropy; a 12-word phrase would carry 128, which Grover's algorithm reduces
// to 2^64 — unacceptable for a chain whose purpose is quantum resistance.
const MnemonicWordCount = 24

// mnemonicEntropyBytes is the entropy behind a 24-word phrase: 256 bits.
const mnemonicEntropyBytes = 32

// keySeedLength is the size of the per-key seed handed to the deterministic
// keygen. 64 bytes comfortably covers every scheme's seed draw (Falcon-512 takes
// 48, MAYO-5 fewer) and leaves headroom for future ones.
const keySeedLength = 64

// hkdfSalt separates this project's key derivation from any other use of the
// same BIP39 seed. Changing it invalidates every existing wallet — it is pinned
// by the known-answer test.
const hkdfSalt = "qwid-wallet-v1"

// NewMnemonic24 generates a fresh 24-word recovery phrase from the system CSPRNG.
// The phrase is returned as []byte, not string, so the caller can zero it.
func NewMnemonic24() ([]byte, error) {
	entropy := make([]byte, mnemonicEntropyBytes)
	if _, err := rand.Read(entropy); err != nil {
		return nil, fmt.Errorf("nie można pobrać entropii z systemowego CSPRNG: %w", err)
	}
	defer ZeroBytes(entropy)

	m, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("nie można zbudować frazy: %w", err)
	}
	return []byte(m), nil
}

// SeedFromMnemonic validates a recovery phrase and turns it into the 64-byte
// BIP39 seed (PBKDF2-HMAC-SHA512, 2048 iterations, empty passphrase).
func SeedFromMnemonic(mnemonic []byte) ([]byte, error) {
	phrase := strings.Join(strings.Fields(string(mnemonic)), " ")
	if n := len(strings.Fields(phrase)); n != MnemonicWordCount {
		return nil, fmt.Errorf("fraza musi mieć dokładnie %d słów, podano %d", MnemonicWordCount, n)
	}
	// bip39.IsMnemonicValid only checks word count and wordlist membership; it
	// does not verify the checksum bits. bip39.MnemonicToByteArray calls
	// IsMnemonicValid internally and then verifies the checksum, so it is the
	// only one of the two that actually rejects a mnemonic with a bad checksum.
	if _, err := bip39.MnemonicToByteArray(phrase); err != nil {
		return nil, fmt.Errorf("nieprawidłowa fraza: słowo spoza listy BIP39 albo błędna suma kontrolna")
	}
	return bip39.NewSeed(phrase, ""), nil
}

// DeriveKeySeed derives the per-key seed for one signature scheme and one role.
// Domain separation by scheme name means a single phrase covers whatever scheme
// the chain votes in later; separation by role keeps the primary and secondary
// keys independent of each other given only one of them.
func DeriveKeySeed(seed []byte, sigName string, primary bool) []byte {
	role := "secondary"
	if primary {
		role = "primary"
	}
	info := make([]byte, 0, len(sigName)+1+len(role))
	info = append(info, sigName...)
	info = append(info, 0x00)
	info = append(info, role...)

	out := make([]byte, keySeedLength)
	r := hkdf.New(sha512.New, seed, []byte(hkdfSalt), info)
	if _, err := io.ReadFull(r, out); err != nil {
		// HKDF-SHA512 can emit up to 16320 bytes; a 64-byte read cannot fail.
		panic("hkdf: " + err.Error())
	}
	return out
}

// ZeroBytes overwrites b in place. Use it on every buffer that held a phrase or
// a seed before letting it go out of scope.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
