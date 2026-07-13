package wallet

import (
	"strings"
	"testing"

	"github.com/wonabru/qwid-node/common"
)

// TestGetMnemonicWordsRejectsOversizedKeyHonestly verifies CW-M2: a secret key
// larger than the 64-byte mnemonic ceiling (e.g. a post-quantum key) gets a clear,
// directive error instead of the misleading "less than 64 bytes" message. Pure
// length check — no oqs/CGO.
func TestGetMnemonicWordsRejectsOversizedKeyHonestly(t *testing.T) {
	w := &Wallet{}
	w.Account1.secretKey = common.PrivKey{ByteValue: make([]byte, 100)} // > 64

	_, err := w.GetMnemonicWords(true)
	if err == nil {
		t.Fatal("expected an error for a >64-byte secret key")
	}
	msg := err.Error()
	if strings.Contains(msg, "less than 64 bytes") {
		t.Fatalf("misleading old message still present: %q", msg)
	}
	if !strings.Contains(msg, "wallet-file") {
		t.Fatalf("error should direct the user to the wallet-file backup: %q", msg)
	}
}
