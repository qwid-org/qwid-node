package transactionsDefinition

import (
	"strings"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// Rendering a transaction must never bring the process down. The Web UI panicked
// with "slice bounds out of range [:20] with length 0" on an ordinary transfer:
// a transaction that carries no public key holds an EMPTY byte slice once it has
// been through JSON, which is not nil, so it passed the nil check and reached a
// fixed-width truncation of a shorter string.
func TestGetStringHandlesAKeylessTransaction(t *testing.T) {
	cases := map[string]common.PubKey{
		"no key at all":       {},
		"empty but not nil":   {ByteValue: []byte{}},
		"shorter than the cut": {ByteValue: []byte{0x01, 0x02}},
	}
	for name, pk := range cases {
		t.Run(name, func(t *testing.T) {
			td := TxData{Recipient: common.Address{}, Amount: 1, Pubkey: pk}
			got := td.GetString() // must not panic
			if !strings.Contains(got, "Recipient:") {
				t.Fatalf("rendering produced nothing usable: %q", got)
			}
		})
	}
}

func TestHexPrefixNeverPanicsAndMarksTruncation(t *testing.T) {
	if got := common.HexPrefix("", 20); got != "" {
		t.Fatalf("empty input returned %q", got)
	}
	if got := common.HexPrefix("abc", 20); got != "abc" {
		t.Fatalf("a short string was altered: %q", got)
	}
	if got := common.HexPrefix("abcdef", 3); got != "abc..." {
		t.Fatalf("truncation is not marked: %q", got)
	}
}

// A transaction with no public key must not display an address at all. The
// decoder calls PubKey.Init even with an empty key, and Init hashes whatever it
// is given, so the struct ends up holding the address of an empty key —
// 3345524abf6bbe1809449224b5972c41790b6cf2, identical on every keyless
// transaction. Printed beside a transfer it reads like a third party to it.
func TestKeylessTransactionShowsNoDerivedAddress(t *testing.T) {
	empty := common.PubKey{}
	if err := empty.Init([]byte{}, common.Address{}); err != nil {
		t.Skipf("cannot reproduce the decoder's call: %v", err)
	}
	if empty.Address.GetHex() == "" {
		t.Skip("Init left the address unset; nothing to hide")
	}

	td := TxData{Amount: 1, Pubkey: empty}
	got := td.GetString()
	if strings.Contains(got, empty.Address.GetHex()) {
		t.Fatalf("the address of an empty key is still displayed:\n%s", got)
	}
}

// PubKey.Init must refuse a key too short to be one. The check it replaced was
// dead — it additionally required both schemes to be unpaused, which the
// single-active-scheme model makes impossible — so Init accepted any length,
// including empty, and derived an address from it.
func TestPubKeyInitRejectsImpossiblyShortKeys(t *testing.T) {
	for _, n := range []int{0, 1, 20} {
		pk := common.PubKey{}
		if err := pk.Init(make([]byte, n), common.Address{}); err == nil {
			t.Fatalf("a %d-byte public key was accepted", n)
		}
		var zero common.Address
		if pk.Address.GetHex() != zero.GetHex() {
			t.Fatalf("a rejected %d-byte key still produced an address: %s", n, pk.Address.GetHex())
		}
	}
	// A real key must still be accepted; rejecting one would break decoding.
	realKey := make([]byte, common.PubKeyLength(false))
	pk := common.PubKey{}
	if err := pk.Init(realKey, common.Address{}); err != nil {
		t.Fatalf("a key of the primary scheme's length was rejected: %v", err)
	}
	if !pk.Primary {
		t.Fatal("a key of the primary length was not marked primary")
	}
}
