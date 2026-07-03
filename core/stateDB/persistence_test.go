package stateDB

import (
	"testing"

	"github.com/wonabru/qwid-node/common"
)

func sampleState() StateAccount {
	sa := CreateStateDB()
	var a [common.AddressLength]byte
	a[0] = 0xAB
	sa.Codes[a] = []byte{0x60, 0x00, 0x60, 0x00}
	sa.CodeHashes[a] = common.Hash{0x11}
	sa.Nonces[a] = 7
	sa.StatesHashes[a] = map[common.Hash]common.Hash{{0x01}: {0x02}}
	sa.Balances[a] = map[[common.AddressLength]byte]int64{a: 500}
	sa.Tokens[a] = TokenInfo{Name: "Tok", Symbols: "TK", Decimals: 8}
	return sa
}

func TestStateMarshalRoundTrip(t *testing.T) {
	sa := sampleState()
	b, err := sa.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got StateAccount
	got = CreateStateDB()
	if err := got.Unmarshal(b); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	var a [common.AddressLength]byte
	a[0] = 0xAB
	if string(got.Codes[a]) != string(sa.Codes[a]) {
		t.Fatal("code mismatch")
	}
	if got.Nonces[a] != 7 {
		t.Fatalf("nonce mismatch: %d", got.Nonces[a])
	}
	if got.StatesHashes[a][common.Hash{0x01}] != (common.Hash{0x02}) {
		t.Fatal("storage slot mismatch")
	}
	if got.Balances[a][a] != 500 {
		t.Fatal("token balance mismatch")
	}
	if got.Tokens[a].Symbols != "TK" {
		t.Fatal("token info mismatch")
	}
}
