package stateDB

import (
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
)

func sampleState() StateAccount {
	sa := CreateStateDB()
	var a [common.AddressLength]byte
	a[0] = 0xAB
	sa.Accounts[a] = account.Account{Balance: 12345}
	sa.Codes[a] = []byte{0x60, 0x00, 0x60, 0x00}
	sa.CodeHashes[a] = common.Hash{0x11}
	sa.Nonces[a] = 7
	sa.StatesHashes[a] = map[common.Hash]common.Hash{{0x01}: {0x02}}
	sa.States[common.Hash{0x03}] = []byte{0xDE, 0xAD, 0xBE, 0xEF}
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
	if got.Accounts[a].Balance != 12345 {
		t.Fatalf("account balance mismatch: %d", got.Accounts[a].Balance)
	}
	if string(got.Codes[a]) != string(sa.Codes[a]) {
		t.Fatal("code mismatch")
	}
	if got.CodeHashes[a] != (common.Hash{0x11}) {
		t.Fatalf("code hash mismatch: %v", got.CodeHashes[a])
	}
	if got.Nonces[a] != 7 {
		t.Fatalf("nonce mismatch: %d", got.Nonces[a])
	}
	if got.StatesHashes[a][common.Hash{0x01}] != (common.Hash{0x02}) {
		t.Fatal("storage slot mismatch")
	}
	if string(got.States[common.Hash{0x03}]) != string([]byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Fatalf("states mismatch: %v", got.States[common.Hash{0x03}])
	}
	if got.Balances[a][a] != 500 {
		t.Fatal("token balance mismatch")
	}
	if got.Tokens[a].Symbols != "TK" {
		t.Fatal("token info mismatch")
	}
}

func TestStoreAndLoadEVMState(t *testing.T) {
	// Requires database.MainDB to be initialized by the test harness; skip if not.
	sa := sampleState()
	if err := sa.Store(5); err != nil {
		t.Skipf("DB not available in this test context: %v", err)
	}
	var loaded StateAccount
	loaded = CreateStateDB()
	if err := loaded.Load(5); err != nil {
		t.Fatalf("Load: %v", err)
	}
	var a [common.AddressLength]byte
	a[0] = 0xAB
	if loaded.Nonces[a] != 7 {
		t.Fatalf("nonce not persisted: %d", loaded.Nonces[a])
	}
}
