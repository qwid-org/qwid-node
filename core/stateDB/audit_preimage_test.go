package stateDB

import (
	"strings"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// Audit 2026-11-12 F-EVM-01: keccak preimages are not part of the persisted
// EVM state, and a snapshot written before the fix sheds them when loaded.
func TestSnapshotCarriesNoPreimages(t *testing.T) {
	sa := CreateStateDB()
	sa.States[common.Hash{1}] = []byte("preimage-bytes")
	b, err := sa.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"states":{"`) {
		t.Fatalf("snapshot still carries preimages: %s", b)
	}
	old := `{"accounts":{},"codes":{},"codeHashes":{},"statesHashes":{},"nonces":{},` +
		`"states":{"0100000000000000000000000000000000000000000000000000000000000000":"cHJlaW1hZ2U="},"balances":{},"tokens":{}}`
	loaded := CreateStateDB()
	if err := loaded.Unmarshal([]byte(old)); err != nil {
		t.Fatal(err)
	}
	if len(loaded.States) != 0 {
		t.Fatalf("an old snapshot's %d preimages were loaded", len(loaded.States))
	}
}
