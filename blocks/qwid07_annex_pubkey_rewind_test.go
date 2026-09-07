package blocks

import (
	"path/filepath"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/pubkeys"
)

// registerTestKey stores a secondary key under a distinct identity and journals
// it at the given height, exactly as ProcessBlockPubKey does for a new
// registration. Returns the key's derived address.
func registerTestKey(t *testing.T, identityByte, keyByte byte, height int64) (common.Address, common.Address) {
	t.Helper()
	var identity common.Address
	idb := make([]byte, common.AddressLength)
	for i := range idb {
		idb[i] = identityByte
	}
	if err := identity.Init(idb); err != nil {
		t.Fatalf("build identity: %v", err)
	}

	kb := make([]byte, common.PubKeyLength2(false))
	for i := range kb {
		kb[i] = keyByte
	}
	pk := common.PubKey{Primary: false, MainAddress: identity}
	if err := pk.Init(kb, identity); err != nil {
		t.Skipf("cannot build secondary pubkey for active scheme: %v", err)
	}
	derived, err := common.PubKeyToAddress(pk.GetBytes(), pk.Primary)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	if err := StorePubKey(pk); err != nil {
		t.Fatalf("StorePubKey: %v", err)
	}
	if err := StorePubKeyInPatriciaTrie(pk); err != nil {
		t.Fatalf("StorePubKeyInPatriciaTrie: %v", err)
	}
	journalPubKeyRegistration(height, derived, identity)
	return identity, derived
}

// TestQWID07Annex_RewindUndoesPubKeyRegistration verifies that unregistering the
// registrations journalled at a height removes exactly those keys (record +
// identity trie + journal entry), and leaves registrations at other heights
// untouched (QWID-2026-07 annex).
func TestQWID07Annex_RewindUndoesPubKeyRegistration(t *testing.T) {
	db := &database.BlockchainDB{}
	pdb, err := db.InitPermanent(filepath.Join(t.TempDir(), "blockchain"))
	if err != nil {
		t.Skipf("RocksDB unavailable: %v", err)
	}
	savedDB, savedTrie := database.MainDB, pubkeys.GlobalMerkleTree
	database.MainDB = pdb
	pubkeys.InitPermanentTrie()
	t.Cleanup(func() {
		pdb.Close()
		database.MainDB, pubkeys.GlobalMerkleTree = savedDB, savedTrie
	})

	// A key registered at the canonical height 5, and one at the forked height 9.
	idCanon, derivedCanon := registerTestKey(t, 0x11, 0x22, 5)
	idFork, derivedFork := registerTestKey(t, 0x33, 0x44, 9)

	// Both are present before the rewind.
	if _, err := pubkeys.LoadPubKey(derivedCanon.GetBytes()); err != nil {
		t.Fatalf("canonical key should be registered: %v", err)
	}
	if _, err := pubkeys.LoadPubKey(derivedFork.GetBytes()); err != nil {
		t.Fatalf("forked key should be registered: %v", err)
	}

	// Rewind removes the block at height 9: only the forked key must disappear.
	UnregisterPubKeysAtHeight(9)

	if _, err := pubkeys.LoadPubKey(derivedFork.GetBytes()); err == nil {
		t.Fatal("forked key must be unregistered after rewinding its height")
	}
	if _, err := pubkeys.LoadAddresses(idFork); err == nil {
		t.Fatal("forked identity's trie must be gone (its only key was removed)")
	}
	// The journal entry for height 9 must be cleared.
	if keys, _ := database.MainDB.LoadAllKeys(append(common.PubKeyRegistrationJournalDBPrefix[:], common.GetByteInt64(9)...)); len(keys) != 0 {
		t.Fatalf("journal at height 9 should be empty, got %d entries", len(keys))
	}

	// The canonical key at height 5 must be untouched.
	if _, err := pubkeys.LoadPubKey(derivedCanon.GetBytes()); err != nil {
		t.Fatalf("canonical key must survive a rewind of a different height: %v", err)
	}
	addrs, err := pubkeys.LoadAddresses(idCanon)
	if err != nil {
		t.Fatalf("canonical identity trie must survive: %v", err)
	}
	found := false
	for _, a := range addrs {
		if a.GetBytes() != nil && a == derivedCanon {
			found = true
		}
	}
	if !found {
		t.Fatal("canonical identity must still list its key after the unrelated rewind")
	}
}
