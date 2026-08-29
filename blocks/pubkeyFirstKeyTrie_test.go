package blocks

import (
	"path/filepath"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/pubkeys"
)

// A key that does NOT derive the identity it is registered under must still be
// storable as that identity's FIRST key.
//
// Transaction verification already accepts this: its bootstrap rule lets a
// non-primary key name an identity it does not derive, so long as
// pk.MainAddress is the sender. Application used to disagree — it sent every
// first key through CreateAddressFromFirstPubKey, which bootstraps the identity
// *out of* the key bytes and so demands derived == MainAddress. A block
// carrying such a registration was therefore accepted into the chain and then
// refused when applied, and the node rewound and retried it forever.
//
// The retry also failed with a *different* error than the first attempt,
// because the helper stored the derived-address trie before its caller checked
// the identity matched. The second assertion below pins that down: registering
// twice must stay clean, so a rewind-and-reapply cannot poison the state.
func TestFirstKeyNeedNotDeriveItsIdentity(t *testing.T) {
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

	// An identity with no trie at all, and a secondary key whose own derived
	// address is necessarily different from it.
	identity := common.Address{}
	if err := identity.Init([]byte{0x2b, 0x74, 0xca, 0x4e, 0x12, 0xf8, 0x3e, 0xa0, 0xc6, 0x17,
		0x38, 0x3e, 0x45, 0x90, 0x9d, 0x52, 0xa6, 0x01, 0xec, 0xd4}); err != nil {
		t.Fatalf("could not build the identity address: %v", err)
	}

	pk := common.PubKey{Primary: false, MainAddress: identity}
	if err := pk.Init(make([]byte, common.PubKeyLength2(false)), identity); err != nil {
		t.Skipf("cannot build a secondary pubkey for the active scheme: %v", err)
	}

	derived, err := common.PubKeyToAddress(pk.GetBytes(), pk.Primary)
	if err != nil {
		t.Fatalf("could not derive the key address: %v", err)
	}
	if derived == identity {
		t.Fatalf("test is void: the key derives the identity it names")
	}

	if err := StorePubKeyInPatriciaTrie(pk); err != nil {
		t.Fatalf("first registration was refused: %v", err)
	}

	addrs, err := pubkeys.LoadAddresses(identity)
	if err != nil {
		t.Fatalf("the identity has no trie after registration: %v", err)
	}
	found := false
	for _, a := range addrs {
		if a == derived {
			found = true
		}
	}
	if !found {
		t.Fatalf("the key's address %s is not recorded under identity %s", derived.GetHex(), identity.GetHex())
	}

	// Re-applying the same block must not fail: a rewind replays it.
	if err := StorePubKeyInPatriciaTrie(pk); err != nil {
		t.Fatalf("re-applying the same registration failed: %v", err)
	}
}
