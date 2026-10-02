package blocks

import (
	"path/filepath"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/pubkeys"
)

func withTempRegistry(t *testing.T) {
	t.Helper()
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
}

func testIdentity(t *testing.T, b byte) common.Address {
	t.Helper()
	var a common.Address
	raw := make([]byte, common.AddressLength)
	for i := range raw {
		raw[i] = b
	}
	if err := a.Init(raw); err != nil {
		t.Fatalf("build identity: %v", err)
	}
	return a
}

// testKey builds a key of the active scheme for the slot, naming identity and
// carrying its derived address, as ProcessBlockPubKey hands it on.
func testKey(t *testing.T, identity common.Address, keyByte byte, primary bool) common.PubKey {
	t.Helper()
	n := common.PubKeyLength2(false)
	if primary {
		n = common.PubKeyLength(false)
	}
	kb := make([]byte, n)
	for i := range kb {
		kb[i] = keyByte
	}
	derived, err := common.PubKeyToAddress(kb, primary)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	pk := common.PubKey{Primary: primary}
	if err := pk.Init(kb, derived); err != nil {
		t.Skipf("cannot build pubkey for active scheme: %v", err)
	}
	pk.Primary = primary
	pk.Address = derived
	pk.MainAddress = identity
	return pk
}

func TestS306_RegistryAnswersAsOfHeight(t *testing.T) {
	withTempRegistry(t)
	id := testIdentity(t, 0x11)
	pk := testKey(t, id, 0x22, false)
	if err := registerPubKeyAtHeight(pk, 5); err != nil {
		t.Fatalf("register: %v", err)
	}
	d := pk.Address.GetBytes()
	if h := pubkeys.RegistrationHeight(d); h != 5 {
		t.Fatalf("registration height = %d, want 5", h)
	}
	if _, err := pubkeys.LoadPubKeyAsOf(d, 4); err == nil {
		t.Fatal("key registered at 5 must not exist as of 4")
	}
	if _, err := pubkeys.LoadAddressesAsOf(id, 4); err == nil {
		t.Fatal("identity must have no keys as of 4")
	}
	if _, err := pubkeys.LoadPubKeyAsOf(d, 5); err != nil {
		t.Fatalf("key must exist as of its own height: %v", err)
	}
	if _, err := pubkeys.LoadPubKeyWithPrimaryOfLengthAsOf(id, false, len(pk.GetBytes()), 4); err == nil {
		t.Fatal("length-matched lookup must honour the height too")
	}
	if _, err := pubkeys.LoadPubKeyWithPrimaryOfLength(id, false, len(pk.GetBytes())); err != nil {
		t.Fatalf("the unlimited reader must see the key: %v", err)
	}
}

// A duplicate registration in a later block keeps the original height and
// writes no journal entry, so rewinding the later block keeps the key.
func TestS306_DuplicateRegistrationKeepsOriginalHeight(t *testing.T) {
	withTempRegistry(t)
	id := testIdentity(t, 0x33)
	pk := testKey(t, id, 0x44, false)
	if err := registerPubKeyAtHeight(pk, 5); err != nil {
		t.Fatalf("register at 5: %v", err)
	}
	if err := registerPubKeyAtHeight(pk, 9); err != nil {
		t.Fatalf("re-register at 9: %v", err)
	}
	if h := pubkeys.RegistrationHeight(pk.Address.GetBytes()); h != 5 {
		t.Fatalf("registration height = %d after a duplicate, want 5", h)
	}
	if keys, _ := database.MainDB.LoadAllKeys(append(common.PubKeyRegistrationJournalDBPrefix[:], common.GetByteInt64(9)...)); len(keys) != 0 {
		t.Fatalf("a duplicate must not be journalled, got %d entries at 9", len(keys))
	}
	UnregisterPubKeysAboveHeight(7, 9)
	if _, err := pubkeys.LoadPubKey(pk.Address.GetBytes()); err != nil {
		t.Fatalf("rewinding the duplicate's block must keep the canonical key: %v", err)
	}
}

func TestS306_RewindDropsRegistrationHeight(t *testing.T) {
	withTempRegistry(t)
	id := testIdentity(t, 0x55)
	pk := testKey(t, id, 0x66, false)
	if err := registerPubKeyAtHeight(pk, 9); err != nil {
		t.Fatalf("register: %v", err)
	}
	UnregisterPubKeysAtHeight(9)
	if ok, _ := database.MainDB.IsKey(append(common.PubKeyRegistrationHeightDBPrefix[:], pk.Address.GetBytes()...)); ok {
		t.Fatal("the registration height must go with the key")
	}
	// Registered again later, the key gets its new height, not genesis.
	if err := registerPubKeyAtHeight(pk, 12); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if h := pubkeys.RegistrationHeight(pk.Address.GetBytes()); h != 12 {
		t.Fatalf("registration height = %d, want 12", h)
	}
}

// Operational staking needs both keys registered by the PARENT block: a key
// registered in the block being applied does not count yet.
func TestS306_OperatorKeysAsOfParent(t *testing.T) {
	withTempRegistry(t)
	id := testIdentity(t, 0x77)
	if err := registerPubKeyAtHeight(testKey(t, id, 0x01, true), 2); err != nil {
		t.Fatalf("register primary: %v", err)
	}
	if err := registerPubKeyAtHeight(testKey(t, id, 0x02, false), 6); err != nil {
		t.Fatalf("register secondary: %v", err)
	}
	if pubkeys.HasOperatorKeysAsOf(id, 5) {
		t.Fatal("secondary key registered at 6 must not count as of 5")
	}
	if !pubkeys.HasOperatorKeysAsOf(id, 6) {
		t.Fatal("both keys exist as of 6")
	}
	if !pubkeys.HasOperatorKeysAsOf(id, pubkeys.NoHeightLimit) {
		t.Fatal("both keys exist now")
	}
}
