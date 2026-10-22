package genesis

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
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

func newPubKeyHex(t *testing.T, sigName string) string {
	t.Helper()
	var s oqs.Signature
	defer s.Clean()
	if err := s.Init(sigName, nil); err != nil {
		t.Skipf("liboqs unavailable: %v", err)
	}
	pub, err := s.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(pub)
}

// The operator's (or a staker's) genesis spare must end up exactly where a
// block-carried registration puts it: in the owner's key list, with a record
// naming the owner - so the dual-key rule counts it and Verify resolves it to
// the owner.
func TestGenesisSecondaryKeyJoinsTheOwnersIdentity(t *testing.T) {
	withTempRegistry(t)
	owner := storeGenesisPubKey(newPubKeyHex(t, common.SigName()), true).Address

	if pubkeys.HasOperatorKeysAsOf(owner, 0) {
		t.Fatal("owner holds both keys before its spare is registered")
	}
	spare, err := storeGenesisSecondaryKey(newPubKeyHex(t, common.SigName2()), owner)
	if err != nil {
		t.Fatal(err)
	}
	if !pubkeys.HasOperatorKeysAsOf(owner, 0) {
		t.Fatal("the genesis spare does not count towards the owner's two keys")
	}
	rec, err := pubkeys.LoadPubKeyAsOf(spare.Address.GetBytes(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if rec.MainAddress != owner {
		t.Fatalf("spare record names %s, want the owner %s", rec.MainAddress.GetHex(), owner.GetHex())
	}
	if _, err := pubkeys.LoadAddresses(spare.Address); err == nil {
		t.Fatal("the spare opened an identity of its own")
	}
	// Listing the same key twice (operator_pub_key_2 and the operator's
	// staking pub_key_2) is harmless.
	if _, err := storeGenesisSecondaryKey(hex.EncodeToString(spare.GetBytes()), owner); err != nil {
		t.Fatalf("re-registering the same spare failed: %v", err)
	}
}

func TestGenesisSecondaryKeyRejectsWrongLength(t *testing.T) {
	withTempRegistry(t)
	owner := storeGenesisPubKey(newPubKeyHex(t, common.SigName()), true).Address
	if _, err := storeGenesisSecondaryKey(newPubKeyHex(t, common.SigName()), owner); err == nil {
		t.Fatal("a primary-scheme key was accepted as operator_pub_key_2")
	}
}

// Configs without the field keep their digest, so their signatures stay
// valid; a config that sets it is covered by the digest like any other field.
func TestOperatorPubKey2OmittedKeepsDigest(t *testing.T) {
	g := Genesis{ChainID: 23, OperatorPubKey: "aa"}
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("operator_pub_key_2")) {
		t.Fatal("an unset operator_pub_key_2 enters the digested JSON and would invalidate signed configs")
	}
	d0, _ := GenesisConfigDigest(g)
	g.OperatorPubKey2 = "bb"
	if d1, _ := GenesisConfigDigest(g); d0 == d1 {
		t.Fatal("operator_pub_key_2 is not covered by the genesis digest")
	}
}
