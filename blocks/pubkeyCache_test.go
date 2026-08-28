package blocks

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/pubkeys"
)

func withPubKeyCacheDB(t *testing.T) {
	t.Helper()
	db := &database.BlockchainDB{}
	pdb, err := db.InitPermanent(filepath.Join(t.TempDir(), "blockchain"))
	if err != nil {
		t.Skipf("RocksDB unavailable: %v", err)
	}
	saved := database.MainDB
	database.MainDB = pdb
	t.Cleanup(func() {
		pdb.Close()
		database.MainDB = saved
	})
}

func identity(t *testing.T, seed byte) common.Address {
	t.Helper()
	b := make([]byte, common.AddressLength)
	for i := range b {
		b[i] = seed + byte(i)
	}
	a := common.Address{}
	if err := a.Init(b); err != nil {
		t.Fatalf("could not build an address: %v", err)
	}
	return a
}

// The cache must never outlive the record it copied. A re-registration writes a
// new record under the SAME address — the address derives from the key bytes,
// so only the metadata can differ — and a reader that already populated the
// cache must see the new metadata, not the decode it took earlier.
func TestPubKeyCacheReflectsAReWrite(t *testing.T) {
	withPubKeyCacheDB(t)

	first, second := identity(t, 0x10), identity(t, 0x50)
	keyBytes := make([]byte, common.PubKeyLength(false))
	for i := range keyBytes {
		keyBytes[i] = byte(i % 251)
	}
	addr, err := common.PubKeyToAddress(keyBytes, true)
	if err != nil {
		t.Fatalf("cannot derive the key address: %v", err)
	}

	pk := common.PubKey{ByteValue: keyBytes, Address: addr, MainAddress: first, Primary: true}
	if err := StorePubKey(pk); err != nil {
		t.Fatalf("first store failed: %v", err)
	}
	got, err := pubkeys.LoadPubKey(addr.GetBytes())
	if err != nil {
		t.Fatalf("first load failed: %v", err)
	}
	if got.MainAddress.GetHex() != first.GetHex() {
		t.Fatalf("first load returned identity %s, expected %s", got.MainAddress.GetHex(), first.GetHex())
	}

	pk.MainAddress = second
	if err := StorePubKey(pk); err != nil {
		t.Fatalf("second store failed: %v", err)
	}
	got, err = pubkeys.LoadPubKey(addr.GetBytes())
	if err != nil {
		t.Fatalf("second load failed: %v", err)
	}
	if got.MainAddress.GetHex() != second.GetHex() {
		t.Fatalf("load served a stale cached record: identity %s, expected %s",
			got.MainAddress.GetHex(), second.GetHex())
	}
}

// A caller holding a loaded key must not be able to corrupt what everyone else
// reads. Verification passes these bytes straight into liboqs, so a shared
// slice would turn one careless caller into a chain-wide verification failure.
func TestPubKeyCacheIsolatesCallers(t *testing.T) {
	withPubKeyCacheDB(t)

	keyBytes := make([]byte, common.PubKeyLength(false))
	for i := range keyBytes {
		keyBytes[i] = byte(i % 241)
	}
	addr, err := common.PubKeyToAddress(keyBytes, true)
	if err != nil {
		t.Fatalf("cannot derive the key address: %v", err)
	}
	if err := StorePubKey(common.PubKey{
		ByteValue: keyBytes, Address: addr, MainAddress: identity(t, 0x20), Primary: true,
	}); err != nil {
		t.Fatalf("store failed: %v", err)
	}

	first, err := pubkeys.LoadPubKey(addr.GetBytes())
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	first.GetBytes()[0] ^= 0xFF

	second, err := pubkeys.LoadPubKey(addr.GetBytes())
	if err != nil {
		t.Fatalf("second load failed: %v", err)
	}
	if !bytes.Equal(second.GetBytes(), keyBytes) {
		t.Fatal("a caller's mutation reached the next reader's key")
	}
}
