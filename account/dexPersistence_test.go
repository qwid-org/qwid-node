package account

import (
	"path/filepath"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
)

func withDexTestDB(t *testing.T) {
	t.Helper()
	db := &database.BlockchainDB{}
	pdb, err := db.InitPermanent(filepath.Join(t.TempDir(), "blockchain"))
	if err != nil {
		t.Skipf("RocksDB unavailable: %v", err)
	}
	savedDB, savedDex := database.MainDB, DexAccounts
	database.MainDB = pdb
	t.Cleanup(func() {
		pdb.Close()
		database.MainDB, DexAccounts = savedDB, savedDex
	})
	DexAccounts = DexAccountsType{AllDexAccounts: map[[common.AddressLength]byte]DexAccount{}}
}

func dexPersistAddr(seed byte) [common.AddressLength]byte {
	var a [common.AddressLength]byte
	for i := range a {
		a[i] = seed + byte(i)
	}
	return a
}

// The restart cycle that QWID-2026-12 broke. DEX pools are consensus state,
// yet no accepted block ever stored them and the shutdown write went to the
// un-loadable literal height -1 — so every restart reverted the DEX to
// genesis while the rest of the network kept the live values, and the same
// swap then produced different reserves on different nodes.
func TestDexStateSurvivesTheStoreLoadCycle(t *testing.T) {
	withDexTestDB(t)

	// Genesis snapshot at 0, like cmd/mining does.
	if err := StoreDexAccounts(0); err != nil {
		t.Fatalf("genesis store failed: %v", err)
	}

	// DEX activity at height 41.
	a := dexPersistAddr(0x11)
	DexAccounts.AllDexAccounts[a] = DexAccount{TokenAddress: common.Address{ByteValue: a}, TokenPool: 777, CoinPool: 999}
	if err := StoreDexAccounts(41); err != nil {
		t.Fatalf("store at height failed: %v", err)
	}

	// "Restart": wipe memory, load like startup does (-1 = newest stored).
	DexAccounts = DexAccountsType{AllDexAccounts: map[[common.AddressLength]byte]DexAccount{}}
	if err := LoadDexAccounts(-1); err != nil {
		t.Fatalf("startup load failed: %v", err)
	}
	got, ok := DexAccounts.AllDexAccounts[a]
	if !ok || got.TokenPool != 777 || got.CoinPool != 999 {
		t.Fatalf("restart lost the DEX state: got %+v ok=%v — the node would resume from genesis pools", got, ok)
	}
}

// A rewind target between two snapshots must resolve to the newest snapshot at
// or below it — never above, which would resurrect state the chain no longer
// contains, and never genesis, which was the old failure.
func TestDexLoadFallsBackDownwardsOnly(t *testing.T) {
	withDexTestDB(t)

	a := dexPersistAddr(0x22)
	if err := StoreDexAccounts(0); err != nil {
		t.Fatal(err)
	}
	DexAccounts.AllDexAccounts[a] = DexAccount{TokenAddress: common.Address{ByteValue: a}, TokenPool: 5}
	if err := StoreDexAccounts(20); err != nil {
		t.Fatal(err)
	}
	DexAccounts.AllDexAccounts[a] = DexAccount{TokenAddress: common.Address{ByteValue: a}, TokenPool: 6}
	if err := StoreDexAccounts(40); err != nil {
		t.Fatal(err)
	}

	// Rewind to 25: nothing stored there; 20 is the right answer, 40 is not.
	DexAccounts = DexAccountsType{AllDexAccounts: map[[common.AddressLength]byte]DexAccount{}}
	if err := LoadDexAccounts(25); err != nil {
		t.Fatalf("load at a gap height failed: %v", err)
	}
	if got := DexAccounts.AllDexAccounts[a].TokenPool; got != 5 {
		t.Fatalf("gap load returned pool %d, expected the height-20 snapshot (5)", got)
	}
}

// The shutdown path passes -1; the old code wrote a key encoding literal -1
// that no loader could ever select. Now it must land on the current height.
func TestDexStoreNormalizesNegativeHeight(t *testing.T) {
	withDexTestDB(t)
	savedH := common.GetHeight()
	common.SetHeight(73)
	t.Cleanup(func() { common.SetHeight(savedH) })

	a := dexPersistAddr(0x33)
	DexAccounts.AllDexAccounts[a] = DexAccount{TokenAddress: common.Address{ByteValue: a}, CoinPool: 12}
	if err := StoreDexAccounts(-1); err != nil {
		t.Fatalf("shutdown-style store failed: %v", err)
	}

	DexAccounts = DexAccountsType{AllDexAccounts: map[[common.AddressLength]byte]DexAccount{}}
	if err := LoadDexAccounts(73); err != nil {
		t.Fatalf("load at the current height failed: %v", err)
	}
	if DexAccounts.AllDexAccounts[a].CoinPool != 12 {
		t.Fatal("the shutdown snapshot did not land at the current height")
	}
}
