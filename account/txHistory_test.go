package account

import (
	"path/filepath"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
)

// withHistoryTempDB points database.MainDB at a throwaway RocksDB so these
// tests never touch the operator's real blockchain database.
func withHistoryTempDB(t *testing.T) {
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

// withFreshAccounts swaps the global account map and restores it afterwards.
func withFreshAccounts(t *testing.T) {
	t.Helper()
	AccountsRWMutex.Lock()
	saved := Accounts
	Accounts = AccountsType{AllAccounts: map[[common.AddressLength]byte]Account{}}
	AccountsRWMutex.Unlock()
	t.Cleanup(func() {
		AccountsRWMutex.Lock()
		Accounts = saved
		AccountsRWMutex.Unlock()
	})
}

func hashOf(b byte) common.Hash {
	h := common.Hash{}
	h[0] = b
	return h
}

// TestOldSnapshotDecodesWithDerivedCounts: a pre-index account blob ends right
// after the history lists. Decoding it must fill the lists AND derive the
// counters from their lengths, or migration would write a zero-length history.
func TestOldSnapshotDecodesWithDerivedCounts(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	a := Account{Balance: 77}
	a.Address[0] = 0xAA
	a.TransactionsSender = []common.Hash{hashOf(1), hashOf(2)}
	a.TransactionsRecipient = []common.Hash{hashOf(3)}
	a.SentCount, a.ReceivedCount = 2, 1

	// The old format is exactly the new one minus the two trailing counters.
	oldBlob := a.Marshal()
	oldBlob = oldBlob[:len(oldBlob)-16]

	decoded := Account{}
	if err := decoded.Unmarshal(oldBlob); err != nil {
		t.Fatalf("Unmarshal starego formatu: %v", err)
	}
	if decoded.SentCount != 2 || decoded.ReceivedCount != 1 {
		t.Fatalf("counters = %d/%d, expected 2/1 (derived from the list lengths)",
			decoded.SentCount, decoded.ReceivedCount)
	}
	if len(decoded.TransactionsSender) != 2 || len(decoded.TransactionsRecipient) != 1 {
		t.Fatal("the old-format lists were not read")
	}

	// New-format round trip carries the counters explicitly.
	slim := Account{Balance: 77, SentCount: 9, ReceivedCount: 4}
	decoded2 := Account{}
	if err := decoded2.Unmarshal(slim.Marshal()); err != nil {
		t.Fatalf("Unmarshal nowego formatu: %v", err)
	}
	if decoded2.SentCount != 9 || decoded2.ReceivedCount != 4 {
		t.Fatalf("new-format counters = %d/%d, expected 9/4", decoded2.SentCount, decoded2.ReceivedCount)
	}
}

// TestMigrationMovesListsToIndex: loading a pre-index snapshot must move the
// in-state history to the DB index, clear the lists, and leave the next stored
// snapshot slim.
func TestMigrationMovesListsToIndex(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withHistoryTempDB(t)
	withFreshAccounts(t)

	addr := [common.AddressLength]byte{0xBB}
	AccountsRWMutex.Lock()
	Accounts.AllAccounts[addr] = Account{
		Address:               addr,
		Balance:               5,
		TransactionsSender:    []common.Hash{hashOf(1), hashOf(2), hashOf(3)},
		TransactionsRecipient: []common.Hash{hashOf(4)},
		SentCount:             3,
		ReceivedCount:         1,
	}
	AccountsRWMutex.Unlock()

	// Store writes the lists (pre-index shape), then LoadAccounts migrates.
	if err := StoreAccounts(11); err != nil {
		t.Fatalf("StoreAccounts: %v", err)
	}
	if err := LoadAccounts(11); err != nil {
		t.Fatalf("LoadAccounts: %v", err)
	}

	acc, ok := GetAccountByAddressBytes(addr[:])
	if !ok {
		t.Fatal("the account disappeared after migration")
	}
	if len(acc.TransactionsSender) != 0 || len(acc.TransactionsRecipient) != 0 {
		t.Fatal("the in-state lists were not cleared after migration")
	}
	if acc.SentCount != 3 || acc.ReceivedCount != 1 {
		t.Fatalf("counters after migration = %d/%d, expected 3/1", acc.SentCount, acc.ReceivedCount)
	}
	sent := GetTxHistorySent(addr, 0)
	if len(sent) != 3 || sent[0] != hashOf(1) || sent[2] != hashOf(3) {
		t.Fatalf("sent index after migration = %v", sent)
	}
	if recv := GetTxHistoryReceived(addr, 0); len(recv) != 1 || recv[0] != hashOf(4) {
		t.Fatalf("indeks odebranych po migracji = %v", recv)
	}

	// The next snapshot no longer carries the history.
	if err := StoreAccounts(12); err != nil {
		t.Fatalf("StoreAccounts(12): %v", err)
	}
	if err := LoadAccounts(12); err != nil {
		t.Fatalf("LoadAccounts(12): %v", err)
	}
	acc, _ = GetAccountByAddressBytes(addr[:])
	if acc.SentCount != 3 || len(GetTxHistorySent(addr, 0)) != 3 {
		t.Fatal("historia zgubiona po ponownym zapisie odchudzonego snapshotu")
	}
}

// TestHistoryRollbackByCounter: a rewind restores an older counter; re-applied
// transactions must overwrite the index tail in place, and readers must never
// see past the counter.
func TestHistoryRollbackByCounter(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withHistoryTempDB(t)
	withFreshAccounts(t)

	addr := [common.AddressLength]byte{0xCC}
	AccountsRWMutex.Lock()
	Accounts.AllAccounts[addr] = Account{Address: addr}
	AccountsRWMutex.Unlock()

	AddTransactionsSender(addr, hashOf(1))
	AddTransactionsSender(addr, hashOf(2))
	AddTransactionsSender(addr, hashOf(3))

	// Rewind: the snapshot restored a counter of 1.
	AccountsRWMutex.Lock()
	acc := Accounts.AllAccounts[addr]
	acc.SentCount = 1
	Accounts.AllAccounts[addr] = acc
	AccountsRWMutex.Unlock()

	if got := GetTxHistorySent(addr, 0); len(got) != 1 || got[0] != hashOf(1) {
		t.Fatalf("after the rewind the visible history = %v, expected entry 1 only", got)
	}

	// Re-apply a different fork: entry at seq 1 must be overwritten.
	AddTransactionsSender(addr, hashOf(9))
	got := GetTxHistorySent(addr, 0)
	if len(got) != 2 || got[1] != hashOf(9) {
		t.Fatalf("after re-applying, history = %v, expected [1 9]", got)
	}
}

// TestLastStoredHeightMetaSurvivesGaps: snapshots stored once per batch leave
// height gaps; the meta key must report the true maximum, and the rewind's
// lowering must take effect. The contiguity-searching fallback broke exactly
// here - after the first gap it reported the last pre-gap height and a
// restarted node loaded stale balances.
func TestLastStoredHeightMetaSurvivesGaps(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withHistoryTempDB(t)
	withFreshAccounts(t)

	for _, h := range []int64{0, 1, 2, 34, 66} { // contiguous run, then batch gaps
		if err := StoreAccounts(h); err != nil {
			t.Fatalf("StoreAccounts(%d): %v", h, err)
		}
	}
	if h, err := LastHeightStoredInAccounts(); err != nil || h != 66 {
		t.Fatalf("LastHeightStoredInAccounts = %d, %v; expected 66 despite the gaps", h, err)
	}

	// The rewind removed everything above 34 and lowered the record.
	SetLastStoredSnapshotHeights(34)
	if h, err := LastHeightStoredInAccounts(); err != nil || h != 34 {
		t.Fatalf("after lowering, LastHeightStoredInAccounts = %d, %v; expected 34", h, err)
	}
	// A later store raises it again.
	if err := StoreAccounts(98); err != nil {
		t.Fatalf("StoreAccounts(98): %v", err)
	}
	if h, err := LastHeightStoredInAccounts(); err != nil || h != 98 {
		t.Fatalf("after a further write, LastHeightStoredInAccounts = %d, %v; expected 98", h, err)
	}
}
