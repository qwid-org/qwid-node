package account

import (
	"path/filepath"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
)

// withStakingTestDB installs a fresh RocksDB as database.MainDB and resets the
// in-memory staking shards, restoring both on cleanup.
func withStakingTestDB(t *testing.T) {
	t.Helper()
	db := &database.BlockchainDB{}
	pdb, err := db.InitPermanent(filepath.Join(t.TempDir(), "blockchain"))
	if err != nil {
		t.Skipf("RocksDB unavailable: %v", err)
	}
	savedDB := database.MainDB
	savedStaking := StakingAccounts
	database.MainDB = pdb
	t.Cleanup(func() {
		pdb.Close()
		database.MainDB = savedDB
		StakingAccounts = savedStaking
	})
	StakingAccounts = [256]StakingAccountsType{}
}

func stakingSeedShards(seed byte) {
	for i := 0; i < 256; i++ {
		var addr [common.AddressLength]byte
		for j := range addr {
			addr[j] = seed + byte(i) + byte(j)
		}
		StakingAccounts[i] = StakingAccountsType{
			AllStakingAccounts: map[[common.AddressLength]byte]StakingAccount{
				addr: {StakedBalance: int64(1000 + i), DelegatedAccount: addr, Address: addr},
			},
			StakeChangedAt: int64(i),
		}
	}
}

// TestQWID15_CompleteCheckpointRoundTrips confirms a fully written checkpoint is
// reported present and reloads shard-for-shard.
func TestQWID15_CompleteCheckpointRoundTrips(t *testing.T) {
	withStakingTestDB(t)
	stakingSeedShards(0x20)

	if err := StoreStakingAccounts(7); err != nil {
		t.Fatalf("store failed: %v", err)
	}
	if !StakingAccountsStoredAtHeight(7) {
		t.Fatal("complete checkpoint should be reported stored")
	}

	StakingAccounts = [256]StakingAccountsType{}
	if err := LoadStakingAccounts(7); err != nil {
		t.Fatalf("load of complete checkpoint failed: %v", err)
	}
	// Spot-check a few shards decoded with their data.
	for _, i := range []int{0, 1, 128, 255} {
		if StakingAccounts[i].StakeChangedAt != int64(i) {
			t.Errorf("shard %d: StakeChangedAt=%d, want %d", i, StakingAccounts[i].StakeChangedAt, i)
		}
		if len(StakingAccounts[i].AllStakingAccounts) != 1 {
			t.Errorf("shard %d: expected 1 staking account, got %d", i, len(StakingAccounts[i].AllStakingAccounts))
		}
	}
}

// TestQWID15_PartialCheckpointNotReportedComplete simulates the old partial
// write — shards on disk but no completeness manifest — and asserts the height
// is NOT advertised as restorable.
func TestQWID15_PartialCheckpointNotReportedComplete(t *testing.T) {
	withStakingTestDB(t)
	stakingSeedShards(0x30)

	// Write only shard 1 by hand, exactly as a partial write would leave it, and
	// deliberately do NOT write the manifest.
	hb := common.GetByteInt64(9)
	prefix := append(common.StakingAccountsDBPrefix[:], hb...)
	prefix = append(prefix, byte(1))
	if err := database.MainDB.Put(prefix, StakingAccounts[1].Marshal()); err != nil {
		t.Fatalf("seed shard put failed: %v", err)
	}

	if StakingAccountsStoredAtHeight(9) {
		t.Fatal("a checkpoint with shard 1 but no manifest must NOT be reported complete")
	}
}

// TestQWID15_MissingShardFailsLoad confirms a checkpoint that lost a shard after
// its manifest was written fails the load loudly instead of silently loading a
// zero/stale shard.
func TestQWID15_MissingShardFailsLoad(t *testing.T) {
	withStakingTestDB(t)
	stakingSeedShards(0x40)

	if err := StoreStakingAccounts(5); err != nil {
		t.Fatalf("store failed: %v", err)
	}
	// Lose one shard (e.g. selective key loss / storage fault).
	hb := common.GetByteInt64(5)
	prefix := append(common.StakingAccountsDBPrefix[:], hb...)
	prefix = append(prefix, byte(42))
	if err := database.MainDB.Delete(prefix); err != nil {
		t.Fatalf("delete shard failed: %v", err)
	}

	if err := LoadStakingAccounts(5); err == nil {
		t.Fatal("load must fail when a shard is missing")
	}
}

// TestQWID15_RemoveDeletesManifest confirms retention/rewind removal clears the
// manifest, so a height whose shards are gone is no longer reported complete.
func TestQWID15_RemoveDeletesManifest(t *testing.T) {
	withStakingTestDB(t)
	stakingSeedShards(0x50)

	if err := StoreStakingAccounts(3); err != nil {
		t.Fatalf("store failed: %v", err)
	}
	if !StakingAccountsStoredAtHeight(3) {
		t.Fatal("checkpoint should be reported stored before removal")
	}
	if err := RemoveStakingAccountsFromDB(3); err != nil {
		t.Fatalf("remove failed: %v", err)
	}
	if StakingAccountsStoredAtHeight(3) {
		t.Fatal("checkpoint must not be reported stored after its manifest is removed")
	}
}
