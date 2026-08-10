package stateDB

import (
	"math"
	"math/big"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/core/types"
)

func addr(b byte) common.Address {
	var a common.Address
	a.ByteValue[0] = b
	return a
}

func TestRevertToSnapshotRestoresSlots(t *testing.T) {
	sa := CreateStateDB()
	a := addr(0x01)
	key := common.Hash{0xAA}

	sa.SetState(a, key, common.Hash{0x01}) // v1
	snap := sa.Snapshot()
	sa.SetState(a, key, common.Hash{0x02}) // v2
	sa.SetState(a, key, common.Hash{0x03}) // v3

	if sa.GetState(a, key) != (common.Hash{0x03}) {
		t.Fatalf("pre-revert value wrong: %v", sa.GetState(a, key))
	}
	sa.RevertToSnapshot(snap)
	if sa.GetState(a, key) != (common.Hash{0x01}) {
		t.Fatalf("revert did not restore original slot value, got %v", sa.GetState(a, key))
	}
}

func TestRevertDeletesNewlyCreatedSlot(t *testing.T) {
	sa := CreateStateDB()
	a := addr(0x02)
	key := common.Hash{0xBB}
	snap := sa.Snapshot()
	sa.SetState(a, key, common.Hash{0x09})
	sa.RevertToSnapshot(snap)
	if sa.GetState(a, key) != (common.Hash{}) {
		t.Fatalf("newly created slot not removed on revert: %v", sa.GetState(a, key))
	}
}

func TestRevertToSnapshotOutOfRange(t *testing.T) {
	sa := CreateStateDB()
	a := addr(0x03)
	key := common.Hash{0xCC}

	// Set some state changes
	sa.SetState(a, key, common.Hash{0x11})
	snap := sa.Snapshot()
	sa.SetState(a, key, common.Hash{0x22})
	sa.SetState(a, key, common.Hash{0x33})

	// Revert to far-out-of-range value should not panic and should clamp to journal length
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RevertToSnapshot panicked with out-of-range value: %v", r)
		}
	}()
	sa.RevertToSnapshot(9999)
	// After reverting to 9999 (clamped to len(journal)), state should be at the clamped point
	// which should keep all changes (no revert occurs when sn >= len(journal))
	if sa.GetState(a, key) != (common.Hash{0x33}) {
		t.Fatalf("revert to 9999 should clamp and not panic, got %v", sa.GetState(a, key))
	}

	// Verify revert to snapshot before the out-of-range call still works
	sa.RevertToSnapshot(snap)
	if sa.GetState(a, key) != (common.Hash{0x11}) {
		t.Fatalf("revert to snap did not restore original value, got %v", sa.GetState(a, key))
	}
}

func TestAddLogAndRevert(t *testing.T) {
	sa := CreateStateDB()
	sa.ClearLogs()
	snap := sa.Snapshot()
	sa.AddLog(&types.Log{Address: addr(0x03)})
	if len(sa.GetLogs()) != 1 {
		t.Fatalf("log not captured: %d", len(sa.GetLogs()))
	}
	sa.RevertToSnapshot(snap)
	if len(sa.GetLogs()) != 0 {
		t.Fatalf("log not reverted: %d", len(sa.GetLogs()))
	}
}

func TestSuicide(t *testing.T) {
	sa := CreateStateDB()
	a := addr(0x04)
	sa.CreateAccount(a)
	if sa.HasSuicided(a) {
		t.Fatal("fresh account reported suicided")
	}
	if !sa.Suicide(a) {
		t.Fatal("Suicide returned false for existing account")
	}
	if !sa.HasSuicided(a) {
		t.Fatal("HasSuicided false after Suicide")
	}
}

func TestSuicideRevertAndNonexistent(t *testing.T) {
	sa := CreateStateDB()

	// Suicide on a nonexistent (never-CreateAccount'd) address.
	nonexistent := addr(0x05)
	if sa.Suicide(nonexistent) {
		t.Fatal("Suicide returned true for nonexistent account")
	}
	if sa.HasSuicided(nonexistent) {
		t.Fatal("HasSuicided true for nonexistent account")
	}

	// Revert path: suicide should be undone by RevertToSnapshot.
	a := addr(0x06)
	sa.CreateAccount(a)
	snap := sa.Snapshot()
	if !sa.Suicide(a) {
		t.Fatal("Suicide returned false for existing account")
	}
	if !sa.HasSuicided(a) {
		t.Fatal("HasSuicided false after Suicide")
	}
	sa.RevertToSnapshot(snap)
	if sa.HasSuicided(a) {
		t.Fatal("HasSuicided true after RevertToSnapshot")
	}

	// ClearSuicided should also reset suicided state, even without a revert.
	if !sa.Suicide(a) {
		t.Fatal("Suicide returned false for existing account (second call)")
	}
	if !sa.HasSuicided(a) {
		t.Fatal("HasSuicided false after Suicide (second call)")
	}
	sa.ClearSuicided()
	if sa.HasSuicided(a) {
		t.Fatal("HasSuicided true after ClearSuicided")
	}
}

func TestAccessList(t *testing.T) {
	sa := CreateStateDB()
	a := addr(0x05)
	if sa.AddressInAccessList(a) {
		t.Fatal("address unexpectedly warm before add")
	}
	sa.AddAddressToAccessList(a)
	if !sa.AddressInAccessList(a) {
		t.Fatal("address not warm after add")
	}
	slot := common.Hash{0xCC}
	adOk, slOk := sa.SlotInAccessList(a, slot)
	if !adOk || slOk {
		t.Fatalf("slot state wrong before add: addr=%v slot=%v", adOk, slOk)
	}
	sa.AddSlotToAccessList(a, slot)
	adOk, slOk = sa.SlotInAccessList(a, slot)
	if !adOk || !slOk {
		t.Fatal("slot not warm after add")
	}
}

func TestAccessListRevert(t *testing.T) {
	sa := CreateStateDB()
	a := addr(0x07)
	slot := common.Hash{0xDD}

	snap := sa.Snapshot()
	sa.AddAddressToAccessList(a)
	sa.AddSlotToAccessList(a, slot)

	if !sa.AddressInAccessList(a) {
		t.Fatal("address not warm after add")
	}
	adOk, slOk := sa.SlotInAccessList(a, slot)
	if !adOk || !slOk {
		t.Fatal("slot not warm after add")
	}

	sa.RevertToSnapshot(snap)

	if sa.AddressInAccessList(a) {
		t.Fatal("address still warm after RevertToSnapshot")
	}
	_, slOk = sa.SlotInAccessList(a, slot)
	if slOk {
		t.Fatal("slot still warm after RevertToSnapshot")
	}

	// ClearAccessList should also cold out a previously-warmed address,
	// even without a revert.
	sa.AddAddressToAccessList(a)
	if !sa.AddressInAccessList(a) {
		t.Fatal("address not warm after add (second time)")
	}
	sa.ClearAccessList()
	if sa.AddressInAccessList(a) {
		t.Fatal("address still warm after ClearAccessList")
	}
}

// initNativeAccounts resets the native account map so balance bridging has a
// clean, non-nil map to write into.
func initNativeAccounts() {
	account.AccountsRWMutex.Lock()
	account.Accounts.AllAccounts = make(map[[common.AddressLength]byte]account.Account)
	account.AccountsRWMutex.Unlock()
}

func TestGetBalanceReadsNative(t *testing.T) {
	initNativeAccounts()
	sa := CreateStateDB()
	a := addr(0x10)
	account.SetBalance(a.ByteValue, 4200)
	if got := sa.GetBalance(a); got.Int64() != 4200 {
		t.Fatalf("GetBalance = %s, want 4200", got.String())
	}
	// Absent account reads as zero.
	if got := sa.GetBalance(addr(0x11)); got.Sign() != 0 {
		t.Fatalf("absent GetBalance = %s, want 0", got.String())
	}
}

func TestEmptyConsidersBalance(t *testing.T) {
	initNativeAccounts()
	sa := CreateStateDB()
	a := addr(0x12)
	// zero nonce, no code, but non-zero balance => NOT empty (EIP-161).
	account.SetBalance(a.ByteValue, 1)
	if sa.Empty(a) {
		t.Fatal("account with balance reported Empty")
	}
	account.SetBalance(a.ByteValue, 0)
	if !sa.Empty(a) {
		t.Fatal("zero nonce/code/balance account not reported Empty")
	}
}

func TestAddSubBalanceMutatesNativeAndReverts(t *testing.T) {
	initNativeAccounts()
	sa := CreateStateDB()
	a := addr(0x20)
	account.SetBalance(a.ByteValue, 1000)

	snap := sa.Snapshot()
	sa.AddBalance(a, big.NewInt(500))
	if account.GetBalance(a.ByteValue) != 1500 {
		t.Fatalf("after AddBalance native = %d, want 1500", account.GetBalance(a.ByteValue))
	}
	sa.SubBalance(a, big.NewInt(200))
	if account.GetBalance(a.ByteValue) != 1300 {
		t.Fatalf("after SubBalance native = %d, want 1300", account.GetBalance(a.ByteValue))
	}

	sa.RevertToSnapshot(snap)
	if account.GetBalance(a.ByteValue) != 1000 {
		t.Fatalf("after revert native = %d, want 1000 (restored)", account.GetBalance(a.ByteValue))
	}
}

func TestSubBalanceFloorsAtZero(t *testing.T) {
	initNativeAccounts()
	sa := CreateStateDB()
	a := addr(0x21)
	account.SetBalance(a.ByteValue, 50)
	sa.SubBalance(a, big.NewInt(9999)) // would go negative
	if account.GetBalance(a.ByteValue) != 0 {
		t.Fatalf("SubBalance did not floor at 0: got %d", account.GetBalance(a.ByteValue))
	}
}

func TestBalanceSaturates(t *testing.T) {
	initNativeAccounts()
	sa := CreateStateDB()
	a := addr(0x22)
	// Start near the top of int64 so a further add overflows and saturates.
	account.SetBalance(a.ByteValue, math.MaxInt64-5)
	sa.AddBalance(a, big.NewInt(100)) // would overflow int64
	if account.GetBalance(a.ByteValue) != math.MaxInt64 {
		t.Fatalf("Add overflow did not saturate to MaxInt64: got %d", account.GetBalance(a.ByteValue))
	}

	// An amount larger than int64 range must saturate, not wrap.
	b := addr(0x23)
	account.SetBalance(b.ByteValue, 10)
	huge := new(big.Int).Lsh(big.NewInt(1), 70) // 2^70, far beyond int64
	sa.AddBalance(b, huge)
	if account.GetBalance(b.ByteValue) != math.MaxInt64 {
		t.Fatalf("out-of-int64 amount did not saturate: got %d", account.GetBalance(b.ByteValue))
	}
}

func TestRefundAccounting(t *testing.T) {
	sa := CreateStateDB()
	if sa.GetRefund() != 0 {
		t.Fatal("fresh refund not zero")
	}
	sa.AddRefund(100)
	sa.AddRefund(50)
	if sa.GetRefund() != 150 {
		t.Fatalf("GetRefund = %d, want 150", sa.GetRefund())
	}
	sa.SubRefund(20)
	if sa.GetRefund() != 130 {
		t.Fatalf("after SubRefund = %d, want 130", sa.GetRefund())
	}
	sa.SubRefund(9999) // clamp, no underflow
	if sa.GetRefund() != 0 {
		t.Fatalf("SubRefund underflow not clamped: %d", sa.GetRefund())
	}
	sa.AddRefund(77)
	sa.ResetTransient()
	if sa.GetRefund() != 0 {
		t.Fatalf("ResetTransient did not clear refund: %d", sa.GetRefund())
	}
}
