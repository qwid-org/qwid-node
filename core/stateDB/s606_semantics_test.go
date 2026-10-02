package stateDB

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// S6-06: a reverted CREATE leaves nothing behind - no account, nonce or code.
func TestRevertUndoesCreateNonceAndCode(t *testing.T) {
	sa := CreateStateDB()
	a := addr(0x31)
	snap := sa.Snapshot()
	sa.CreateAccount(a)
	sa.SetNonce(a, 1)
	sa.SetCode(a, []byte{0x60, 0x00})
	sa.RevertToSnapshot(snap)
	if sa.Exist(a) || sa.GetNonce(a) != 0 || len(sa.GetCode(a)) != 0 || sa.GetCodeHash(a) != (common.Hash{}) {
		t.Fatal("a reverted create left state behind")
	}
	if _, ok := sa.Nonces[a.ByteValue]; ok {
		t.Fatal("a reverted SetNonce left a map entry")
	}

	// An existing value comes back exactly.
	sa.SetNonce(a, 5)
	sa.SetCode(a, []byte{1})
	snap = sa.Snapshot()
	sa.SetNonce(a, 6)
	sa.SetCode(a, []byte{2})
	sa.RevertToSnapshot(snap)
	if sa.GetNonce(a) != 5 || string(sa.GetCode(a)) != string([]byte{1}) {
		t.Fatal("revert did not restore the previous nonce and code")
	}
}

// S6-06: GetCommittedState is the value at the start of the transaction.
func TestCommittedStateIsTheValueAtTxStart(t *testing.T) {
	sa := CreateStateDB()
	a, k := addr(0x32), common.Hash{0x01}
	sa.SetState(a, k, common.Hash{0x0A})
	sa.ResetTransient() // a new transaction begins with slot = 0x0A

	sa.SetState(a, k, common.Hash{0x0B})
	sa.SetState(a, k, common.Hash{0x0C})
	if got := sa.GetCommittedState(a, k); got != (common.Hash{0x0A}) {
		t.Fatalf("committed state = %x, want the value at tx start", got)
	}
	if got := sa.GetState(a, k); got != (common.Hash{0x0C}) {
		t.Fatalf("current state = %x", got)
	}
	sa.ResetTransient()
	if got := sa.GetCommittedState(a, k); got != (common.Hash{0x0C}) {
		t.Fatalf("the next transaction must start from the stored value, got %x", got)
	}
}

// S6-06: a self-destructed contract loses its code, storage and nonce once
// its transaction succeeds.
func TestFinaliseRemovesSelfDestructedContract(t *testing.T) {
	sa := CreateStateDB()
	a, keep := addr(0x33), addr(0x34)
	for _, x := range []common.Address{a, keep} {
		sa.CreateAccount(x)
		sa.SetNonce(x, 1)
		sa.SetCode(x, []byte{0x60})
		sa.SetState(x, common.Hash{1}, common.Hash{2})
	}
	if !sa.Suicide(a) {
		t.Fatal("suicide refused")
	}
	sa.FinaliseTx()
	if sa.Exist(a) || len(sa.GetCode(a)) != 0 || sa.GetNonce(a) != 0 || sa.GetState(a, common.Hash{1}) != (common.Hash{}) {
		t.Fatal("a self-destructed contract survived its transaction")
	}
	if !sa.Exist(keep) || len(sa.GetCode(keep)) == 0 || sa.GetState(keep, common.Hash{1}) != (common.Hash{2}) {
		t.Fatal("finalising touched a contract that did not self-destruct")
	}
}
