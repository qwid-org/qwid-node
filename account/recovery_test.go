package account

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

func c(b byte) [common.AddressLength]byte {
	var x [common.AddressLength]byte
	x[0] = b
	return x
}

const D = common.RecoveryCommitMaturityBlocks

func TestPendingCommitMaturesAfterD(t *testing.T) {
	var a Account
	a.SetPendingRecoveryCommit(c(1), 100)
	if a.EffectiveRecoveryCommit(100+D-1) != ([common.AddressLength]byte{}) {
		t.Fatal("pending commitment effective before maturity")
	}
	if a.EffectiveRecoveryCommit(100+D) != c(1) {
		t.Fatal("pending commitment not effective at maturity")
	}
}

func TestLatestCommitWinsAndRestartsClock(t *testing.T) {
	var a Account
	a.SetPendingRecoveryCommit(c(1), 100)
	a.SetPendingRecoveryCommit(c(2), 200) // overwrite before maturity
	if a.EffectiveRecoveryCommit(100+D) != ([common.AddressLength]byte{}) {
		t.Fatal("overwritten commitment still matured")
	}
	if a.EffectiveRecoveryCommit(200+D) != c(2) {
		t.Fatal("latest commitment did not win")
	}
}

func TestMaturedCommitStaysActiveWhileNextIsPending(t *testing.T) {
	var a Account
	a.SetPendingRecoveryCommit(c(1), 100)
	a.SetPendingRecoveryCommit(c(2), 100+D+5) // c(1) matured before this
	if got := a.EffectiveRecoveryCommit(100 + D + 6); got != c(1) {
		t.Fatalf("matured commitment lost when a new one was set: %v", got)
	}
}

func TestConsumeIsImmediate(t *testing.T) {
	var a Account
	a.SetPendingRecoveryCommit(c(1), 100)
	a.ConsumeRecoveryCommit(c(9))
	if a.EffectiveRecoveryCommit(101) != c(9) || a.RecoveryPendingCommit != ([common.AddressLength]byte{}) {
		t.Fatal("consume did not set next immediately and clear pending")
	}
}

func TestVoidDropsOnlyUnmatured(t *testing.T) {
	young, old := c(0x10), c(0x20)
	Accounts = AccountsType{AllAccounts: map[[common.AddressLength]byte]Account{
		young: {Address: young, RecoveryPendingCommit: c(1), RecoveryPendingHeight: 1000},
		old:   {Address: old, RecoveryPendingCommit: c(2), RecoveryPendingHeight: 1000 - D},
	}}
	if n := VoidPendingRecoveryCommits(1000); n != 1 {
		t.Fatalf("voided %d, want 1", n)
	}
	if Accounts.AllAccounts[young].EffectiveRecoveryCommit(1000+D) != ([common.AddressLength]byte{}) {
		t.Fatal("unmatured commitment survived an encryption change")
	}
	if Accounts.AllAccounts[old].RecoveryCommit != c(2) {
		t.Fatal("matured commitment was not promoted")
	}
}

func TestCommitFieldsRoundTrip(t *testing.T) {
	a := Account{Address: c(5), Balance: 7, RecoveryCommit: c(1), RecoveryPendingCommit: c(2), RecoveryPendingHeight: 42}
	var b Account
	if err := b.Unmarshal(a.Marshal()); err != nil {
		t.Fatal(err)
	}
	if b.RecoveryCommit != a.RecoveryCommit || b.RecoveryPendingCommit != a.RecoveryPendingCommit || b.RecoveryPendingHeight != 42 {
		t.Fatalf("round trip lost commitment fields: %+v", b)
	}
}

func TestFirstBindWins(t *testing.T) {
	Accounts = AccountsType{AllAccounts: map[[common.AddressLength]byte]Account{}}
	k := [32]byte{1}
	if !AddRecoveryBind(k, RecoveryBind{Identity: c(1), Payload: [32]byte{7}, Height: 10}) {
		t.Fatal("first bind refused")
	}
	if AddRecoveryBind(k, RecoveryBind{Identity: c(1), Payload: [32]byte{8}, Height: 11}) {
		t.Fatal("second bind with the same key replaced the first")
	}
	b, ok := GetRecoveryBind(k)
	if !ok || b.Payload != ([32]byte{7}) {
		t.Fatalf("got %+v", b)
	}
}

func TestPruneDropsExpiredBinds(t *testing.T) {
	Accounts = AccountsType{AllAccounts: map[[common.AddressLength]byte]Account{}}
	AddRecoveryBind([32]byte{1}, RecoveryBind{Height: 100})
	AddRecoveryBind([32]byte{2}, RecoveryBind{Height: 200})
	if n := PruneRecoveryBinds(100 + common.RecoveryBindExpiryBlocks + 1); n != 1 {
		t.Fatalf("pruned %d, want 1", n)
	}
	if _, ok := GetRecoveryBind([32]byte{1}); ok {
		t.Fatal("expired bind kept")
	}
	if _, ok := GetRecoveryBind([32]byte{2}); !ok {
		t.Fatal("live bind pruned")
	}
}

func TestBindsSurviveSnapshotRoundTrip(t *testing.T) {
	at := AccountsType{
		AllAccounts:   map[[common.AddressLength]byte]Account{c(1): {Address: c(1), Balance: 5}},
		RecoveryBinds: map[[32]byte]RecoveryBind{{3}: {Identity: c(1), Payload: [32]byte{4}, Height: 9}},
		Height:        77,
	}
	var back AccountsType
	if err := back.Unmarshal(at.Marshal()); err != nil {
		t.Fatal(err)
	}
	if back.Height != 77 || back.RecoveryBinds[[32]byte{3}] != at.RecoveryBinds[[32]byte{3}] {
		t.Fatalf("binds lost in snapshot: %+v", back)
	}
}
