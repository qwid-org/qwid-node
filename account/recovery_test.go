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

func z() [common.AddressLength]byte { return [common.AddressLength]byte{} }

// The first commitments of an account - set when it is opened, by the key its
// address comes from - apply at once: there is nothing earlier to protect.
func TestFirstCommitmentsApplyImmediately(t *testing.T) {
	var a Account
	a.SetCommitments(c(7), c(1), 100)
	if a.EffectiveSpareCommit(100) != c(7) || a.EffectiveRecoveryCommit(100) != c(1) {
		t.Fatal("the opening commitments did not apply immediately")
	}
}

// Every later change waits RecoveryCommitMaturityBlocks.
func TestLaterCommitmentsMatureAfterD(t *testing.T) {
	var a Account
	a.SetCommitments(c(7), c(1), 50)
	a.SetCommitments(c(8), c(2), 100)
	if a.EffectiveSpareCommit(100+D-1) != c(7) || a.EffectiveRecoveryCommit(100+D-1) != c(1) {
		t.Fatal("a change applied before maturing")
	}
	if a.EffectiveSpareCommit(100+D) != c(8) || a.EffectiveRecoveryCommit(100+D) != c(2) {
		t.Fatal("a change did not apply at maturity")
	}
}

func TestLatestCommitWinsAndRestartsClock(t *testing.T) {
	var a Account
	a.SetCommitments(c(7), c(1), 50)
	a.SetCommitments(c(8), c(2), 100)
	a.SetCommitments(c(9), c(3), 200) // overwrite before maturity
	if a.EffectiveSpareCommit(100+D) != c(7) || a.EffectiveRecoveryCommit(100+D) != c(1) {
		t.Fatal("an overwritten change still matured")
	}
	if a.EffectiveSpareCommit(200+D) != c(9) || a.EffectiveRecoveryCommit(200+D) != c(3) {
		t.Fatal("the latest change did not win")
	}
}

func TestMaturedCommitStaysActiveWhileNextIsPending(t *testing.T) {
	var a Account
	a.SetCommitments(c(7), c(1), 50)
	a.SetCommitments(c(8), c(2), 100)
	a.SetCommitments(c(9), c(3), 100+D+5) // the first change matured before this
	if a.EffectiveSpareCommit(100+D+6) != c(8) || a.EffectiveRecoveryCommit(100+D+6) != c(2) {
		t.Fatal("a matured change was lost when a newer one was set")
	}
}

// A zero value leaves that commitment as it is: a wallet without a recovery
// phrase points at a spare key but has no recovery secret to commit to.
func TestZeroLeavesACommitmentUnchanged(t *testing.T) {
	var a Account
	a.SetCommitments(c(7), c(1), 50)
	a.SetCommitments(c(8), z(), 100)
	if a.EffectiveSpareCommit(100+D) != c(8) || a.EffectiveRecoveryCommit(100+D) != c(1) {
		t.Fatal("a zero recovery commitment cleared the existing one")
	}
}

func TestConsumeIsImmediate(t *testing.T) {
	var a Account
	a.SetCommitments(c(7), c(1), 50)
	a.SetCommitments(c(8), c(2), 100)
	a.ConsumeRecoveryCommit(c(9))
	if a.EffectiveRecoveryCommit(101) != c(9) || a.RecoveryPendingCommit != z() {
		t.Fatal("consume did not set next immediately and clear the pending one")
	}
	if a.EffectiveSpareCommit(100+D) != c(8) {
		t.Fatal("consuming the recovery commitment touched the spare commitment")
	}
}

func TestVoidDropsOnlyUnmatured(t *testing.T) {
	young, old := c(0x10), c(0x20)
	Accounts = AccountsType{AllAccounts: map[[common.AddressLength]byte]Account{
		young: {Address: young, SparePendingCommit: c(3), RecoveryPendingCommit: c(1), RecoveryPendingHeight: 1000},
		old:   {Address: old, SparePendingCommit: c(4), RecoveryPendingCommit: c(2), RecoveryPendingHeight: 1000 - D},
	}}
	if n := VoidPendingRecoveryCommits(1000); n != 1 {
		t.Fatalf("voided %d, want 1", n)
	}
	y := Accounts.AllAccounts[young]
	if y.EffectiveSpareCommit(1000+D) != z() || y.EffectiveRecoveryCommit(1000+D) != z() {
		t.Fatal("unmatured commitments survived a scheme break")
	}
	if Accounts.AllAccounts[old].SpareCommit != c(4) || Accounts.AllAccounts[old].RecoveryCommit != c(2) {
		t.Fatal("matured commitments were not promoted")
	}
}

func TestCommitFieldsRoundTrip(t *testing.T) {
	a := Account{Address: c(5), Balance: 7, RecoveryCommit: c(1), RecoveryPendingCommit: c(2), RecoveryPendingHeight: 42,
		SpareCommit: c(3), SparePendingCommit: c(4)}
	var b Account
	if err := b.Unmarshal(a.Marshal()); err != nil {
		t.Fatal(err)
	}
	if b.RecoveryCommit != a.RecoveryCommit || b.RecoveryPendingCommit != a.RecoveryPendingCommit || b.RecoveryPendingHeight != 42 ||
		b.SpareCommit != a.SpareCommit || b.SparePendingCommit != a.SparePendingCommit {
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
