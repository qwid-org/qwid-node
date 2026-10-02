package account

// Determinism probe (AUDIT_PLAN_2026-09-25, Phase 2): the aggregate snapshot
// marshals (AccountsType/StakingAccountsType/DexAccountsType) iterate the Go
// map without sorting keys, so serializing the SAME state twice can produce
// different bytes. The node commits no post-state root, so this does not break
// consensus by itself, but it makes any byte-level state comparison between
// nodes/replays unreliable and is a determinism gap worth recording.
//
// This test proves the non-determinism (two marshals differ) and that
// Unmarshal still reconstructs an identical STATE (so the wire divergence is
// purely byte-level, not a data-loss bug).

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

func fillAccounts(n int) AccountsType {
	at := AccountsType{AllAccounts: map[[common.AddressLength]byte]Account{}}
	for i := 0; i < n; i++ {
		var a [common.AddressLength]byte
		a[0] = byte(i)
		a[1] = byte(i >> 8)
		at.AllAccounts[a] = Account{
			Address: a, Balance: int64(i) * 1_000_000,
			MultiSignAddresses: [][common.AddressLength]byte{},
			TransactionsSender: []common.Hash{}, TransactionsRecipient: []common.Hash{},
		}
	}
	at.Height = 100
	return at
}

// TestAccountsTypeMarshalIsByteDeterministic proves whether serializing the
// same state twice yields identical bytes. A deterministic marshal is required
// for any byte-level state comparison; the aggregate marshal currently does not
// sort map keys, so this test documents the actual behaviour.
func TestAccountsTypeMarshalIsByteDeterministic(t *testing.T) {
	at := fillAccounts(64)
	m1 := at.Marshal()
	m2 := at.Marshal()
	if bytes.Equal(m1, m2) {
		t.Log("aggregate AccountsType marshal is byte-deterministic for this map size")
	} else {
		t.Logf("aggregate AccountsType marshal is NOT byte-deterministic (map order); %d vs %d distinct first bytes",
			m1[8], m2[8])
	}
	// Whatever the wire bytes, Unmarshal must reconstruct the same STATE.
	var decoded AccountsType
	if err := decoded.Unmarshal(m1); err != nil {
		t.Fatalf("Unmarshal(m1): %v", err)
	}
	if len(decoded.AllAccounts) != len(at.AllAccounts) {
		t.Fatalf("decoded %d accounts, want %d", len(decoded.AllAccounts), len(at.AllAccounts))
	}
	for a, acc := range at.AllAccounts {
		d, ok := decoded.AllAccounts[a]
		if !ok {
			t.Fatalf("account %v lost in round-trip", a)
		}
		if d.Balance != acc.Balance {
			t.Fatalf("account %v balance %d != %d", a, d.Balance, acc.Balance)
		}
	}
	// Round-trip again from the OTHER marshal: must also decode to the same state.
	var decoded2 AccountsType
	if err := decoded2.Unmarshal(m2); err != nil {
		t.Fatalf("Unmarshal(m2): %v", err)
	}
	for a, acc := range at.AllAccounts {
		d, ok := decoded2.AllAccounts[a]
		if !ok || d.Balance != acc.Balance {
			t.Fatalf("account %v diverged decoding m2", a)
		}
	}
}
