package serverrpc

import "testing"

// DETS reported a single location, resolved first-match-wins with the
// confirmed DB checked first. An escrow transfer enters the escrow pool while
// the block that carries it is being processed, so it is in the confirmed DB
// AND in the pool at the same time — and always reported plain "confirmed_db".
// The wallet's history therefore showed every escrow transfer as settled,
// including ones whose value had not moved yet.
//
// "Confirmed" stays true and stays first, because it is what most callers ask
// about; the outstanding state is appended as a qualifier rather than
// replacing it, since the two facts are independent.

func TestTxLocationReportsEscrowAlongsideConfirmed(t *testing.T) {
	got := txLocation(true, false, false, true, false)
	if got != "confirmed_db+escrow" {
		t.Fatalf("txLocation = %q, want confirmed_db+escrow — a confirmed "+
			"transaction still awaiting settlement must say so", got)
	}
}

func TestTxLocationReportsMultisigAlongsideConfirmed(t *testing.T) {
	if got := txLocation(true, false, false, false, true); got != "confirmed_db+multisig" {
		t.Fatalf("txLocation = %q, want confirmed_db+multisig", got)
	}
}

func TestTxLocationPlainConfirmedWhenNothingOutstanding(t *testing.T) {
	if got := txLocation(true, false, false, false, false); got != "confirmed_db" {
		t.Fatalf("txLocation = %q, want confirmed_db", got)
	}
}

// Behaviour for transactions that have not reached a block is unchanged.
func TestTxLocationUnconfirmedPrecedenceUnchanged(t *testing.T) {
	cases := []struct {
		name                                              string
		confirmed, poolDB, main, escrow, multisig, expect any
	}{}
	_ = cases

	if got := txLocation(false, true, false, false, false); got != "pool_db" {
		t.Errorf("pool_db case: got %q", got)
	}
	if got := txLocation(false, false, true, false, false); got != "memory_main" {
		t.Errorf("memory_main case: got %q", got)
	}
	if got := txLocation(false, false, false, true, false); got != "memory_escrow" {
		t.Errorf("memory_escrow case: got %q", got)
	}
	if got := txLocation(false, false, false, false, true); got != "memory_multisign" {
		t.Errorf("memory_multisign case: got %q", got)
	}
	if got := txLocation(false, false, false, false, false); got != "" {
		t.Errorf("not found anywhere: got %q, want empty", got)
	}
}

// The pool DB mirrors transactions that are also in memory; confirmed still
// wins over it, and the qualifier still applies.
func TestTxLocationQualifierSurvivesPoolDB(t *testing.T) {
	if got := txLocation(true, true, false, true, false); got != "confirmed_db+escrow" {
		t.Fatalf("txLocation = %q, want confirmed_db+escrow", got)
	}
}
