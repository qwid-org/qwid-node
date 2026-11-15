package blocks

import (
	"bytes"
	"strings"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// Consensus (audit 2026-11-15): a block's encoded oracle proofs must fit
// common.MaxOracleProofBudgetBytes, the room the nonce topic it is broadcast
// on has for them. A larger block could reach peers only through sync.
func proofsOfTotal(total int) [][]byte {
	const each = 1 << 20
	var out [][]byte
	for total > 0 {
		n := each
		if total < n {
			n = total
		}
		out = append(out, bytes.Repeat([]byte{7}, n))
		total -= n
	}
	return out
}

func TestBlockOverTheProofBudgetIsRefused(t *testing.T) {
	parent := parentAt(t, 99)
	blk := childOf(parent)
	blk.BaseBlock.OracleProofs = proofsOfTotal(int(common.MaxOracleProofBudgetBytes))
	err := AuthenticateOracleProofs(blk, parent)
	if err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("a block over the oracle proof budget was not refused for it: %v", err)
	}
}

func TestWhatTheProducerKeepsFitsTheBudget(t *testing.T) {
	kept := FitOracleProofs(proofsOfTotal(2 * int(common.MaxOracleProofBudgetBytes)))
	if err := oracleProofBudgetError(kept); err != nil {
		t.Fatalf("the proofs the producer keeps break the budget: %v", err)
	}
	used := 4
	for _, pb := range kept {
		used += len(pb) + 4
	}
	room := int(common.MaxOracleProofBudgetBytes) - used - 4 // one more proof's payload
	exact := append(append([][]byte{}, kept...), make([]byte, room))
	if err := oracleProofBudgetError(exact); err != nil {
		t.Fatalf("proofs filling the budget exactly were refused: %v", err)
	}
	over := append(append([][]byte{}, kept...), make([]byte, room+1))
	if err := oracleProofBudgetError(over); err == nil {
		t.Fatal("proofs one byte over the budget were accepted")
	}
}
