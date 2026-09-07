package vm

// Lock-in test for QWID-2026-26: opcode 0x44 (PREVRANDAO/DIFFICULTY) must not
// nil-dereference Context.Random. The fork runs the merge jump table
// unconditionally, so this opcode is always dispatched to opRandom; a nil
// Random (as the host block contexts used to pass) panicked block application
// on every validator. Fix already applied — keep green.

import (
	"math/big"
	"testing"

	"github.com/qwid-org/qwid-node/params"
)

func TestQWID26_RandomOpcodeToleratesNilRandom(t *testing.T) {
	blockCtx := BlockContext{
		BlockNumber: big.NewInt(1),
		Random:      nil, // exactly what the host contexts used to pass
	}
	evm := NewEVM(blockCtx, TxContext{}, nil, params.AllEthashProtocolChanges, Config{})

	op := GetGenericJumpTable()[RANDOM]
	if op == nil || op.execute == nil {
		t.Fatal("opcode 0x44 has no executable entry")
	}
	stack := newstack()
	scope := &ScopeContext{Stack: stack, Contract: &Contract{Code: []byte{byte(RANDOM)}}}
	pc := uint64(0)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("opcode 0x44 panicked on a nil Context.Random (%v) — one contract using "+
				"block.difficulty/block.prevrandao would stall the chain (QWID-2026-26)", r)
		}
	}()
	if _, err := op.execute(&pc, evm.interpreter, scope); err != nil {
		t.Fatalf("opcode 0x44 returned an error on nil Random: %v", err)
	}
	if v := stack.pop(); !v.IsZero() {
		t.Fatalf("nil Random must push zero, got %s", v.Hex())
	}
}
