package vm

import (
	"testing"
)

// PUSH0 (EIP-3855) pushes a zero word for 2 gas. The node's interpreter is
// built on the Merge instruction set, which predates it, so contracts compiled
// by any current solc — whose default target is Shanghai — failed at deployment
// with "invalid opcode: PUSH0". That is a deployment-time failure on a live
// chain with no hint about the cause, hit by anyone following ordinary Solidity
// guidance.
//
// PUSH0 is the only instruction Shanghai adds, so implementing it is what makes
// default-compiled contracts deployable. The other Shanghai EIPs (3651 warm
// COINBASE, 3860 initcode metering) change gas accounting, not whether code
// runs, and this chain does not track Ethereum's gas schedule anyway.

// Note: every one of the 256 slots is populated — validate() panics on a nil
// entry, so unassigned opcodes carry opUndefined. Checking for a non-nil entry
// therefore proves nothing; the check has to be that executing it does not
// report an invalid opcode.
func TestPush0IsImplemented(t *testing.T) {
	op := GetGenericJumpTable()[PUSH0]
	if op == nil || op.execute == nil {
		t.Fatal("PUSH0 has no executable entry in the jump table")
	}

	stack := newstack()
	scope := &ScopeContext{
		Stack:    stack,
		Contract: &Contract{Code: []byte{byte(PUSH0)}},
	}
	pc := uint64(0)

	if _, err := op.execute(&pc, nil, scope); err != nil {
		t.Fatalf("PUSH0 is not implemented (%v); contracts compiled for Shanghai "+
			"— the current solc default — cannot be deployed", err)
	}
}

// EIP-3855 prices PUSH0 at 2 gas — the same as the other zero-input pushes of
// a constant, and cheaper than PUSH1's 3, which is the entire point of the
// instruction.
func TestPush0CostsQuickStep(t *testing.T) {
	op := GetGenericJumpTable()[PUSH0]
	if op == nil {
		t.Skip("PUSH0 not implemented yet")
	}
	if op.constantGas != GasQuickStep {
		t.Errorf("PUSH0 costs %d gas, want %d (GasQuickStep, per EIP-3855)",
			op.constantGas, GasQuickStep)
	}
}

// It must leave exactly one word on the stack, and that word must be zero.
func TestPush0PushesZeroAndOneWord(t *testing.T) {
	op := GetGenericJumpTable()[PUSH0]
	if op == nil {
		t.Skip("PUSH0 not implemented yet")
	}

	stack := newstack()
	scope := &ScopeContext{
		Stack:    stack,
		Contract: &Contract{Code: []byte{byte(PUSH0)}},
	}
	pc := uint64(0)

	if _, err := op.execute(&pc, nil, scope); err != nil {
		t.Fatalf("PUSH0 returned an error: %v", err)
	}

	if stack.len() != 1 {
		t.Fatalf("stack depth = %d after PUSH0, want 1", stack.len())
	}
	if v := stack.peek(); !v.IsZero() {
		t.Fatalf("PUSH0 pushed %s, want 0", v.String())
	}
}

// The stack bounds must be declared, or the interpreter's pre-execution check
// cannot tell that PUSH0 grows the stack by one.
func TestPush0DeclaresStackBounds(t *testing.T) {
	op := GetGenericJumpTable()[PUSH0]
	if op == nil {
		t.Skip("PUSH0 not implemented yet")
	}
	if op.minStack != minStack(0, 1) {
		t.Errorf("minStack = %d, want %d", op.minStack, minStack(0, 1))
	}
	if op.maxStack != maxStack(0, 1) {
		t.Errorf("maxStack = %d, want %d", op.maxStack, maxStack(0, 1))
	}
}
