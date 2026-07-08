package blocks

import (
	"errors"
	"fmt"
	"testing"

	vm "github.com/wonabru/qwid-node/core/evm"
)

func TestIsEVMExecutionError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"reverted", vm.ErrExecutionReverted, true},
		{"out of gas", vm.ErrOutOfGas, true},
		{"code store oog", vm.ErrCodeStoreOutOfGas, true},
		{"depth", vm.ErrDepth, true},
		{"insufficient balance", vm.ErrInsufficientBalance, true},
		{"addr collision", vm.ErrContractAddressCollision, true},
		{"max code size", vm.ErrMaxCodeSizeExceeded, true},
		{"invalid jump", vm.ErrInvalidJump, true},
		{"write protection", vm.ErrWriteProtection, true},
		{"return data oob", vm.ErrReturnDataOutOfBounds, true},
		{"gas uint overflow", vm.ErrGasUintOverflow, true},
		{"invalid code", vm.ErrInvalidCode, true},
		{"nonce uint overflow", vm.ErrNonceUintOverflow, true},
		{"wrapped reverted", fmt.Errorf("evaluate: %w", vm.ErrExecutionReverted), true},
		{"struct invalid opcode", &vm.ErrInvalidOpCode{}, true},
		{"struct stack underflow", &vm.ErrStackUnderflow{}, true},
		{"struct stack overflow", &vm.ErrStackOverflow{}, true},
		{"nil", nil, false},
		{"plain db error", errors.New("db read failed"), false},
		{"wrapped non-evm", fmt.Errorf("boom: %w", errors.New("io")), false},
	}
	for _, c := range cases {
		if got := isEVMExecutionError(c.err); got != c.want {
			t.Errorf("%s: isEVMExecutionError = %v, want %v", c.name, got, c.want)
		}
	}
}
