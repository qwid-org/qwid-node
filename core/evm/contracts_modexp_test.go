package vm

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/wonabru/qwid-node/common"
)

// modexpInput builds the MODEXP precompile input: three 32-byte big-endian
// lengths followed by base||exp||mod.
func modexpInput(baseLen, expLen, modLen uint64, base, exp, mod []byte) []byte {
	var b []byte
	b = append(b, common.LeftPadBytes(new(big.Int).SetUint64(baseLen).Bytes(), 32)...)
	b = append(b, common.LeftPadBytes(new(big.Int).SetUint64(expLen).Bytes(), 32)...)
	b = append(b, common.LeftPadBytes(new(big.Int).SetUint64(modLen).Bytes(), 32)...)
	b = append(b, base...)
	b = append(b, exp...)
	b = append(b, mod...)
	return b
}

func TestBigModExpRejectsOversized(t *testing.T) {
	// modLen just over the ceiling; base/exp small. No operands needed — the
	// length check must fire before any operand load.
	in := modexpInput(1, 1, MaxModExpLen+1, nil, nil, nil)
	if _, err := (&bigModExp{}).Run(in); err != ErrModExpOperandTooLarge {
		t.Fatalf("oversized modLen: err = %v, want ErrModExpOperandTooLarge", err)
	}
}

func TestBigModExpSmallStillWorks(t *testing.T) {
	// 3^2 mod 5 = 4
	in := modexpInput(1, 1, 1, []byte{0x03}, []byte{0x02}, []byte{0x05})
	out, err := (&bigModExp{}).Run(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(out, []byte{0x04}) {
		t.Fatalf("3^2 mod 5: got %v, want [4]", out)
	}
}
