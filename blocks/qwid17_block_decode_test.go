package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// decodeNoPanic runs Block.GetFromBytes under recover and reports a panic as a
// failure. QWID-2026-17 requires the block decoder to return an error for ANY
// input rather than panic (the input comes from any handshake-completed peer,
// before consensus authentication).
func decodeNoPanic(t *testing.T, name string, b []byte) (err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: Block.GetFromBytes panicked: %v", name, r)
		}
	}()
	_, err = Block{}.GetFromBytes(b)
	return err
}

func TestQWID17_BlockDecodersNeverPanic(t *testing.T) {
	// Build the exact adversarial shape from the finding: a 176-byte input whose
	// BaseHeader decodes successfully (three zero-length variable fields and a
	// one-byte signature, which Signature.Init accepts) but leaves only 42 bytes
	// — fewer than the 66-byte fixed tail BaseBlock slices next. Before the fix
	// this panicked at b[42:50]; now it must return an error.
	header := make([]byte, 117)
	for i := range header {
		header[i] = 0x02
	}
	adversarial := append([]byte(nil), header...)
	adversarial = append(adversarial, common.BytesToLenAndBytes(nil)...)          // Encryption1 (len 0)
	adversarial = append(adversarial, common.BytesToLenAndBytes(nil)...)          // Encryption2 (len 0)
	adversarial = append(adversarial, common.BytesToLenAndBytes(nil)...)          // SignatureMessage (len 0)
	adversarial = append(adversarial, common.BytesToLenAndBytes([]byte{0x01})...) // Signature (1 byte)
	for len(adversarial) < 176 {
		adversarial = append(adversarial, 0x00)
	}

	if err := decodeNoPanic(t, "adversarial-176", adversarial); err == nil {
		t.Error("adversarial 176-byte input should decode to an error, not succeed")
	}

	// Truncation sweep: every prefix of the adversarial buffer, plus a longer
	// patterned buffer, must return normally without panicking.
	for n := 0; n <= len(adversarial); n++ {
		decodeNoPanic(t, "adversarial-trunc", adversarial[:n])
	}

	patterned := make([]byte, 300)
	for i := range patterned {
		patterned[i] = byte(i % 251)
	}
	for n := 0; n <= len(patterned); n++ {
		decodeNoPanic(t, "patterned-trunc", patterned[:n])
	}

	// A header that decodes but leaves a remainder between 66 (BaseBlock tail)
	// and short of the extra 40 bytes Block.GetFromBytes needs for hash+fee:
	// build header + valid empty oracle fields so BaseBlock succeeds, with just
	// under 40 trailing bytes.
	base := append([]byte(nil), header...)
	base = append(base, common.BytesToLenAndBytes(nil)...)          // Encryption1
	base = append(base, common.BytesToLenAndBytes(nil)...)          // Encryption2
	base = append(base, common.BytesToLenAndBytes(nil)...)          // SignatureMessage
	base = append(base, common.BytesToLenAndBytes([]byte{0x01})...) // Signature
	// BaseBlock fixed tail: 66 bytes (block header hash 32 + ts 8 + reward 2 +
	// supply 8 + priceOracle 8 + randOracle 8), then two zero-length oracle
	// data fields. Height field (b[36:44]) is 0x02020202... which is below
	// OracleProofsActivationHeight? Use whatever; oracle proofs branch is gated.
	tail := make([]byte, 66)
	base = append(base, tail...)
	base = append(base, common.BytesToLenAndBytes(nil)...) // PriceOracleData
	base = append(base, common.BytesToLenAndBytes(nil)...) // RandOracleData
	base = append(base, []byte{0x01, 0x02, 0x03}...)       // only 3 bytes: < 40 for hash+fee
	decodeNoPanic(t, "short-block-tail", base)
}
