package transactionsDefinition

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// TestTxParamNonceRoundTrip verifies AC-H2: TxParam serializes and deserializes
// an int64 nonce (including values beyond the old int16 range) at the correct
// byte offsets.
func TestTxParamNonceRoundTrip(t *testing.T) {
	nonces := []int64{0, 1, 32767, 32768, 1 << 40, 9223372036854775807}
	for _, nonce := range nonces {
		tp := TxParam{
			ChainID:     23,
			Sender:      common.EmptyAddress(),
			SendingTime: 1700000000,
			Nonce:       nonce,
		}
		b := tp.GetBytes()
		got, _, err := TxParam{}.GetFromBytes(b)
		if err != nil {
			t.Fatalf("nonce %d: GetFromBytes failed: %v", nonce, err)
		}
		if got.Nonce != nonce {
			t.Fatalf("nonce round-trip: got %d want %d", got.Nonce, nonce)
		}
		if got.ChainID != 23 {
			t.Fatalf("chainID round-trip: got %d want 23", got.ChainID)
		}
		if got.SendingTime != 1700000000 {
			t.Fatalf("sendingTime round-trip: got %d want 1700000000", got.SendingTime)
		}
	}
}
