package transactionsDefinition

// Executable specification for open audit findings in this package. Failing
// tests document unfixed holes; they must pass once fixed (see
// SECURITY_AUDIT_2026-09-05.md).

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// QWID-2026-06: a multisignature definition with five or more signers is a
// VALID configuration and must survive the encode/decode round trip. Losing
// it at decode strands legitimately configured accounts.
func TestQWID06_FiveSignerMultisigRoundTrips(t *testing.T) {
	td := TxData{
		Recipient:       common.EmptyAddress(),
		Amount:          1,
		MultiSignNumber: 5,
	}
	for i := 0; i < 5; i++ {
		var a [common.AddressLength]byte
		a[0] = byte(i + 1)
		td.MultiSignAddresses = append(td.MultiSignAddresses, a)
	}
	b, err := td.GetBytes()
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	got, rest, err := TxData{}.GetFromBytes(b)
	if err != nil {
		t.Fatalf("a valid 5-signer multisig definition failed to decode: %v (QWID-2026-06)", err)
	}
	if len(rest) != 0 {
		t.Fatalf("decode left %d trailing bytes", len(rest))
	}
	if int(got.MultiSignNumber) != 5 || len(got.MultiSignAddresses) != 5 {
		t.Fatalf("round trip lost the definition: number=%d addresses=%d (QWID-2026-06)",
			got.MultiSignNumber, len(got.MultiSignAddresses))
	}
	for i := range td.MultiSignAddresses {
		if !bytes.Equal(got.MultiSignAddresses[i][:], td.MultiSignAddresses[i][:]) {
			t.Fatalf("signer %d changed across the round trip", i)
		}
	}
}

// QWID-2026-03 / QWID-2026-17: transaction bytes arriving from the network are
// attacker-chosen. Decoding ANY byte string — truncated at every boundary, or
// with any internal length prefix rewritten — must return an error, never
// panic. A panic aborts the whole handler and (in the nonce handler) prints a
// stack trace, an attacker-driven amplifier. This is a fuzz-shaped invariant,
// not a single crafted input, so it stays valid as the wire format evolves.
func TestQWID03_17_TransactionDecoderNeverPanics(t *testing.T) {
	// A well-formed transaction with OptData and a synthetic signature, so the
	// serialization exercises every internal length-prefixed field.
	sigBytes := make([]byte, common.SignatureLength(false)+1)
	sig, _ := common.GetSignatureFromBytes(sigBytes, common.EmptyAddress())
	tx := Transaction{
		TxParam: TxParam{ChainID: common.GetChainID(), Sender: common.EmptyAddress(), SendingTime: 1, Nonce: 1},
		TxData:  TxData{Recipient: common.EmptyAddress(), Amount: 3, OptData: []byte{1, 2, 3, 4}},
		Height:  5, GasPrice: 1, GasUsage: 1, Signature: sig,
	}
	_ = tx.CalcHashAndSet()
	full := tx.GetBytes()

	var inputs [][]byte
	// Every truncation length.
	for n := 0; n <= len(full); n++ {
		inputs = append(inputs, append([]byte(nil), full[:n]...))
	}
	// Every 4-byte window rewritten to zero (turns a length prefix into 0,
	// which is exactly the empty-field condition behind QWID-2026-03) and to a
	// huge value (over-long length, QWID-2026-17).
	for i := 0; i+4 <= len(full); i++ {
		z := append([]byte(nil), full...)
		z[i], z[i+1], z[i+2], z[i+3] = 0, 0, 0, 0
		inputs = append(inputs, z)
		big := append([]byte(nil), full...)
		big[i], big[i+1], big[i+2], big[i+3] = 0x7f, 0xff, 0xff, 0xff
		inputs = append(inputs, big)
	}

	for idx, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Transaction.GetFromBytes panicked on crafted input #%d (len %d): %v "+
						"— reachable from P2P handlers (QWID-2026-03 / QWID-2026-17)", idx, len(in), r)
				}
			}()
			var d Transaction
			_, _, _ = d.GetFromBytes(in) // error is fine; a panic is not
		}()
	}
}
