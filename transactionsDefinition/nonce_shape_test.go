package transactionsDefinition

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// Audit 2026-11-13: a validator nonce has exactly one shape. Its free fields
// (nonce number, gas, trailing bytes, the unused rand slot) let one validator
// mint any number of distinct, validly signed nonces for one height.
func canonicalNonce() Transaction {
	opt := make([]byte, 8+common.HashLength+16)
	opt = append(opt, common.BytesToLenAndBytes(nil)...)
	opt = append(opt, common.BytesToLenAndBytes(nil)...)
	return Transaction{
		TxParam: TxParam{ChainID: common.GetChainID(), SendingTime: 1},
		TxData:  TxData{Recipient: common.GetDelegatedAccountAddress(1), OptData: opt},
		Height:  10,
	}
}

func TestNonceShape(t *testing.T) {
	if err := nonceShapeError(canonicalNonce()); err != nil {
		t.Fatalf("the canonical nonce is refused: %v", err)
	}
	noVotes := canonicalNonce()
	noVotes.TxData.OptData = noVotes.TxData.OptData[:8+common.HashLength+16]
	if err := nonceShapeError(noVotes); err != nil {
		t.Fatalf("a nonce without vote fields is refused: %v", err)
	}
	for name, edit := range map[string]func(*Transaction){
		"nonce number":   func(tx *Transaction) { tx.TxParam.Nonce = 7 },
		"gas price":      func(tx *Transaction) { tx.GasPrice = 1 },
		"gas usage":      func(tx *Transaction) { tx.GasUsage = 1 },
		"rand slot":      func(tx *Transaction) { tx.TxData.OptData[8+common.HashLength+8] = 1 },
		"trailing bytes": func(tx *Transaction) { tx.TxData.OptData = append(tx.TxData.OptData, 0xAA) },
		"truncated vote": func(tx *Transaction) { tx.TxData.OptData = tx.TxData.OptData[:len(tx.TxData.OptData)-1] },
		"locked amount":  func(tx *Transaction) { tx.TxData.LockedAmount = 1 },
		"multisig":       func(tx *Transaction) { tx.TxParam.MultiSignTx = common.Hash{1} },
	} {
		tx := canonicalNonce()
		edit(&tx)
		if nonceShapeError(tx) == nil {
			t.Errorf("a nonce with a non-canonical %s is accepted", name)
		}
	}
}

// The nonce's second signature (audit 2026-11-14) rides in a third
// length-prefixed field; it signs the nonce with that field empty, under its
// own domain, so it is no signature of any transaction.
func TestNonceSecondSignatureField(t *testing.T) {
	tx := canonicalNonce()
	tx.TxData.OptData = append(tx.TxData.OptData, common.BytesToLenAndBytes(nil)...)
	if err := nonceShapeError(tx); err != nil {
		t.Fatalf("a nonce with an empty second-signature field is refused: %v", err)
	}
	msg, err := NonceSecondSignatureMessage(tx)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetNonceSecondSignature(&tx, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if err := nonceShapeError(tx); err != nil {
		t.Fatalf("a nonce carrying a second signature is refused: %v", err)
	}
	sig, msg2, ok := NonceSecondSignature(tx)
	if !ok || string(sig) != string([]byte{1, 2, 3}) || string(msg2) != string(msg) {
		t.Fatal("the second signature or the message it signs did not round-trip")
	}
	_ = tx.CalcHashAndSet()
	if string(msg) == string(tx.Hash.GetBytes()) {
		t.Fatal("the second signature signs the transaction hash itself")
	}
	tx.TxData.OptData = append(tx.TxData.OptData, common.BytesToLenAndBytes(nil)...)
	if nonceShapeError(tx) == nil {
		t.Fatal("a fourth field is accepted")
	}
}
