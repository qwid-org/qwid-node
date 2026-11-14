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
