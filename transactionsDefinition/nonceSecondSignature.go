package transactionsDefinition

import (
	"fmt"

	"github.com/qwid-org/qwid-node/common"
)

// The second signature of a validator nonce (audit 2026-11-14).
//
// A nonce carries the validator's scheme votes and its price. Signed with one
// scheme, whoever breaks that scheme could forge every validator's vote and
// price - two thirds of the stake for any scheme change, any price - until the
// scheme is paused. A validator holding an eligible spare key therefore also
// signs its nonce with the spare; its vote and price count only with both
// signatures (blocks.proofCounts).
//
// OptData = height(8) || parent hash(32) || price(8) || rand slot(8)
//         || LB(vote1) || LB(vote2) || LB(second signature)
//
// The second signature signs the nonce with that last field empty, under its
// own domain: it is no signature of any transaction. The first signature signs
// the whole nonce, second signature included, as before.

const nonceSecondSignatureDomain = "QWID-NONCE-SIG2-v1"

const nonceHeadLen = 8 + common.HashLength + 16

// splitNonceOptData returns the nonce data up to and including the votes, and
// the second-signature field (nil when absent).
func splitNonceOptData(opt []byte) (core []byte, sig2 []byte, err error) {
	if len(opt) < nonceHeadLen {
		return nil, nil, fmt.Errorf("nonce data too short")
	}
	rest := opt[nonceHeadLen:]
	if len(rest) == 0 {
		return opt, nil, nil
	}
	_, rest1, err := common.BytesWithLenToBytes(rest)
	if err != nil {
		return nil, nil, err
	}
	_, rest2, err := common.BytesWithLenToBytes(rest1)
	if err != nil {
		return nil, nil, err
	}
	core = opt[:len(opt)-len(rest2)]
	if len(rest2) == 0 {
		return core, nil, nil
	}
	sig2, tail, err := common.BytesWithLenToBytes(rest2)
	if err != nil {
		return nil, nil, err
	}
	if len(tail) != 0 {
		return nil, nil, fmt.Errorf("bytes after the nonce's second signature")
	}
	return core, sig2, nil
}

// NonceSecondSignatureMessage is what a nonce's second signature signs.
func NonceSecondSignatureMessage(tx Transaction) ([]byte, error) {
	core, _, err := splitNonceOptData(tx.TxData.OptData)
	if err != nil {
		return nil, err
	}
	if len(core) == nonceHeadLen {
		return nil, fmt.Errorf("a nonce without votes carries no second signature")
	}
	c := tx
	c.TxData.OptData = append(append([]byte{}, core...), common.BytesToLenAndBytes(nil)...)
	if err := c.CalcHashAndSet(); err != nil {
		return nil, err
	}
	msg := append(common.BytesToLenAndBytes([]byte(nonceSecondSignatureDomain)), c.Hash.GetBytes()...)
	return common.CalcHashToByte(msg)
}

// NonceSecondSignature returns the second signature a nonce carries and the
// message it signs; ok is false when it carries none.
func NonceSecondSignature(tx Transaction) (sig []byte, msg []byte, ok bool) {
	_, sig2, err := splitNonceOptData(tx.TxData.OptData)
	if err != nil || len(sig2) == 0 {
		return nil, nil, false
	}
	msg, err = NonceSecondSignatureMessage(tx)
	if err != nil {
		return nil, nil, false
	}
	return sig2, msg, true
}

// SetNonceSecondSignature puts sig into the nonce's second-signature field.
// The caller signs the nonce (and so recomputes its hash) afterwards.
func SetNonceSecondSignature(tx *Transaction, sig []byte) error {
	core, _, err := splitNonceOptData(tx.TxData.OptData)
	if err != nil {
		return err
	}
	if len(core) == nonceHeadLen {
		return fmt.Errorf("a nonce without votes carries no second signature")
	}
	tx.TxData.OptData = append(append([]byte{}, core...), common.BytesToLenAndBytes(sig)...)
	return nil
}
