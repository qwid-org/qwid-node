package wallet

import (
	"fmt"

	"github.com/qwid-org/qwid-node/common"
)

const randaoSeedDomain = "QWID-RANDAO-seed-v1"

// RandaoSeed returns the RANDAO seed this wallet commits to in the block it
// produces at height (S4-06, blocks/randao.go). Seeds are derived, not
// stored: the chain records only the commitment and its height, and the
// producer re-derives the seed when its next block reveals it - after a
// restart or a rewind just the same.
//
// The secret is the BIP39 seed when the wallet has a recovery phrase, which
// survives signature-scheme changes, and the primary secret key otherwise.
// A seed reveals nothing about either: it is a domain-separated hash.
func (w *Wallet) RandaoSeed(height int64) ([]byte, error) {
	if w == nil {
		return nil, fmt.Errorf("no wallet")
	}
	m := w.lock()
	m.RLock()
	defer m.RUnlock()
	secret := w.seed
	if len(secret) == 0 {
		secret = w.Account1.secretKey.GetBytes()
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("wallet secret unavailable (locked or wiped)")
	}
	b := common.BytesToLenAndBytes([]byte(randaoSeedDomain))
	b = append(b, common.BytesToLenAndBytes(secret)...)
	b = append(b, common.GetByteInt64(height)...)
	h, err := common.CalcHashToByte(b)
	ZeroBytes(b)
	if err != nil {
		return nil, err
	}
	return h, nil
}
