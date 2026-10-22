package wallet

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/qwid-org/qwid-node/common"
)

const recoverySecretDomain = "qwid-recovery-secret"

// RecoverySecret is S_n, the n-th one-time recovery secret of this identity
// (CLAUDE.md "Recovery commitment"). It is derived from the BIP39 seed and
// never stored: the phrase is its only backup. There is deliberately no
// fallback to a secret key - breaking a signature scheme can expose secret
// keys, and S must survive exactly that.
func (w *Wallet) RecoverySecret(n uint32) ([]byte, error) {
	if w == nil {
		return nil, fmt.Errorf("no wallet")
	}
	m := w.lock()
	m.RLock()
	defer m.RUnlock()
	if len(w.seed) == 0 {
		return nil, fmt.Errorf("wallet has no recovery phrase: recovery secrets cannot be derived")
	}
	b := common.BytesToLenAndBytes([]byte(recoverySecretDomain))
	b = append(b, common.BytesToLenAndBytes(w.seed)...)
	b = append(b, w.MainAddress.GetBytes()...)
	b = binary.BigEndian.AppendUint32(b, n)
	h, err := common.CalcHashToByte(b)
	ZeroBytes(b)
	return h, err
}

// RecoveryCommitmentAddress is C_n = H160(S_n), the value a registration
// carries in its Recipient.
func (w *Wallet) RecoveryCommitmentAddress(n uint32) (common.Address, error) {
	s, err := w.RecoverySecret(n)
	if err != nil {
		return common.Address{}, err
	}
	defer ZeroBytes(s)
	return common.RecoveryCommitment(s)
}

// FindRecoveryIndex finds n with C_n == c, so the wallet never has to store
// which secret is current: the chain holds C, the phrase holds every S.
func (w *Wallet) FindRecoveryIndex(c common.Address, limit uint32) (uint32, error) {
	for n := uint32(0); n < limit; n++ {
		cn, err := w.RecoveryCommitmentAddress(n)
		if err != nil {
			return 0, err
		}
		if bytes.Equal(cn.GetBytes(), c.GetBytes()) {
			return n, nil
		}
	}
	return 0, fmt.Errorf("commitment %s is not one of this wallet's first %d", c.GetHex(), limit)
}

// CommitmentForRegistration is the Recipient a key registration should carry:
// C_0 for an identity with no commitment at all, otherwise the identity itself
// (no change - re-sending a commitment would restart its maturity clock).
func (w *Wallet) CommitmentForRegistration(keys RegisteredKeys) (common.Address, error) {
	var zero common.Address
	if !bytes.Equal(keys.RecoveryCommit.GetBytes(), zero.GetBytes()) ||
		!bytes.Equal(keys.RecoveryPending.GetBytes(), zero.GetBytes()) {
		return w.MainAddress, nil
	}
	return w.RecoveryCommitmentAddress(0)
}

// NewTestRecoveryWallet builds a wallet with a seed and a primary public key
// only - for tests of recovery tooling outside this package.
func NewTestRecoveryWallet(seed, primaryPub []byte) *Wallet {
	w := &Wallet{seed: seed}
	w.MainAddress.ByteValue[0] = 0xAA
	w.MainAddress.Primary = true
	_ = w.Account1.PublicKey.Init(primaryPub, w.MainAddress)
	return w
}
