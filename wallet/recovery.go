package wallet

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
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

// OpeningCommitments are what the registration opening an account carries:
// Recipient = the ADDRESS of the wallet's key in the other slot than the one
// registered (the spare, whose public key stays unpublished until needed), and
// OptData = the recovery commitment C_0 (nil without a recovery phrase). ok is
// false once the identity has commitments: later registrations leave them.
func (w *Wallet) OpeningCommitments(keys RegisteredKeys, registerPrimary bool) (spare common.Address, recovery []byte, ok bool) {
	if keys.HasCommitments() {
		return common.Address{}, nil, false
	}
	spare = w.Account2.Address
	if !registerPrimary {
		spare = w.Account1.Address
	}
	if c, err := w.RecoveryCommitmentAddress(0); err == nil {
		recovery = c.GetBytes()
	}
	return spare, recovery, true
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

// SetMainAddressFromLiveScheme makes the address of the key whose scheme is
// live the wallet's identity, and has both keys name it. An identity's first
// on-chain key must be the one its address comes from; while the primary is
// paused only the spare can sign that first registration and then vouch for
// the primary key. An address taken from the paused primary key could open the
// account but never add its spare - a paused scheme vouches for nothing - so
// the account would stay frozen until the primary scheme is un-paused.
func (w *Wallet) SetMainAddressFromLiveScheme(primaryPaused bool) {
	main := w.Account1.Address
	if primaryPaused {
		main = w.Account2.Address
	}
	w.MainAddress = main
	w.Account1.PublicKey.MainAddress = main
	w.Account2.PublicKey.MainAddress = main
}

// SignWithAddressKey signs msg with the key whose address is the wallet's
// identity, whichever scheme it belongs to - possibly one the chain no longer
// uses, so not Account1/Account2 any more. It is rederived from the phrase for
// each candidate scheme (both slots), or taken from the per-scheme key archive.
// Used to open an account that never registered a key (an address opening).
func (w *Wallet) SignWithAddressKey(msg []byte, schemes []string) (sigName string, pub, sig []byte, err error) {
	if w.HasSeed() {
		for _, name := range schemes {
			for _, primary := range []bool{true, false} {
				acc, derr := GenerateNewAccountFromSeed(*w, name, primary)
				if derr != nil || acc.Address.ByteValue != w.MainAddress.ByteValue {
					continue
				}
				s, serr := acc.signer.Sign(msg)
				acc.signer.Clean()
				return name, acc.PublicKey.GetBytes(), s, serr
			}
		}
	}
	for name, a := range w.Accounts {
		if a.Address.ByteValue != w.MainAddress.ByteValue {
			continue
		}
		secret, derr := w.decrypt(a.EncryptedSecretKey)
		if derr != nil {
			continue
		}
		var signer oqs.Signature
		ierr := signer.Init(name, secret)
		ZeroBytes(secret)
		if ierr != nil {
			signer.Clean()
			continue
		}
		s, serr := signer.Sign(msg)
		signer.Clean()
		return name, a.PublicKey.GetBytes(), s, serr
	}
	return "", nil, nil, fmt.Errorf("no key of this wallet hashes to its address %s (tried %v and the key archive)",
		w.MainAddress.GetHex(), schemes)
}
