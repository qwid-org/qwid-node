package common

import (
	"bytes"
	"fmt"
	"hash"

	"github.com/qwid-org/qwid-node/crypto/blake2b"
)

// Hash-only key recovery (see CLAUDE.md "Recovery commitment"). Every value
// here is a hash of a secret S derived from the wallet's BIP39 phrase, so the
// protocol rests on Blake2b alone - no signature scheme, which is the point:
// it must still work when every signature scheme an identity holds is broken.
const (
	RecoveryCommitMaturityBlocks int64 = 60480  // ~1 week: a new commitment is effective after this
	RecoveryBindDelayBlocks      int64 = 360    // ~1 h: minimum age of a bind before its reveal
	RecoveryBindExpiryBlocks     int64 = 120960 // ~2 weeks: binds older than this are pruned
	RecoverySecretLength               = 32
	RecoveryBindOptDataLength          = AddressLength + 32 + 32
	RecoveryRevealOptDataLength        = RecoverySecretLength + AddressLength
)

// Reserved recipients. Not delegated-format (byte 2.. is non-zero), so they
// are never routed to staking, rewards or the DEX.
var (
	RecoveryBindAddress   = recoveryAddress('B')
	RecoveryRevealAddress = recoveryAddress('R')
)

func recoveryAddress(kind byte) Address {
	var a Address
	for i := 0; i < AddressLength-2; i++ {
		a.ByteValue[i] = 0xFF
	}
	a.ByteValue[AddressLength-2] = 'R'
	a.ByteValue[AddressLength-1] = kind
	a.Primary = true
	return a
}

func IsRecoveryAddress(a Address) bool {
	return bytes.Equal(a.GetBytes(), RecoveryBindAddress.GetBytes()) ||
		bytes.Equal(a.GetBytes(), RecoveryRevealAddress.GetBytes())
}

func recoveryHash(size int, domain string, parts ...[]byte) ([]byte, error) {
	var h hash.Hash
	var err error
	if size == 20 {
		h, err = blake2b.New160(nil)
	} else {
		h, err = blake2b.New256(nil)
	}
	if err != nil {
		return nil, err
	}
	h.Write(BytesToLenAndBytes([]byte(domain)))
	for _, p := range parts {
		h.Write(BytesToLenAndBytes(p))
	}
	return h.Sum(nil), nil
}

// RecoveryCommitment is C = H160(S), carried in a registration's Recipient.
func RecoveryCommitment(secret []byte) (Address, error) {
	if len(secret) != RecoverySecretLength {
		return Address{}, fmt.Errorf("recovery secret must be %d bytes, got %d", RecoverySecretLength, len(secret))
	}
	b, err := recoveryHash(20, "qwid-recovery-commit", secret)
	if err != nil {
		return Address{}, err
	}
	var a Address
	copy(a.ByteValue[:], b)
	a.Primary = true
	return a, nil
}

// RecoveryTag identifies S in a bind without revealing it. Nobody can make a
// bind with the right tag before S is public, so the first bind per tag wins.
func RecoveryTag(secret []byte) ([32]byte, error) {
	var t [32]byte
	b, err := recoveryHash(32, "qwid-recovery-tag", secret)
	if err != nil {
		return t, err
	}
	copy(t[:], b)
	return t, nil
}

// RecoveryPayload binds what the reveal will do: which key joins identity and
// which commitment replaces the consumed one.
func RecoveryPayload(identity, newKey, next Address, secret []byte) ([32]byte, error) {
	var p [32]byte
	b, err := recoveryHash(32, "qwid-recovery-payload", identity.GetBytes(), newKey.GetBytes(), next.GetBytes(), secret)
	if err != nil {
		return p, err
	}
	copy(p[:], b)
	return p, nil
}

// RecoveryBindKey is the bind store's key for (identity, tag).
func RecoveryBindKey(identity Address, tag [32]byte) [32]byte {
	var k [32]byte
	b, _ := recoveryHash(32, "qwid-recovery-bind-key", identity.GetBytes(), tag[:])
	copy(k[:], b)
	return k
}
