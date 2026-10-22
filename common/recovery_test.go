package common

import (
	"bytes"
	"testing"
)

func secretOf(b byte) []byte { return bytes.Repeat([]byte{b}, RecoverySecretLength) }

func TestRecoveryAddressesAreReservedAndDistinct(t *testing.T) {
	if RecoveryBindAddress == RecoveryRevealAddress {
		t.Fatal("bind and reveal share an address")
	}
	if !IsRecoveryAddress(RecoveryBindAddress) || !IsRecoveryAddress(RecoveryRevealAddress) {
		t.Fatal("reserved address not recognised")
	}
	var plain Address
	plain.ByteValue[19] = 7
	if IsRecoveryAddress(plain) {
		t.Fatal("ordinary address recognised as reserved")
	}
}

func TestRecoveryHashesAreDomainSeparatedAndDeterministic(t *testing.T) {
	c1, err := RecoveryCommitment(secretOf(1))
	if err != nil {
		t.Fatal(err)
	}
	c1b, _ := RecoveryCommitment(secretOf(1))
	c2, _ := RecoveryCommitment(secretOf(2))
	if c1 != c1b || c1 == c2 {
		t.Fatal("commitment not deterministic or not secret-dependent")
	}
	tag, err := RecoveryTag(secretOf(1))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(tag[:20], c1.ByteValue[:]) {
		t.Fatal("tag and commitment share a prefix: domains not separated")
	}
	var id, k, next Address
	id.ByteValue[0], k.ByteValue[0], next.ByteValue[0] = 1, 2, 3
	p1, _ := RecoveryPayload(id, k, next, secretOf(1))
	k.ByteValue[0] = 9
	p2, _ := RecoveryPayload(id, k, next, secretOf(1))
	if p1 == p2 {
		t.Fatal("payload does not bind the new key")
	}
	if RecoveryBindKey(id, tag) == RecoveryBindKey(next, tag) {
		t.Fatal("bind key does not bind the identity")
	}
}

func TestRecoveryCommitmentRejectsWrongSecretLength(t *testing.T) {
	if _, err := RecoveryCommitment([]byte{1, 2, 3}); err == nil {
		t.Fatal("short secret accepted")
	}
}
