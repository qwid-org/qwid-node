package wallet

import (
	"encoding/hex"
	"encoding/json"

	"github.com/qwid-org/qwid-node/common"
)

// RegisteredKeys is the node's PUBA answer about one identity.
//
// HasPrimary/HasSecondary say whether a key of the CURRENT scheme is
// registered in each slot (what can sign right now); AnyPrimary/AnySecondary
// whether any key at all is, which is what the consensus dual-key rule counts.
type RegisteredKeys struct {
	HasPrimary      bool
	HasSecondary    bool
	AnyPrimary      bool
	AnySecondary    bool
	RecoveryCommit  common.Address // effective recovery commitment, zero if none
	RecoveryPending common.Address // commitment still maturing, zero if none
	SpareCommit     common.Address // spare key address in force, zero if none
	SparePending    common.Address // spare key address still maturing, zero if none
}

// ParsePUBA reads the node's PUBA reply.
func ParsePUBA(reply []byte) (RegisteredKeys, error) {
	var resp struct {
		HasPrimary   bool `json:"hasPrimary"`
		HasSecondary bool `json:"hasSecondary"`
		Addresses    []struct {
			Primary bool `json:"primary"`
		} `json:"addresses"`
		RecoveryCommit  string `json:"recoveryCommit"`
		RecoveryPending string `json:"recoveryPending"`
		SpareCommit     string `json:"spareCommit"`
		SparePending    string `json:"sparePending"`
	}
	if err := json.Unmarshal(reply, &resp); err != nil {
		return RegisteredKeys{}, err
	}
	k := RegisteredKeys{HasPrimary: resp.HasPrimary, HasSecondary: resp.HasSecondary}
	for _, a := range resp.Addresses {
		if a.Primary {
			k.AnyPrimary = true
		} else {
			k.AnySecondary = true
		}
	}
	// A current-scheme key is a key; never report fewer than that.
	k.AnyPrimary = k.AnyPrimary || k.HasPrimary
	k.AnySecondary = k.AnySecondary || k.HasSecondary
	for _, f := range []struct {
		hexv string
		dst  *common.Address
	}{{resp.RecoveryCommit, &k.RecoveryCommit}, {resp.RecoveryPending, &k.RecoveryPending},
		{resp.SpareCommit, &k.SpareCommit}, {resp.SparePending, &k.SparePending}} {
		if f.hexv == "" {
			continue
		}
		b, err := hex.DecodeString(f.hexv)
		if err != nil {
			return RegisteredKeys{}, err
		}
		if err := f.dst.Init(b); err != nil {
			return RegisteredKeys{}, err
		}
	}
	return k, nil
}

// HasSpareCover mirrors the consensus spare rule: a spare key address
// committed to (in force or maturing), or both slots registered.
func (k RegisteredKeys) HasSpareCover() bool {
	var zero common.Address
	return k.SpareCommit != zero || k.SparePending != zero || (k.AnyPrimary && k.AnySecondary)
}

// HasCommitments reports whether the identity has any commitment yet.
func (k RegisteredKeys) HasCommitments() bool {
	var zero common.Address
	return k.RecoveryCommit != zero || k.RecoveryPending != zero || k.SpareCommit != zero || k.SparePending != zero
}

// SendRefusal mirrors, for a wallet about to send, the two consensus rules a
// transaction can break through its keys alone, so the operator is told why
// instead of the node dropping the transaction. It returns "" when neither
// applies.
//
//   - Spare rule: until an identity has a way out of a broken scheme - a
//     commitment to its spare key's address, or both keys registered - it may
//     send only key registrations (amount 0).
//   - Paused schemes authorise no new key, except an identity's very first
//     one registering itself (its public key is unpublished until then).
func SendRefusal(keys RegisteredKeys, carriesKey, pureRegistration, signingPaused bool) string {
	firstKey := !keys.AnyPrimary && !keys.AnySecondary
	if carriesKey && signingPaused && !firstKey {
		return "The key that would sign this registration belongs to a PAUSED signature scheme. A paused scheme " +
			"is presumed broken, so it can no longer vouch for a new key; only the identity's other, live key can. " +
			"Without one, wait until the scheme is un-paused."
	}
	if !keys.HasSpareCover() && !(carriesKey && pureRegistration) {
		return "This identity has no spare yet, so it can send nothing but a key registration. Register your key " +
			"with \"Include Public Key\" (amount 0, to your own address): the registration commits to your spare " +
			"key's address automatically."
	}
	return ""
}
