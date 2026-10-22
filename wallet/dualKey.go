package wallet

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

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
	}{{resp.RecoveryCommit, &k.RecoveryCommit}, {resp.RecoveryPending, &k.RecoveryPending}} {
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

// SendRefusal mirrors, for a wallet about to send, the two consensus rules a
// transaction can break through its keys alone, so the operator is told why
// instead of the node dropping the transaction. It returns "" when neither
// applies.
//
//   - Dual-key rule: until an identity holds both a primary and a secondary
//     key, it may send only pure registrations (amount 0, to itself) carrying a
//     key.
//   - Paused schemes authorise no new key, except an identity's very first
//     one registering itself (its public key is unpublished until then).
func SendRefusal(keys RegisteredKeys, carriesKey, pureRegistration, signingPaused bool) string {
	firstKey := !keys.AnyPrimary && !keys.AnySecondary
	if carriesKey && signingPaused && !firstKey {
		return "The key that would sign this registration belongs to a PAUSED signature scheme. A paused scheme " +
			"is presumed broken, so it can no longer vouch for a new key; only the identity's other, live key can. " +
			"Without one, wait until the scheme is un-paused."
	}
	if !(keys.AnyPrimary && keys.AnySecondary) && !(carriesKey && pureRegistration) {
		return fmt.Sprintf("This identity must register BOTH its keys before sending anything else "+
			"(registered: primary=%v, secondary=%v). Send a pure registration for each missing key first: "+
			"amount 0, to your own address, with the public key included - the second one after the first is in a block.",
			keys.AnyPrimary, keys.AnySecondary)
	}
	return ""
}
