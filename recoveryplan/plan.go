// Package recoveryplan works out a key recovery - by recovery commitment, or
// by opening an account that never registered a key - from a wallet and the
// node's answer about its identity. Shared by cmd/recoverKey and the web UI so
// the rules exist once (CLAUDE.md "Recovery commitment").
package recoveryplan

import (
	"fmt"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/wallet"
)

// maxRecoveryIndex bounds the search for the secret behind a commitment.
const maxRecoveryIndex = 1000

// errNothingToRecover: the account still has a registered key of the live
// scheme, so it signs as it is.
var errNothingToRecover = fmt.Errorf("nothing to recover: your registered key of the live signature scheme still works")

// Plan is everything both recovery phases need: which slot the new key
// joins, the new key, the secret that opens the bind and the commitments the
// account ends with - for either mode.
type Plan struct {
	SlotPrimary bool
	NewKey      common.PubKey
	Secret      []byte // S (commitment mode) or the old public key (address mode)
	Next        common.Address
	BindData    []byte   // OptData of the bind transaction
	BindKey     [32]byte // where the bind is stored on chain

	// Address opening: the account never registered a key, so the key its
	// address is the hash of - of whatever scheme - opens it.
	AddressMode bool
	Spare       common.Address
	OldScheme   string
	OldPub      []byte
	OldSig      []byte
}

// planRecovery works out everything both phases need, from the phrase and the
// node's PUBA answer only: which slot lacks a key of the current scheme, the
// wallet's key for it, the secret opening the effective commitment, and the
// commitment that replaces it.
// Make plans a recovery for wallet w from the node's PUBA answer: address
// opening for an account with no key and no commitments, otherwise recovery
// through its recovery commitment. defaultSchemes are the built-in schemes,
// where an old address key may come from.
func Make(w *wallet.Wallet, keys wallet.RegisteredKeys, primaryPaused bool, defaultSchemes []string) (Plan, error) {
	var r Plan
	if !keys.AnyPrimary && !keys.AnySecondary && !keys.HasCommitments() {
		return planAddressOpening(w, primaryPaused, defaultSchemes)
	}
	// A registered key of the live scheme still signs: nothing to recover. A
	// missing spare is no reason - it stays unpublished on purpose, behind its
	// committed address, until the live key's scheme fails.
	if (keys.HasPrimary && !primaryPaused) || (keys.HasSecondary && primaryPaused) {
		return r, errNothingToRecover
	}
	switch {
	case !keys.HasPrimary:
		r.SlotPrimary = true
		r.NewKey = w.Account1.PublicKey
	case !keys.HasSecondary:
		r.NewKey = w.Account2.PublicKey
	default:
		return r, errNothingToRecover
	}
	if len(r.NewKey.GetBytes()) == 0 {
		return r, fmt.Errorf("the wallet has no key for the slot to recover; load it with the current schemes")
	}
	var zero common.Address
	if keys.RecoveryCommit == zero {
		return r, fmt.Errorf("the identity has no effective recovery commitment")
	}
	n, err := w.FindRecoveryIndex(keys.RecoveryCommit, maxRecoveryIndex)
	if err != nil {
		return r, err
	}
	if r.Secret, err = w.RecoverySecret(n); err != nil {
		return r, err
	}
	if r.Next, err = w.RecoveryCommitmentAddress(n + 1); err != nil {
		return r, err
	}
	r.NewKey.MainAddress = w.MainAddress
	tag, err := common.RecoveryTag(r.Secret)
	if err != nil {
		return r, err
	}
	payload, err := common.RecoveryPayload(w.MainAddress, r.NewKey.Address, r.Next, r.Secret)
	if err != nil {
		return r, err
	}
	r.BindData = transactionsDefinition.BuildRecoveryBindOptData(w.MainAddress, tag, payload)
	r.BindKey = common.RecoveryBindKey(w.MainAddress, tag)
	return r, nil
}

// planAddressOpening opens an account that never registered a key: the new
// key is the wallet's key of the LIVE scheme, the spare commitment points at
// its other key, the recovery commitment is C_0, and the old key behind the
// address signs all of it.
func planAddressOpening(w *wallet.Wallet, primaryPaused bool, defaultSchemes []string) (Plan, error) {
	r := Plan{AddressMode: true, SlotPrimary: !primaryPaused}
	if r.SlotPrimary {
		r.NewKey, r.Spare = w.Account1.PublicKey, w.Account2.Address
	} else {
		r.NewKey, r.Spare = w.Account2.PublicKey, w.Account1.Address
	}
	if len(r.NewKey.GetBytes()) == 0 {
		return r, fmt.Errorf("the wallet has no key of the live scheme; load it with the current schemes")
	}
	r.NewKey.MainAddress = w.MainAddress
	if c, err := w.RecoveryCommitmentAddress(0); err == nil {
		r.Next = c
	}
	msg, err := common.AddressOpenMessage(w.MainAddress, r.NewKey.Address, r.Next, r.Spare)
	if err != nil {
		return r, err
	}
	schemes := append(append([]string{}, defaultSchemes...), w.SigName, w.SigName2)
	if r.OldScheme, r.OldPub, r.OldSig, err = w.SignWithAddressKey(msg, schemes); err != nil {
		return r, err
	}
	tag, err := common.RecoveryTag(r.OldPub)
	if err != nil {
		return r, err
	}
	payload, err := common.AddressOpenPayload(w.MainAddress, r.NewKey.Address, r.Next, r.Spare, r.OldPub)
	if err != nil {
		return r, err
	}
	r.BindData = transactionsDefinition.BuildRecoveryBindOptData(w.MainAddress, tag, payload)
	r.BindKey = common.RecoveryBindKey(w.MainAddress, tag)
	return r, nil
}

// RevealOptData is the OptData of the reveal transaction for this plan.
func (p Plan) RevealOptData() []byte {
	if p.AddressMode {
		return transactionsDefinition.BuildAddressRevealOptData(transactionsDefinition.AddressReveal{
			Next: p.Next, Spare: p.Spare, OldScheme: p.OldScheme, OldPub: p.OldPub, OldSig: p.OldSig,
		})
	}
	return transactionsDefinition.BuildRecoveryRevealOptData(p.Secret, p.Next)
}
