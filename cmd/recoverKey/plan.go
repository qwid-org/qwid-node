package main

import (
	"fmt"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/wallet"
)

const maxRecoveryIndex = 1000

type recovery struct {
	slotPrimary bool
	newKey      common.PubKey
	secret      []byte
	next        common.Address
	bindData    []byte
}

// planRecovery works out everything both phases need, from the phrase and the
// node's PUBA answer only: which slot lacks a key of the current scheme, the
// wallet's key for it, the secret opening the effective commitment, and the
// commitment that replaces it.
func planRecovery(w *wallet.Wallet, keys wallet.RegisteredKeys) (recovery, error) {
	var r recovery
	switch {
	case !keys.HasPrimary:
		r.slotPrimary = true
		r.newKey = w.Account1.PublicKey
	case !keys.HasSecondary:
		r.newKey = w.Account2.PublicKey
	default:
		return r, fmt.Errorf("both slots already hold a key of the current scheme: nothing to recover")
	}
	if len(r.newKey.GetBytes()) == 0 {
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
	if r.secret, err = w.RecoverySecret(n); err != nil {
		return r, err
	}
	if r.next, err = w.RecoveryCommitmentAddress(n + 1); err != nil {
		return r, err
	}
	r.newKey.MainAddress = w.MainAddress
	tag, err := common.RecoveryTag(r.secret)
	if err != nil {
		return r, err
	}
	payload, err := common.RecoveryPayload(w.MainAddress, r.newKey.Address, r.next, r.secret)
	if err != nil {
		return r, err
	}
	r.bindData = transactionsDefinition.BuildRecoveryBindOptData(w.MainAddress, tag, payload)
	return r, nil
}
