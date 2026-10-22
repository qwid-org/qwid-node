package blocks

import (
	"bytes"
	"fmt"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// processRecoveryTransaction applies the three recovery transaction kinds
// (CLAUDE.md "Recovery commitment"). None moves coins beyond its fee, none
// touches its Recipient's account: for a commitment the Recipient is a hash,
// for a bind or reveal a reserved address.
func processRecoveryTransaction(tx transactionsDefinition.Transaction, height, fee int64) (bool, error) {
	sender := tx.GetSenderAddress()
	switch {
	case tx.IsRecoveryBind():
		identity, tag, payload, err := transactionsDefinition.ParseRecoveryBind(tx.TxData.OptData)
		if err != nil {
			return true, err
		}
		account.AddTransactionsSender(sender.ByteValue, tx.GetHash())
		// A later bind of the same tag changes nothing but still pays.
		account.AddRecoveryBind(common.RecoveryBindKey(identity, tag),
			account.RecoveryBind{Identity: identity.ByteValue, Payload: payload, Height: height})
		return true, AddBalance(sender.ByteValue, -fee)

	case tx.IsRecoveryReveal():
		secret, next, err := transactionsDefinition.ParseRecoveryReveal(tx.TxData.OptData)
		if err != nil {
			return true, err
		}
		acc, ok := account.GetAccountByAddressBytes(sender.GetBytes())
		c, err := common.RecoveryCommitment(secret)
		if err != nil {
			return true, err
		}
		// Verified against the parent; re-check against the state this block
		// has built so far.
		if !ok || c.ByteValue != acc.EffectiveRecoveryCommit(height) {
			return true, fmt.Errorf("recovery commitment of %s changed before its reveal applied", sender.GetHex())
		}
		tag, err := common.RecoveryTag(secret)
		if err != nil {
			return true, err
		}
		account.AddTransactionsSender(sender.ByteValue, tx.GetHash())
		if err := account.ConsumeAccountRecoveryCommit(sender.ByteValue, next.ByteValue); err != nil {
			return true, err
		}
		account.DeleteRecoveryBind(common.RecoveryBindKey(sender, tag))
		return true, AddBalance(sender.ByteValue, -fee)

	case tx.IsCommitmentRegistration():
		account.AddTransactionsSender(sender.ByteValue, tx.GetHash())
		if err := account.SetAccountPendingRecoveryCommit(sender.ByteValue, tx.TxData.Recipient.ByteValue, height); err != nil {
			return true, err
		}
		return true, AddBalance(sender.ByteValue, -fee)
	}
	return false, nil
}

// applyRecoveryMaintenance runs after a block's transfers: expired binds go,
// and a change of signature schemes voids every commitment that had not
// matured - it may have been written with the key of a scheme now paused as
// broken.
func applyRecoveryMaintenance(newBlock, lastBlock Block) {
	h := newBlock.GetHeader().Height
	account.PruneRecoveryBinds(h)
	nh, lh := newBlock.GetHeader(), lastBlock.GetHeader()
	if !bytes.Equal(nh.Encryption1, lh.Encryption1) || !bytes.Equal(nh.Encryption2, lh.Encryption2) {
		if n := account.VoidPendingRecoveryCommits(h); n > 0 {
			logger.GetLogger().Printf("signature schemes changed at block %d: voided %d unmatured recovery commitment(s)", h, n)
		}
	}
}
