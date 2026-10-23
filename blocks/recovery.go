package blocks

import (
	"bytes"
	"fmt"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
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

	case tx.IsAddressReveal():
		r, err := transactionsDefinition.ParseAddressReveal(tx.TxData.OptData)
		if err != nil {
			return true, err
		}
		acc, ok := account.GetAccountByAddressBytes(sender.GetBytes())
		if !ok || acc.HasCommitments() {
			return true, fmt.Errorf("%s was opened before its address reveal applied", sender.GetHex())
		}
		tag, err := common.RecoveryTag(r.OldPub)
		if err != nil {
			return true, err
		}
		account.AddTransactionsSender(sender.ByteValue, tx.GetHash())
		// The account's first commitments: they apply at once.
		if err := account.SetAccountCommitments(sender.ByteValue, r.Spare.ByteValue, r.Next.ByteValue, height); err != nil {
			return true, err
		}
		account.DeleteRecoveryBind(common.RecoveryBindKey(sender, tag))
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
		// A commitment change hands control of the account over after a
		// scheme break, so it is held exactly like a transfer: an escrow
		// account's waits out its delay (and can be cancelled meanwhile), a
		// multisig account's needs its approvals. Its maturity then counts
		// from settlement (settleCommitment), not from inclusion. The fee is
		// paid up front, as for every escrow and multisig transaction.
		acc, ok := account.GetAccountByAddressBytes(sender.GetBytes())
		if !ok {
			return true, fmt.Errorf("no account %s for a recovery commitment", sender.GetHex())
		}
		account.AddTransactionsSender(sender.ByteValue, tx.GetHash())
		switch {
		case acc.TransactionDelay > 0:
			tx.Height = height
			transactionsPool.AddEscrowTransaction(tx)
		case acc.MultiSignNumber > 0:
			tx.Height = height
			transactionsPool.AddMultiSignTransaction(tx)
		default:
			if err := settleCommitment(tx, height); err != nil {
				return true, err
			}
		}
		return true, AddBalance(sender.ByteValue, -fee)
	}
	return false, nil
}

// settleCommitment makes a commitment registration take effect: its spare
// address and recovery commitment become the sender's (account.SetCommitments:
// at once for an account's first, maturing from height for later ones).
func settleCommitment(tx transactionsDefinition.Transaction, height int64) error {
	spare, recovery := tx.CommitmentValues()
	return account.SetAccountCommitments(tx.GetSenderAddress().ByteValue, spare, recovery, height)
}

// applyRecoveryMaintenance runs after a block's transfers: expired binds go,
// and a block that marks a scheme as broken voids every commitment that had
// not matured - it may have been written with a key of that scheme.
func applyRecoveryMaintenance(newBlock, lastBlock Block) {
	h := newBlock.GetHeader().Height
	account.PruneRecoveryBinds(h)
	if schemeBroken(newBlock, lastBlock) {
		if n := account.VoidPendingRecoveryCommits(h); n > 0 {
			logger.GetLogger().Printf("signature scheme marked broken at block %d: voided %d unmatured recovery commitment(s)", h, n)
		}
	}
}

// schemeBroken reports whether newBlock marks a scheme as broken: it pauses
// the live primary, or replaces the spare. Those are the only changes after
// which a recent signature may be a forgery. Replacing an already-paused
// primary, or un-pausing one, breaks nothing new - voiding there would
// destroy the commitments users set with the live spare right after the
// break, since those changes can follow it within blocks.
func schemeBroken(newBlock, lastBlock Block) bool {
	nh, lh := newBlock.GetHeader(), lastBlock.GetHeader()
	if !bytes.Equal(nh.Encryption1, lh.Encryption1) {
		cur, cerr := oqs.FromBytesToEncryptionConfig(lh.Encryption1)
		next, nerr := oqs.FromBytesToEncryptionConfig(nh.Encryption1)
		if cerr != nil || nerr != nil {
			return true // unreadable: assume the worst
		}
		if next.SigName == cur.SigName && next.IsPaused && !cur.IsPaused {
			return true
		}
	}
	if !bytes.Equal(nh.Encryption2, lh.Encryption2) {
		cur, cerr := oqs.FromBytesToEncryptionConfig(lh.Encryption2)
		next, nerr := oqs.FromBytesToEncryptionConfig(nh.Encryption2)
		if cerr != nil || nerr != nil {
			return true
		}
		if next.SigName != cur.SigName {
			return true
		}
	}
	return false
}
