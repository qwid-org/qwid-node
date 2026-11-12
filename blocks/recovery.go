package blocks

import (
	"bytes"
	"fmt"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/pubkeys"
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
		// A repeated bind changes nothing but still pays.
		account.AddRecoveryBind(common.RecoveryBindKey(identity, tag, payload),
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
		payload, err := common.AddressOpenPayload(sender, tx.TxData.Pubkey.Address, r.Next, r.Spare, r.OldPub)
		if err != nil {
			return true, err
		}
		account.AddTransactionsSender(sender.ByteValue, tx.GetHash())
		// An address reveal opens the account (no key of it was registered,
		// checked against the parent): its commitments apply at once.
		if err := account.SetAccountCommitments(sender.ByteValue, r.Spare.ByteValue, r.Next.ByteValue, height, true); err != nil {
			return true, err
		}
		account.DeleteRecoveryBind(common.RecoveryBindKey(sender, tag, payload))
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
		payload, err := common.RecoveryPayload(sender, tx.TxData.Pubkey.Address, next, secret)
		if err != nil {
			return true, err
		}
		account.AddTransactionsSender(sender.ByteValue, tx.GetHash())
		if err := account.ConsumeAccountRecoveryCommit(sender.ByteValue, next.ByteValue); err != nil {
			return true, err
		}
		account.DeleteRecoveryBind(common.RecoveryBindKey(sender, tag, payload))
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
			if err := settleCommitment(tx, height, opensAccount(sender, height)); err != nil {
				return true, err
			}
		}
		return true, AddBalance(sender.ByteValue, -fee)
	}
	return false, nil
}

// opensAccount reports whether a registration included at height is the one
// that opens sender's account: no key of the identity was registered by the
// parent block, so the key it carries is the first ever published.
func opensAccount(sender common.Address, height int64) bool {
	_, err := pubkeys.LoadAddressesAsOf(sender, height-1)
	return err != nil
}

// settleCommitment makes a commitment registration take effect: its spare
// address and recovery commitment become the sender's (account.SetCommitments:
// at once when the registration opens the account, maturing from height
// otherwise). A registration held in escrow or for approvals never opens an
// account - it had a policy, so it existed - and always matures.
func settleCommitment(tx transactionsDefinition.Transaction, height int64, opening bool) error {
	spare, recovery := tx.CommitmentValues()
	return account.SetAccountCommitments(tx.GetSenderAddress().ByteValue, spare, recovery, height, opening)
}

// applyRecoveryMaintenance runs after a block's transfers: expired binds go,
// and a block that marks a scheme as broken voids every commitment that had
// not matured, and every key that was vouched for by another key's signature
// as recently - either may have been written with a key of that scheme.
func applyRecoveryMaintenance(newBlock, lastBlock Block) {
	h := newBlock.GetHeader().Height
	account.PruneRecoveryBinds(h)
	recordRetiredSchemes(newBlock, lastBlock)
	if schemeBroken(newBlock, lastBlock) {
		// Keys that joined an identity on another key's signature within the
		// same period are void from this block on (P-01).
		if err := pubkeys.RecordSchemeBreak(h); err != nil {
			logger.GetLogger().Printf("ERROR: cannot record the scheme break at block %d: %v", h, err)
		}
		if n := account.VoidPendingRecoveryCommits(h); n > 0 {
			logger.GetLogger().Printf("signature scheme marked broken at block %d: voided %d unmatured recovery commitment(s)", h, n)
		}
		if n := voidHeldCommitmentRegistrations(h); n > 0 {
			logger.GetLogger().Printf("signature scheme marked broken at block %d: voided %d commitment change(s) held in escrow or awaiting approvals", h, n)
		}
	}
}

// voidHeldCommitmentRegistrations removes, at a scheme break, the commitment
// changes still waiting in the escrow and multisig pools (P-04). They are
// pending in every sense that matters - not in force, and possibly signed with
// the scheme just exposed - but live outside the account state that
// VoidPendingRecoveryCommits clears, so they used to settle after the break
// and mature a week later. The approvals collected for a multisig one go with
// it. Removals are journalled under the block's height, like every pool
// change, so a rewind returns them.
func voidHeldCommitmentRegistrations(height int64) int {
	transactionsPool.ResumePendingPoolJournal(height)
	defer transactionsPool.EndPendingPoolJournal()
	n := 0
	for _, e := range transactionsPool.PoolTxEscrow.PeekEntries(transactionsPool.PoolTxEscrow.NumberOfTransactions()) {
		if e.Transaction.IsCommitmentRegistration() {
			transactionsPool.RemoveEscrowTransaction(e.Transaction.Hash.GetBytes())
			n++
		}
	}
	held := transactionsPool.PoolTxMultiSign.PeekEntries(transactionsPool.PoolTxMultiSign.NumberOfTransactions())
	voided := map[common.Hash]bool{}
	for _, e := range held {
		if bytes.Equal(e.Transaction.TxParam.MultiSignTx.GetBytes(), ZerosHash) && e.Transaction.IsCommitmentRegistration() {
			voided[e.Transaction.Hash] = true
			n++
		}
	}
	for _, e := range held {
		if voided[e.Transaction.Hash] || voided[e.Transaction.TxParam.MultiSignTx] {
			transactionsPool.RemoveMultiSignTransaction(e.Transaction.Hash.GetBytes())
		}
	}
	return n
}

// recordRetiredSchemes notes every scheme newBlock replaces in a slot (P-08):
// addresses derived from its keys can still be opened by revealing the key
// (verifyAddressOpening), which accepts schemes in force or retired only.
func recordRetiredSchemes(newBlock, lastBlock Block) {
	nh, lh := newBlock.GetHeader(), lastBlock.GetHeader()
	for _, slot := range [][2][]byte{{lh.Encryption1, nh.Encryption1}, {lh.Encryption2, nh.Encryption2}} {
		if bytes.Equal(slot[0], slot[1]) {
			continue
		}
		cur, cerr := oqs.FromBytesToEncryptionConfig(slot[0])
		next, nerr := oqs.FromBytesToEncryptionConfig(slot[1])
		if cerr != nil || nerr != nil || cur.SigName == next.SigName {
			continue
		}
		if err := pubkeys.RecordRetiredScheme(nh.Height, cur.SigName); err != nil {
			logger.GetLogger().Printf("ERROR: cannot record the retired scheme %q at block %d: %v", cur.SigName, nh.Height, err)
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
