package transactionsDefinition

import (
	"bytes"
	"fmt"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
)

// Pending pools a transaction enters when its block is applied.
const (
	HeldNone = iota
	HeldEscrow
	HeldMultiSig
)

// IsApproval: a co-signature of a pending multisig transaction.
func (tx Transaction) IsApproval() bool {
	return !bytes.Equal(tx.TxParam.MultiSignTx.GetBytes(), make([]byte, common.HashLength))
}

// HeldPoolOf mirrors where block application puts tx, given its sender's
// account (exists=false: no account): the escrow pool (an escrow account's
// transfer or commitment change), the multisig pool (a multisig account's, or
// an approval), or neither.
func HeldPoolOf(tx Transaction, acc account.Account, exists bool) int {
	if tx.IsRecoveryBind() || tx.IsRecoveryReveal() {
		return HeldNone
	}
	if tx.IsCommitmentRegistration() {
		switch {
		case !exists:
			return HeldNone
		case acc.TransactionDelay > 0:
			return HeldEscrow
		case acc.MultiSignNumber > 0:
			return HeldMultiSig
		}
		return HeldNone
	}
	if _, isCancellation := tx.CancellationTarget(); isCancellation {
		return HeldNone
	}
	target := tx.TxData.Recipient
	if tx.GetLockedAmount() > 0 {
		target = tx.TxData.DelegatedAccountForLocking
	}
	if _, err := account.IntDelegatedAccountFromAddress(target); err == nil || !exists {
		return HeldNone
	}
	approval := tx.IsApproval()
	switch {
	case acc.TransactionDelay > 0 && !approval:
		return HeldEscrow
	case acc.MultiSignNumber > 0 && !approval:
		return HeldMultiSig
	case approval:
		return HeldMultiSig
	}
	return HeldNone
}

// MultiSigHoldSlots is how many pool slots a multisig transaction of acc pays
// for: its own and one per signer that may approve it.
func MultiSigHoldSlots(acc account.Account) int64 {
	return 1 + int64(len(acc.MultiSignAddresses))
}

// RequiredHoldFee is what tx owes, beyond the ordinary minimum fee, for the
// pool slots it will hold (audit 2026-11-13, F-POOL-01): an escrow transfer
// the account's delay; a multisig transaction the whole approval window for
// itself and each signer (the unused part is returned at settlement); an
// approval nothing - its transaction paid for its slot.
func RequiredHoldFee(tx Transaction, acc account.Account, exists bool) int64 {
	switch HeldPoolOf(tx, acc, exists) {
	case HeldEscrow:
		return common.HoldFee(acc.TransactionDelay)
	case HeldMultiSig:
		if tx.IsApproval() {
			return 0
		}
		per := common.HoldFee(common.MaxTransactionInMultiSigPool)
		slots := MultiSigHoldSlots(acc)
		if per > 0 && slots > (int64(^uint64(0)>>1))/per {
			return int64(^uint64(0) >> 1)
		}
		return per * slots
	}
	return 0
}

// PaysHoldFee reports whether tx's fee covers the minimum and hold.
func PaysHoldFee(tx Transaction, hold int64) bool {
	fee, err := tx.CalcFee()
	return err == nil && fee >= tx.MinGasUsage()+hold
}

// ApplyHoldFee raises tx's gas price - and, beyond MaxGasPrice, its declared
// gas - so that its fee covers the minimum fee plus hold. Wallets call it
// before hashing and signing. Raising the price rather than the gas keeps the
// block gas limit for computation.
func ApplyHoldFee(tx *Transaction, hold int64) error {
	if hold <= 0 || PaysHoldFee(*tx, hold) {
		return nil
	}
	if tx.GasUsage < tx.MinGasUsage() {
		tx.GasUsage = tx.MinGasUsage()
	}
	need := tx.MinGasUsage() + hold
	price := (need + tx.GasUsage - 1) / tx.GasUsage
	if price <= common.MaxGasPrice {
		if price > tx.GasPrice {
			tx.GasPrice = price
		}
		return nil
	}
	tx.GasPrice = common.MaxGasPrice
	gas := (need + common.MaxGasPrice - 1) / common.MaxGasPrice
	if gas > common.MaxGasUsage {
		return fmt.Errorf("the hold fee %d exceeds the largest fee a transaction can carry", hold)
	}
	if gas > tx.GasUsage {
		tx.GasUsage = gas
	}
	return nil
}

// ApplyHoldFeeFromAccount is ApplyHoldFee for a wallet: acctReply is the
// node's answer to the RPC ACCT for tx's sender. A reply that is no account
// leaves tx unchanged - the node refuses a held transaction that pays too
// little, with a reason, either way.
func ApplyHoldFeeFromAccount(tx *Transaction, acctReply []byte) error {
	var acc account.Account
	if err := acc.Unmarshal(acctReply); err != nil {
		return nil
	}
	exists := acc.Address == tx.TxParam.Sender.ByteValue
	return ApplyHoldFee(tx, RequiredHoldFee(*tx, acc, exists))
}
