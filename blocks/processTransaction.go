package blocks

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/pubkeys"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

var ZerosHash = make([]byte, common.HashLength)

// ErrEscrowAlreadyMatured marks the one cancellation failure that can never
// reverse: once the chain passes the escrow's maturity height it never goes
// back, so such a cancellation is permanently unusable and must be evicted
// from the pool rather than retried. Every other failure may be transient —
// the target's block might simply not have been processed here yet.
var ErrEscrowAlreadyMatured = errors.New("escrow transaction has already matured")

func validateEscrowCancellation(tx transactionsDefinition.Transaction, height int64) (transactionsDefinition.Transaction, error) {
	targetHash, ok := tx.CancellationTarget()
	if !ok {
		return transactionsDefinition.Transaction{}, fmt.Errorf("not a cancellation transaction")
	}
	senderAddress := tx.GetSenderAddress()
	if tx.TxData.Amount != 0 || !bytes.Equal(tx.TxData.Recipient.GetBytes(), senderAddress.GetBytes()) ||
		tx.TxData.LockedAmount != 0 || tx.TxData.MultiSignNumber != 0 ||
		!bytes.Equal(tx.TxParam.MultiSignTx.GetBytes(), ZerosHash) {
		return transactionsDefinition.Transaction{}, fmt.Errorf("cancellation must have zero amount and target the sender account")
	}
	target, exists := transactionsPool.PoolTxEscrow.GetTransactionByHash(targetHash.GetBytes())
	if !exists {
		return transactionsDefinition.Transaction{}, fmt.Errorf("escrow transaction is not pending")
	}
	targetSender := target.GetSenderAddress()
	if !bytes.Equal(targetSender.GetBytes(), senderAddress.GetBytes()) {
		return transactionsDefinition.Transaction{}, fmt.Errorf("only the escrow transaction owner can cancel it")
	}
	sender, exists := account.GetAccountByAddressBytes(senderAddress.GetBytes())
	if !exists || sender.TransactionDelay <= 0 {
		return transactionsDefinition.Transaction{}, fmt.Errorf("cancellation sender is not an escrow account")
	}
	if height >= target.GetHeight()+sender.TransactionDelay {
		return transactionsDefinition.Transaction{}, ErrEscrowAlreadyMatured
	}
	return target, nil
}

// CountMultiSignApprovals reports how many valid approvals mainTx has within
// group, and how many its sender account requires. group is the multisig pool
// entries keyed by mainTx's hash — the main transaction plus every co-signature
// aimed at it.
//
// It mirrors the rule ProcessTransactionsMultiSign applies: an entry counts
// only when its sender is an authorised signer that has not already been
// counted, its recipient equals the main transaction's, and its amount is
// zero. The main transaction therefore never approves itself, which is the
// part owners get wrong.
//
// Used both by ProcessTransactionsMultiSign to decide settlement and by the
// PEND RPC to report progress, so the wallet can never disagree with the node
// about how many signatures are in.
//
// It copies the authorised-signer slice. Reslicing acc.MultiSignAddresses in
// place — as the settlement loop once did — mutates the account held in the
// global map, because a value copy of an Account shares the slice's backing
// array.
func CountMultiSignApprovals(mainTx transactionsDefinition.Transaction,
	group []transactionsDefinition.Transaction) (approvals int, required int) {

	acc, exists := account.GetAccountByAddressBytes(mainTx.TxParam.Sender.GetBytes())
	if !exists {
		return 0, 0
	}
	required = int(acc.MultiSignNumber)

	notApprovedYet := append([][common.AddressLength]byte(nil), acc.MultiSignAddresses...)
	for _, t := range group {
		if t.TxData.Amount != 0 ||
			!bytes.Equal(mainTx.TxData.Recipient.GetBytes(), t.TxData.Recipient.GetBytes()) {
			continue
		}
		sender := t.TxParam.Sender.ByteValue
		for i, appr := range notApprovedYet {
			if sender == appr {
				approvals++
				notApprovedYet = append(notApprovedYet[:i], notApprovedYet[i+1:]...)
				break
			}
		}
	}
	return approvals, required
}

// EscrowMaturityHeight reports the height at which a pooled escrow transaction
// becomes settleable, or 0 when the sender is unknown or is not an escrow
// account.
//
// It reads the delay from the SENDER ACCOUNT, which is what
// ProcessTransactionsEscrow gates on and what validateEscrowCancellation
// measures the cancellation window with. Note that this is deliberately NOT
// tx.Height + tx.TxData.EscrowTransactionsDelay, the key the escrow pool
// happens to be ordered by: that field is only ever set on a ModifyEscrow
// configuration transaction, so on an ordinary transfer it is zero and the
// pool's ordering key equals the transaction's own height — a height already
// in the past, useless as a settlement estimate.
func EscrowMaturityHeight(tx transactionsDefinition.Transaction) int64 {
	sender := tx.GetSenderAddress()
	acc, exists := account.GetAccountByAddressBytes(sender.GetBytes())
	if !exists || acc.TransactionDelay <= 0 {
		return 0
	}
	return tx.GetHeight() + acc.TransactionDelay
}

// FilterUnbuildableCancellations returns txs without the escrow cancellations
// that would make a block at the given height fail validation, and evicts the
// permanently dead ones from the main pool.
//
// Block assembly used to hand every pooled transaction to the block and let
// CheckBlockTransfers judge the result. That is fine when a rejection is
// transient, but a cancellation whose target has matured fails forever: the
// producer logged the error and returned, leaving the transaction in the pool,
// so the next block was assembled from the same set and failed identically.
// Block production stopped for good (seen at height 139793).
//
// The validation rule itself is unchanged — a block containing such a
// transaction is still invalid. This only stops the node from proposing one.
func FilterUnbuildableCancellations(txs []transactionsDefinition.Transaction, height int64) []transactionsDefinition.Transaction {
	kept := txs[:0]
	for _, tx := range txs {
		if _, isCancellation := tx.CancellationTarget(); !isCancellation {
			kept = append(kept, tx)
			continue
		}
		_, err := validateEscrowCancellation(tx, height)
		if err == nil {
			kept = append(kept, tx)
			continue
		}
		if errors.Is(err, ErrEscrowAlreadyMatured) {
			// Unusable at every future height; keeping it would re-poison
			// every subsequent block.
			logger.GetLogger().Printf("dropping cancellation %s from pool: %v",
				tx.Hash.GetHex(), err)
			transactionsPool.PoolsTx.RemoveTransactionByHash(tx.Hash.GetBytes())
			continue
		}
		// Possibly transient (e.g. the target's block has not been processed
		// here yet): hold it back from this block, but leave it pooled.
		logger.GetLogger().Printf("holding back cancellation %s: %v",
			tx.Hash.GetHex(), err)
	}
	return kept
}

func CheckStakingTransaction(tx transactionsDefinition.Transaction, sumAmount int64, sumFee int64, block Block) bool {
	fee, err := tx.CalcFee()
	if err != nil {
		logger.GetLogger().Println("invalid fee: CheckStakingTransaction:", err)
		return false
	}
	amount := tx.TxData.Amount
	address := tx.GetSenderAddress()
	operational := len(tx.TxData.OptData) > 0
	// An operator including its own operational staking transaction is safe:
	// account.Stake sets OperationalAccount only when it is currently false, so a
	// redundant "operational" flag is a no-op. Rejecting it outright (as before)
	// blocked a validator from adding stake in its own block and prevented a new
	// operator from bootstrapping into operational status.
	acc, exist := account.GetAccountByAddressBytes(address.GetBytes())
	if !exist || !bytes.Equal(acc.Address[:], address.GetBytes()) {
		logger.GetLogger().Println("no account found in check staking transaction: CheckStakingTransaction")
		return false
	}
	if acc.Balance < fee {
		logger.GetLogger().Println("not enough funds on account to cover fee: CheckStakingTransaction")
		return false
	}
	if acc.Balance < sumFee {
		logger.GetLogger().Println("not enough funds on account to cover sumFee: CheckStakingTransaction")
		return false
	}
	addressRecipient := tx.TxData.Recipient
	var n int
	if tx.GetLockedAmount() > 0 {
		n, err = account.IntDelegatedAccountFromAddress(tx.TxData.DelegatedAccountForLocking)
		if n <= 0 || n >= 256 || err != nil {
			fmt.Println("DelegatedAccountForLocking must be a delegated account less than 256: CheckStakingTransaction")
			return false
		}
	} else {
		n, err = account.IntDelegatedAccountFromAddress(addressRecipient)
	}
	if n > 0 && n < 256 {
		// If the sender intends to be an operator, verify both pubkeys are registered

		if operational && amount > 0 && !common.IsSyncing.Load() {
			senderAddr := tx.GetSenderAddress()
			addresses, err := pubkeys.LoadAddresses(senderAddr)
			if err != nil {
				logger.GetLogger().Println("operator must have registered pubkeys: CheckStakingTransaction")
				return false
			}
			hasPrimary := false
			hasSecondary := false
			for _, addr := range addresses {
				if addr.Primary {
					hasPrimary = true
				} else {
					hasSecondary = true
				}
			}
			if !hasPrimary || !hasSecondary {
				logger.GetLogger().Println("operator must have both primary and secondary pubkeys registered: CheckStakingTransaction")
				return false
			}
		}
		if tx.GetLockedAmount() > 0 {

			if amount <= 0 {
				logger.GetLogger().Println("when locking no withdrawals allows: CheckStakingTransaction")
				return false
			}

			if amount < common.MinStakingUser && amount > 0 {
				logger.GetLogger().Println("staking amount has to be larger than ", common.MinStakingUser, ": CheckStakingTransaction")
				return false
			}
			if tx.GetLockedAmount() < 0 {
				logger.GetLogger().Println("locked amount has to be larger or equal than ", 0, ": CheckStakingTransaction")
				return false
			}
			if tx.GetLockedAmount() > amount {
				logger.GetLogger().Println("locked amount has to be less or equal than ", amount, ": CheckStakingTransaction")
				return false
			}
			if tx.GetReleasePerBlock() < 0 {
				logger.GetLogger().Println("release per block has to be larger or equal than ", 0, ": CheckStakingTransaction")
				return false
			}
			if tx.GetReleasePerBlock() > tx.GetLockedAmount() {
				logger.GetLogger().Println("release per block has to be less or equal than ", tx.GetLockedAmount(), ": CheckStakingTransaction")
				return false
			}

		} else {
			accStaking := account.GetStakingAccountByAddressBytes(address.GetBytes(), n)
			if !bytes.Equal(accStaking.DelegatedAccount[:], addressRecipient.GetBytes()) {
				if amount <= 0 {
					logger.GetLogger().Println(n, address.GetHex(), common.Bytes2Hex(accStaking.DelegatedAccount[:]), " != ", common.Bytes2Hex(addressRecipient.GetBytes()))
					logger.GetLogger().Println("no staking account found in check staking transaction", ": CheckStakingTransaction")
					return false
				}

			}
			if amount < common.MinStakingUser && amount > 0 {
				logger.GetLogger().Println("staking amount has to be larger than ", common.MinStakingUser, ": CheckStakingTransaction")
				return false
			}
			if accStaking.StakedBalance+amount < common.MinStakingUser && accStaking.StakedBalance+amount != 0 {
				logger.GetLogger().Println("not enough staked balance. Staking has to be larger than ", common.MinStakingUser, ": CheckStakingTransaction")
				return false
			}
			// check for all transactions together

			if sumAmount < common.MinStakingUser && sumAmount > 0 {
				logger.GetLogger().Println("staking amount has to be larger than ", common.MinStakingUser, ": CheckStakingTransaction")
				return false
			}
			if accStaking.StakedBalance+sumAmount < common.MinStakingUser && accStaking.StakedBalance+sumAmount != 0 {
				logger.GetLogger().Println("not enough staked balance. Staking has to be larger than ", common.MinStakingUser, ": CheckStakingTransaction")
				return false
			}
		}
	}
	if n >= 256 && n < 512 {

		accStaking := account.GetStakingAccountByAddressBytes(address.GetBytes(), n%256)
		if !bytes.Equal(accStaking.Address[:], address.GetBytes()) {
			logger.GetLogger().Println("no staking account found in check staking transaction (rewards)", ": CheckStakingTransaction")
			return false
		}
		if accStaking.StakingRewards+amount < 0 {
			logger.GetLogger().Println("not enough rewards balance. Rewards has to be larger than ", 0, ": CheckStakingTransaction")
			return false
		}
	}
	return true
}

func ProcessMultiSignAndEscrow(tx transactionsDefinition.Transaction) error {

	if tx.TxData.EscrowTransactionsDelay > 0 && tx.TxData.MultiSignNumber > 0 {
		return fmt.Errorf("account cannot be both escrow and multisign")
	}

	acc := account.SetAccountByAddressBytes(tx.TxData.Recipient.ByteValue[:])

	// modify escrow parameters
	if tx.TxData.EscrowTransactionsDelay > 0 {
		err := acc.ModifyAccountToEscrow(tx.TxData.EscrowTransactionsDelay)
		if err != nil {
			return err
		}
	}

	// modify multi sign account
	if tx.TxData.MultiSignNumber > 0 {
		accAddreses := make([]common.Address, len(tx.TxData.MultiSignAddresses))
		for i, addr := range tx.TxData.MultiSignAddresses {
			a := &common.Address{}
			err := a.Init(addr[:])
			if err != nil {
				return err
			}
			accAddreses[i] = *a
		}
		err := acc.ModifyAccountToMultiSign(tx.TxData.MultiSignNumber, accAddreses)
		if err != nil {
			return err
		}
	}
	return nil
}

func ProcessTransaction(tx transactionsDefinition.Transaction, height int64, blockTime int64) error {
	fee, err := tx.CalcFee()
	if err != nil {
		return err
	}
	amount := tx.TxData.Amount
	operational := len(tx.TxData.OptData) > 0
	address := tx.GetSenderAddress()
	account.AddTransactionsSender(address.ByteValue, tx.GetHash())
	addressRecipient := tx.TxData.Recipient
	account.AddTransactionsRecipient(addressRecipient.ByteValue, tx.GetHash())
	if targetHash, isCancellation := tx.CancellationTarget(); isCancellation {
		if _, err := validateEscrowCancellation(tx, height); err != nil {
			return err
		}
		if err := AddBalance(address.ByteValue, -fee); err != nil {
			return err
		}
		transactionsPool.RemoveEscrowTransaction(targetHash.GetBytes())
		transactionsPool.PoolTxEscrow.BanTransactionByHash(targetHash.GetBytes())
		return nil
	}
	var n int
	if tx.GetLockedAmount() > 0 {
		n, err = account.IntDelegatedAccountFromAddress(tx.TxData.DelegatedAccountForLocking)
		if n <= 0 || n >= 256 || err != nil {
			return fmt.Errorf("DelegatedAccountForLocking must be a delegated account less than 256: ProcessTransaction")
		}
	} else {
		n, err = account.IntDelegatedAccountFromAddress(addressRecipient)
	}
	if err == nil { // this is delegated account
		if n > 0 && n < 256 { // this is staking transaction

			if tx.GetLockedAmount() > 0 {
				if amount >= common.MinStakingUser {
					err := account.Stake(addressRecipient.GetBytes(), amount, height, blockTime, n, operational, tx.GetLockedAmount(), tx.GetReleasePerBlock())
					if err != nil {
						return err
					}
				} else {
					return fmt.Errorf("wrong amount in locking: ProcessTransaction")
				}
				err = AddBalance(address.ByteValue, -fee-amount)
				if err != nil {
					return err
				}
			} else {
				if amount >= common.MinStakingUser {
					err := account.Stake(address.GetBytes(), amount, height, blockTime, n, operational, 0, 0)
					if err != nil {
						return err
					}
				} else if amount < 0 {
					err := account.Unstake(address.GetBytes(), amount, height, blockTime, n)
					if err != nil {
						return err
					}

				} else {
					return fmt.Errorf("wrong amount in staking/unstaking: ProcessTransaction")
				}
				err = AddBalance(address.ByteValue, -fee-amount)
				if err != nil {
					return err
				}
			}
			err := ProcessMultiSignAndEscrow(tx)
			if err != nil {
				return err
			}
		}
		if n >= 256 && n < 512 { // this is reward withdrawal transaction

			accStaking := account.GetStakingAccountByAddressBytes(address.GetBytes(), n%256)
			if !bytes.Equal(accStaking.Address[:], address.GetBytes()) {
				return fmt.Errorf("no staking account found in check staking transaction (rewards): ProcessTransaction")
			}
			if amount > 0 {
				logger.GetLogger().Println("not implemented: ProcessTransaction")
				//err := account.Reward(accStaking.Address[:], amount, height, n%256)
				//if err != nil {
				//	return err
				//}
			} else if amount < 0 {
				err := account.WithdrawReward(accStaking.Address[:], amount, height, n%256)
				if err != nil {
					return err
				}
				err = AddBalance(address.ByteValue, -fee-amount)
				if err != nil {
					return err
				}
			} else {
				return fmt.Errorf("wrong amount in rewarding: ProcessTransaction")
			}
		}
		if n >= 512 { // DEX operation - deduct gas fee from sender
			err = AddBalance(address.ByteValue, -fee)
			if err != nil {
				return err
			}
		}
	} else { // this is not delegated account so standard transaction

		senderAcc, exist := account.GetAccountByAddressBytes(address.GetBytes())
		if !exist {
			return fmt.Errorf("no account found")
		}
		if senderAcc.TransactionDelay > 0 && tx.GetHeight()+senderAcc.TransactionDelay > height && bytes.Equal(tx.TxParam.MultiSignTx.GetBytes(), ZerosHash) {
			tx.Height = height
			transactionsPool.AddEscrowTransaction(tx)

		} else if senderAcc.MultiSignNumber > 0 && bytes.Equal(tx.TxParam.MultiSignTx.GetBytes(), ZerosHash) {
			//TODO MultiSignNumber
			tx.Height = height
			transactionsPool.AddMultiSignTransaction(tx)
		} else {
			if bytes.Equal(tx.TxParam.MultiSignTx.GetBytes(), ZerosHash) == false {
				transactionsPool.AddMultiSignTransaction(tx)
			}
			// DB-C2: for contract-call txs the EVM already moved Amount as
			// msg.value; the native path must not move it again. Non-contract
			// (plain) transfers move natively as before.
			if !isContractCallTx(tx, senderAcc, height) {
				err = AddBalance(address.ByteValue, -amount)
				if err != nil {
					return err
				}
				err = AddBalance(addressRecipient.ByteValue, amount)
				if err != nil {
					return err
				}
			}
		}
		// escrow tx and multisigned should be paid fee upfront
		err = AddBalance(address.ByteValue, -fee)
		if err != nil {
			return err
		}

		err := ProcessMultiSignAndEscrow(tx)
		if err != nil {
			return err
		}
	}
	return nil
}

// loadMultiSignMainTx recovers a multisig main transaction from the durable
// transaction databases. Every applied block stores its transactions in the
// confirmed DB, so a node that applied the main tx's block - however long ago -
// can always rebuild the pool entry from there; the pool DB covers a main tx
// that is still pending on this node.
func loadMultiSignMainTx(hash common.Hash) (transactionsDefinition.Transaction, error) {
	t, err := transactionsDefinition.LoadFromDBPoolTx(common.TransactionDBPrefix[:], hash.GetBytes())
	if err == nil {
		return t, nil
	}
	return transactionsDefinition.LoadFromDBPoolTx(common.TransactionPoolHashesDBPrefix[:], hash.GetBytes())
}

func ProcessTransactionsMultiSign(tx transactionsDefinition.Transaction, height int64, tree *transactionsPool.MerkleTree) error {
	// INVARIANT (EVM Phase 3a / DB-C2): matured txs settled here move value
	// natively and UNCONDITIONALLY. This is correct only because these pooled
	// txs are never re-added to a block's TransactionsHashes and therefore never
	// re-dispatched through EvaluateSCForBlock — so the EVM never moves their
	// value. If block assembly ever re-includes a pooled tx hash, this native
	// settlement plus the EVM entry-value move (blocks/evaluate.go) would
	// DOUBLE-MOVE the amount. Do not break that invariant.

	if bytes.Equal(tx.TxParam.MultiSignTx.GetBytes(), ZerosHash) {
		return nil
	}

	txs := transactionsPool.PoolTxMultiSign.PeekTransactions(common.MaxTransactionInPool, common.GetInt64FromByte(tx.TxParam.MultiSignTx.GetBytes()))

	// NOTE: found must be an explicit flag. The previous detection - checking
	// len(mainTx.GetBytes()) == 0 - was dead code: a zero-value Transaction
	// serializes to ~290 bytes, so a missing main tx slipped through with
	// Height 0 and hit the expiry branch below, which reported the same
	// message and permanently rejected the block.
	mainTx := transactionsDefinition.Transaction{}
	mainFound := false
	for _, t := range txs {
		if bytes.Equal(t.Hash.GetBytes(), tx.TxParam.MultiSignTx.GetBytes()) {
			mainTx = t
			mainFound = true
			break
		}
	}

	if !mainFound {
		// The pool is rebuilt from applied blocks, and the main tx travelled in
		// one - so if it is not in the pool (restart wiped the pre-persistence
		// pool, or the pool entry was evicted), recover it from the transaction
		// databases instead of rejecting the block. Rejecting here bricked the
		// chain: the block can never apply without the main tx, and the main tx
		// never arrives again on its own.
		if recovered, err := loadMultiSignMainTx(tx.TxParam.MultiSignTx); err == nil {
			logger.GetLogger().Printf("multisig main tx %x recovered from the transaction DB into the pool",
				tx.TxParam.MultiSignTx.GetBytes()[:8])
			mainTx = recovered
			mainFound = true
			transactionsPool.AddMultiSignTransaction(mainTx)
		}
	}

	if !mainFound {
		for _, t := range txs {
			transactionsPool.RemoveMultiSignTransaction(t.Hash.GetBytes())
		}
		return fmt.Errorf("no main transaction %x in multi signature pool or transaction DBs",
			tx.TxParam.MultiSignTx.GetBytes()[:8])
	}

	// remove transactions related to main if more than a week in pool
	if height-mainTx.GetHeight() > common.MaxTransactionInMultiSigPool {
		for _, t := range txs {
			transactionsPool.RemoveMultiSignTransaction(t.Hash.GetBytes())
		}
		return fmt.Errorf("main transaction %x expired in multi signature pool", mainTx.Hash.GetBytes()[:8])
	}

	acc, exist := account.GetAccountByAddressBytes(mainTx.TxParam.Sender.GetBytes())
	if !exist {
		return fmt.Errorf("no account found: MultiSign")
	}
	if len(txs) < int(acc.MultiSignNumber) {
		logger.GetLogger().Println("not enough signatures for transactions to process ", tx.TxParam.MultiSignTx.GetHex())
		return nil
	}
	// Counting lives in CountMultiSignApprovals so the rule exists once. The
	// loop that used to be inlined here tracked outstanding signers with
	// acc.MultiSignAddresses[:], which shares its backing array with the
	// account in the global map; removing a matched signer shifted elements
	// inside that array and rewrote the account's authorised-signer list.
	// [A B C] became [A C C] — B could no longer approve anything and C
	// occupied two slots, so one address could satisfy two approvals.
	numApprovals, _ := CountMultiSignApprovals(mainTx, txs)
	if numApprovals < int(acc.MultiSignNumber) {
		logger.GetLogger().Println("not enough signatures for transactions to process ", tx.TxParam.MultiSignTx.GetHex())
		return nil
	}

	// transaction should be executed

	amount := mainTx.TxData.Amount
	address := mainTx.GetSenderAddress()
	addressRecipient := mainTx.TxData.Recipient
	var err error
	var n int
	if mainTx.GetLockedAmount() > 0 {
		n, err = account.IntDelegatedAccountFromAddress(mainTx.TxData.DelegatedAccountForLocking)
		if n <= 0 || n >= 256 || err != nil {
			return fmt.Errorf("DelegatedAccountForLocking must be a delegated account less than 256: ProcessTransaction")
		}
	} else {
		n, err = account.IntDelegatedAccountFromAddress(addressRecipient)
	}
	if err == nil { // delegated account any transfer should be processed for staking unstaking and reward withdrawal
		return nil
	} else { // this is not delegated account so standard transaction

		if acc.TransactionDelay > 0 && mainTx.GetHeight()+acc.TransactionDelay > height {
			return fmt.Errorf("transaction should not be executed, should be delayed %v", mainTx.Hash.GetHex())
		} else {
			transactionsPool.RemoveMultiSignTransaction(mainTx.Hash.GetBytes())
			err = AddBalance(address.ByteValue, -amount)
			if err != nil {
				// this can happen very rare. Only when escrow is multisign account
				transactionsPool.RemoveBadTransactionByHash(mainTx.Hash.GetBytes(), height, tree)
				return err
			}

			// amount is always >= 0, so no error here will be
			err = AddBalance(addressRecipient.ByteValue, amount)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func ProcessTransactionsEscrow(height int64, tree *transactionsPool.MerkleTree) error {
	// INVARIANT (EVM Phase 3a / DB-C2): matured txs settled here move value
	// natively and UNCONDITIONALLY. This is correct only because these pooled
	// txs are never re-added to a block's TransactionsHashes and therefore never
	// re-dispatched through EvaluateSCForBlock — so the EVM never moves their
	// value. If block assembly ever re-includes a pooled tx hash, this native
	// settlement plus the EVM entry-value move (blocks/evaluate.go) would
	// DOUBLE-MOVE the amount. Do not break that invariant.

	txs := transactionsPool.PoolTxEscrow.PeekTransactions(common.MaxTransactionInPool, height)
	logger.GetLogger().Printf("ProcessTransactionsEscrow: height=%d, escrow pool returned %d transactions", height, len(txs))

	for i, tx := range txs {

		amount := tx.TxData.Amount
		address := tx.GetSenderAddress()
		addressRecipient := tx.TxData.Recipient
		logger.GetLogger().Printf("  escrow tx[%d]: hash=%s, sender=%s, recipient=%s, amount=%d, txHeight=%d, escrowDelay=%d",
			i, tx.Hash.GetHex()[:16], address.GetHex()[:16], addressRecipient.GetHex()[:16], amount, tx.GetHeight(), tx.TxData.EscrowTransactionsDelay)
		var err error
		var n int
		if tx.GetLockedAmount() > 0 {
			n, err = account.IntDelegatedAccountFromAddress(tx.TxData.DelegatedAccountForLocking)
			if n <= 0 || n >= 256 || err != nil {
				return fmt.Errorf("DelegatedAccountForLocking must be a delegated account less than 256: ProcessTransaction")
			}
		} else {
			n, err = account.IntDelegatedAccountFromAddress(addressRecipient)
		}
		if err == nil { // delegated account any transfer should be processed for staking unstaking and reward withdrawal
			// AC-M7: skip this escrow tx but keep processing the rest of the
			// batch. The previous `return nil` abandoned all remaining escrow
			// transactions on the first delegated-account match.
			logger.GetLogger().Printf("  escrow tx[%d]: delegated account (n=%d), skipping", i, n)
			continue
		} else { // this is not delegated account so standard transaction
			senderAcc, exist := account.GetAccountByAddressBytes(address.GetBytes())
			if !exist {
				return fmt.Errorf("no account found: Escrow")
			}
			logger.GetLogger().Printf("  escrow tx[%d]: senderAcc.TransactionDelay=%d, txHeight+delay=%d, currentHeight=%d",
				i, senderAcc.TransactionDelay, tx.GetHeight()+senderAcc.TransactionDelay, height)
			if senderAcc.TransactionDelay > 0 && tx.GetHeight()+senderAcc.TransactionDelay > height && bytes.Equal(tx.TxParam.MultiSignTx.GetBytes(), ZerosHash) {
				// Skip this one and keep going, as the delegated-account branch
				// above already does (AC-M7). Returning here abandoned every
				// remaining entry in the batch, and the pool is a max-heap keyed
				// on the height an entry was pooled at, so the newest — and
				// therefore least mature — transaction is served first. One
				// fresh escrow transfer was enough to hold every older, already
				// due transfer past its promised delay.
				logger.GetLogger().Printf("  escrow tx[%d]: NOT READY, need to wait %d more blocks", i, tx.GetHeight()+senderAcc.TransactionDelay-height)
				continue
			} else if senderAcc.MultiSignNumber > 0 && bytes.Equal(tx.TxParam.MultiSignTx.GetBytes(), ZerosHash) {
				logger.GetLogger().Printf("  escrow tx[%d]: moving to multisign pool", i)
				if transactionsPool.AddMultiSignTransaction(tx) {
					transactionsPool.RemoveEscrowTransaction(tx.Hash.GetBytes())
				}
			} else {
				logger.GetLogger().Printf("  escrow tx[%d]: EXECUTING (delay passed or no delay)", i)
				if bytes.Equal(tx.TxParam.MultiSignTx.GetBytes(), ZerosHash) == false {
					transactionsPool.AddMultiSignTransaction(tx)
				}
				err = AddBalance(address.ByteValue, -amount)
				if err != nil {
					// this can happen very rare. Only when escrow is multisign account
					transactionsPool.RemoveBadTransactionByHash(tx.Hash.GetBytes(), height, tree)
					return err
				}

				// amount is always >= 0, so no error here will be
				err = AddBalance(addressRecipient.ByteValue, amount)
				if err != nil {
					return err
				}
				transactionsPool.RemoveEscrowTransaction(tx.Hash.GetBytes())
				logger.GetLogger().Printf("  escrow tx[%d]: balance transferred %d from %s to %s", i, amount, address.GetHex()[:16], addressRecipient.GetHex()[:16])
			}
		}
	}
	return nil
}
