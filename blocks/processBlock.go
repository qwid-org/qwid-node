package blocks

import (
	"bytes"
	"fmt"
	"math/big"
	"time"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/oracles"
	"github.com/qwid-org/qwid-node/pubkeys"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
	"github.com/qwid-org/qwid-node/voting"
)

func validateBlockTimestamp(newBlock Block, lastBlock Block, shouldCheck bool) error {

	if newBlock.GetHeader().Height < 2 {
		return nil
	}
	blockTime := newBlock.GetBlockTimeStamp()
	lastTime := lastBlock.GetBlockTimeStamp()
	currTime := common.GetCurrentTimeStampInSecond()

	// 1. Must increase
	if blockTime <= lastTime {
		return fmt.Errorf("timestamp must increase")
	}

	// 2. Not too far in future (allow 30s clock skew)
	if shouldCheck && (blockTime > currTime+common.MaxBlockForwardInTime) {
		return fmt.Errorf("timestamp too far in future")
	}

	// 3. Reasonable progression. A large gap to the parent is only suspicious when
	// the block also claims a time the wall clock has not reached yet. After a chain
	// halt (node restart, network outage) longer than MaxBlockTimeInterval every
	// honest candidate is necessarily stamped more than that far after its parent —
	// producers stamp the current time — so bounding the gap on its own bricks the
	// chain permanently: no successor block could ever be valid again. Comparing
	// against currTime here also gives the sync path a future-timestamp bound, which
	// rule 2 skips. No block already in the chain can trip this, since they all
	// passed the old gap-only rule.
	maxTime := lastTime + common.MaxBlockTimeInterval
	if blockTime > maxTime && blockTime > currTime+common.MaxBlockForwardInTime {
		return fmt.Errorf("timestamp progression too large")
	}

	return nil
}

// VerifyStakeDependent runs the block checks that depend on the staking snapshot
// — the top-128 producer eligibility and the oracle 2/3-stake thresholds. It must
// be called at block-application time, when the in-memory staking state reflects
// height-1 (the block's parent). Running these inside CheckBaseBlock was wrong for
// batched sync, where every batched block was verified against the same start-of-
// batch snapshot instead of its own parent's.
func VerifyStakeDependent(newBlock Block) error {
	blockHeight := newBlock.GetHeader().Height
	if blockHeight > 0 && !account.IsTop128StakingNode(
		mustDelegatedAccountID(newBlock.GetHeader().DelegatedAccount),
		newBlock.GetHeader().OperatorAccount,
	) {
		return fmt.Errorf("block producer is not an eligible top-128 staking node")
	}
	if blockHeight >= OracleProofsActivationHeight {
		if err := AuthorizeOracleProofSigners(newBlock.BaseBlock.OracleProofs); err != nil {
			return fmt.Errorf("oracle proof authorization fails: %w", err)
		}
	}
	totalStaked := account.GetStakedInAllDelegatedAccounts()
	if !oracles.VerifyPriceOracle(blockHeight, totalStaked, newBlock.BaseBlock.PriceOracle, newBlock.BaseBlock.PriceOracleData) {
		return fmt.Errorf("price oracle check fails")
	}
	if !oracles.VerifyRandOracle(blockHeight, totalStaked, newBlock.BaseBlock.RandOracle, newBlock.BaseBlock.RandOracleData) {
		return fmt.Errorf("rand oracle check fails")
	}
	return nil
}

// validateBlockTxHashes rejects a transaction-hash list that repeats a hash or
// exceeds the per-block maximum.
//
// Honest producers cannot emit either (the pool is hash-keyed and capped), but
// nothing on the validator side used to reject a received block that repeated a
// hash: the merkle root recomputed over the duplicated list matched the
// attacker's own header root, and each occurrence loaded from the pool DB and
// applied again, so a producer could include any victim's transfer N times and
// every validator executed it N times (QWID-2026-35). The count cap likewise
// bound only the producer's own selection, never a received block.
func validateBlockTxHashes(txs []common.Hash) error {
	if len(txs) > int(common.MaxTransactionsPerBlock) {
		return fmt.Errorf("block has %d transactions, above the maximum %d", len(txs), common.MaxTransactionsPerBlock)
	}
	seen := make(map[[common.HashLength]byte]struct{}, len(txs))
	for _, h := range txs {
		var k [common.HashLength]byte
		copy(k[:], h.GetBytes())
		if _, dup := seen[k]; dup {
			return fmt.Errorf("block includes transaction %x more than once", h.GetBytes()[:8])
		}
		seen[k] = struct{}{}
	}
	return nil
}

func CheckBaseBlock(newBlock Block, lastBlock Block, forceShouldCheck bool) (*transactionsPool.MerkleTree, error) {
	blockHeight := newBlock.GetHeader().Height
	if newBlock.GetBlockSupply() > common.MaxTotalSupply {
		return nil, fmt.Errorf("supply is too high")
	}
	// Reject repeated or over-count transaction hashes before any per-tx work
	// (QWID-2026-35); this runs on the sync path too since CheckBaseBlock does.
	if err := validateBlockTxHashes(newBlock.TransactionsHashes); err != nil {
		return nil, err
	}

	if newBlock.GetHeader().Height > 0 && !bytes.Equal(lastBlock.BlockHash.GetBytes(), newBlock.GetHeader().PreviousHash.GetBytes()) {
		logger.GetLogger().Println("lastBlock.BlockHash", lastBlock.BlockHash.GetHex(), newBlock.GetHeader().PreviousHash.GetHex())
		return nil, fmt.Errorf("last block hash not match to one stored in new block")
	}
	// needs to check block and process
	if newBlock.CheckProofOfSynergy() == false {
		return nil, fmt.Errorf("proof of synergy fails of block")
	}
	hash, err := newBlock.CalcBlockHash()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(hash.GetBytes(), newBlock.BlockHash.GetBytes()) {
		return nil, fmt.Errorf("wrong hash of block")
	}
	rootMerkleTrie := newBlock.GetHeader().RootMerkleTree
	txs := newBlock.TransactionsHashes
	// Clean capacity, not length: make([][]byte, len(txs)) prepended len(txs)
	// nil leaves before the real hashes, so every tree committed to n nils + n
	// hashes. Producer and validator shared the bug so roots agreed, but any
	// correct future caller would diverge — a consensus trap (QWID-2026-23).
	// Genesis already builds cleanly; this brings block validation in line.
	txsBytes := make([][]byte, 0, len(txs))
	for _, tx := range txs {
		hash := tx.GetBytes()
		txsBytes = append(txsBytes, hash)
	}
	merkleTrie, err := transactionsPool.BuildMerkleTree(blockHeight, txsBytes, transactionsPool.GlobalMerkleTree.DB)
	if err != nil {
		return nil, err
	}
	if newBlock.GetHeader().Height > 0 && !bytes.Equal(merkleTrie.GetRootHash(), rootMerkleTrie.GetBytes()) {
		return nil, fmt.Errorf("root merkleTrie hash check fails")
	}
	// NOTE: the oracle 2/3-stake thresholds and the top-128 producer check depend
	// on the staking snapshot and are enforced in VerifyStakeDependent at block-
	// application time (see its doc comment). Only the stake-independent proof
	// authentication below stays here, so it still runs during batched sync.
	// Bind the embedded oracle values to signed nonce transactions: every price
	// and rand entry must be backed by a signature-verified, fresh proof so a
	// producer cannot fabricate values attributed to other validators.
	if blockHeight >= OracleProofsActivationHeight {
		if err := AuthenticateOracleProofs(newBlock, lastBlock); err != nil {
			return nil, fmt.Errorf("oracle proof authentication fails: %w", err)
		}
	}
	if len(newBlock.BaseBlock.BaseHeader.Encryption1[:]) == 0 || len(newBlock.BaseBlock.BaseHeader.Encryption2[:]) == 0 {
		return nil, fmt.Errorf("encryption opt data should be always present in block")
	}
	blockTime := newBlock.GetBlockTimeStamp()
	currTime := common.GetCurrentTimeStampInSecond()
	shouldCheck := !((currTime - blockTime) > int64(common.BlockTimeInterval)*common.VotingHeightDistance)
	if forceShouldCheck == false {
		shouldCheck = false
	}
	// totalStaked is used by the encryption pause/replace voting checks below,
	// which only run when shouldCheck is true (the live path, correct snapshot).
	totalStaked := account.GetStakedInAllDelegatedAccounts()
	err = validateBlockTimestamp(newBlock, lastBlock, forceShouldCheck)
	if err != nil {
		return nil, err
	}
	// Recompute the expected difficulty from the parent block and the committed
	// timestamps and reject any block that declares a different value. Without
	// this a producer could declare an arbitrarily low difficulty (consensus).
	if blockHeight >= TimestampDifficultyActivationHeight && !ValidDifficulty(
		newBlock.GetHeader().Difficulty,
		lastBlock.GetHeader().Difficulty,
		lastBlock.GetBlockTimeStamp(),
		newBlock.GetBlockTimeStamp(),
	) {
		return nil, fmt.Errorf("declared difficulty does not match expected difficulty derived from parent block")
	}
	if !common.IsSyncing.Load() && !bytes.Equal(newBlock.BaseBlock.BaseHeader.Encryption1[:], lastBlock.BaseBlock.BaseHeader.Encryption1[:]) {
		enc1, err := FromBytesToEncryptionConfig(newBlock.BaseBlock.BaseHeader.Encryption1[:], true)
		if err != nil {
			return nil, err
		}
		// Reported alongside the node's own view: when the two disagree, the
		// node's global config has drifted from the chain and that, not the
		// block, is the thing to investigate.
		lastBlockEnc1Paused := false
		if pe, perr := FromBytesToEncryptionConfig(lastBlock.BaseBlock.BaseHeader.Encryption1[:], true); perr == nil {
			lastBlockEnc1Paused = pe.IsPaused
		}
		_ = lastBlockEnc1Paused

		if enc1.SigName == common.SigName() && enc1.IsPaused == common.IsPaused() {
			//newBlock.BaseBlock.BaseHeader.Encryption1 = []byte{}
			logger.GetLogger().Println("no need to change encryption, so leave encryption 1 empty")
		} else {
			if !oqs.VerifyEncConfig(enc1) {
				return nil, fmt.Errorf("encryption 1 verification fails")
			}
			if shouldCheck && common.IsPaused() == false && common.SigName() != enc1.SigName {
				return nil, fmt.Errorf("you need to pause first to replace encryption, 1: block proposes %q while the node holds %q and reports the primary as live (paused=%v); the parent block records paused=%v",
					enc1.SigName, common.SigName(), common.IsPaused(), lastBlockEnc1Paused)
			}
			if enc1.IsPaused == true && common.IsPaused() == true && enc1.SigName == common.SigName() {
				return nil, fmt.Errorf("pausing fails, encryption is just paused, 1: block proposes pausing %q which the node already holds paused", enc1.SigName)
			}
			if shouldCheck && (enc1.SigName != common.SigName()) && (enc1.IsPaused == false) {
				return nil, fmt.Errorf("new encryption has to be paused, 1: block proposes %q with paused=false while replacing %q", enc1.SigName, common.SigName())
			}

			if shouldCheck && (enc1.SigName != common.SigName()) && !voting.VerifyEncryptionForReplacing(blockHeight, totalStaked, true, newBlock.BaseBlock.BaseHeader.Encryption1[:]) {
				return nil, fmt.Errorf("voting replacement encryption check fails, 1: not enough staked votes back replacing %q with %q at height %d", common.SigName(), enc1.SigName, blockHeight)
			}
			if shouldCheck && enc1.IsPaused == true && enc1.SigName == common.SigName() && !voting.VerifyEncryptionForPausing(blockHeight, totalStaked, true, newBlock.BaseBlock.BaseHeader.Encryption1[:]) {
				return nil, fmt.Errorf("voting pausing check fails, 1: not enough staked votes back pausing %q at height %d", enc1.SigName, blockHeight)
			}
			// Pausing the live primary makes the CURRENT SECONDARY the active
			// scheme. Refuse it unless a key for that secondary is already
			// registered for this block's operator. Otherwise the node would owe
			// every following block a signature under a scheme whose key no node
			// can verify, while the paused primary's signatures are rejected too
			// (wallet.Verify accepts only the non-paused slot) — a permanent
			// deadlock in which the new key can never even be registered
			// (incident 2026-09-08). Register the spare while the primary is live,
			// then pause. Skipped during sync (shouldCheck false).
			if shouldCheck && enc1.IsPaused && !common.IsPaused() && enc1.SigName == common.SigName() {
				op := newBlock.GetHeader().OperatorAccount
				if _, kerr := pubkeys.LoadPubKeyWithPrimaryOfLength(op, false, common.PubKeyLength2(false)); kerr != nil {
					return nil, fmt.Errorf("refusing to pause primary %q: the secondary scheme %q that becomes active has no registered key for operator %s — register it first (while the primary is live), then pause, to avoid the unregistered-active-scheme deadlock",
						common.SigName(), common.SigName2(), op.GetHex())
				}
			}
			if enc1.SigName == common.SigName2() {
				return nil, fmt.Errorf("cannot exist 2 the same ecnryptions schemes, 1")
			}
		}
	}

	if !common.IsSyncing.Load() && !bytes.Equal(newBlock.BaseBlock.BaseHeader.Encryption2[:], lastBlock.BaseBlock.BaseHeader.Encryption2[:]) {
		enc2, err := FromBytesToEncryptionConfig(newBlock.BaseBlock.BaseHeader.Encryption2[:], false)
		if err != nil {
			return nil, err
		}
		if enc2.SigName == common.SigName2() && enc2.IsPaused == common.IsPaused2() {
			//newBlock.BaseBlock.BaseHeader.Encryption2 = []byte{}
			logger.GetLogger().Println("no need to change encryption, so leave encryption 2 empty")
		} else {
			if !oqs.VerifyEncConfig(enc2) {
				return nil, fmt.Errorf("encryption 2 verification fails")
			}
			if shouldCheck && common.IsPaused2() == false && common.SigName2() != enc2.SigName {
				return nil, fmt.Errorf("you need to pause first to replace encryption, 2")
			}
			if enc2.IsPaused == true && common.IsPaused2() == true && enc2.SigName == common.SigName2() {
				return nil, fmt.Errorf("pausing fails, encryption is just puased, 2")
			}
			if shouldCheck && (enc2.SigName != common.SigName2()) && (enc2.IsPaused == false) {
				return nil, fmt.Errorf("new encryption has to be paused, 2")
			}
			if shouldCheck && (enc2.SigName != common.SigName2()) && !voting.VerifyEncryptionForReplacing(blockHeight, totalStaked, false, newBlock.BaseBlock.BaseHeader.Encryption2[:]) {
				return nil, fmt.Errorf("voting replacement encryption check fails, 2")
			}
			if shouldCheck && enc2.IsPaused == true && enc2.SigName == common.SigName2() && !voting.VerifyEncryptionForPausing(blockHeight, totalStaked, false, newBlock.BaseBlock.BaseHeader.Encryption2[:]) {
				return nil, fmt.Errorf("voting pausing check fails, 2")
			}
			// Symmetric to the primary case: pausing the live secondary makes the
			// PRIMARY the active scheme, so refuse it unless the operator has a
			// registered primary key (avoids the unregistered-active-scheme
			// deadlock; incident 2026-09-08).
			if shouldCheck && enc2.IsPaused && !common.IsPaused2() && enc2.SigName == common.SigName2() {
				op := newBlock.GetHeader().OperatorAccount
				if _, kerr := pubkeys.LoadPubKeyWithPrimaryOfLength(op, true, common.PubKeyLength(false)); kerr != nil {
					return nil, fmt.Errorf("refusing to pause secondary %q: the primary scheme %q that becomes active has no registered key for operator %s — register it first, then pause",
						common.SigName2(), common.SigName(), op.GetHex())
				}
			}
			if enc2.SigName == common.SigName() {
				return nil, fmt.Errorf("cannot exist 2 the same ecnryptions schemes, 2")
			}
		}
	}
	return merkleTrie, nil
}

func mustDelegatedAccountID(address common.Address) int {
	id, err := account.IntDelegatedAccountFromAddress(address)
	if err != nil {
		return -1
	}
	return id
}

func IsAllTransactions(block Block) [][]byte {
	txs := block.TransactionsHashes
	hashes := [][]byte{}
	for _, tx := range txs {
		hash := tx.GetBytes()
		// Check both pool DB and confirmed DB
		isInPoolMain := transactionsPool.PoolsTx.HasTransaction(hash)
		isInPoolEscrow := transactionsPool.PoolTxEscrow.HasTransaction(hash)
		isInPoolMultisign := transactionsPool.PoolTxMultiSign.HasTransaction(hash)
		isInPool := transactionsDefinition.CheckFromDBPoolTx(common.TransactionPoolHashesDBPrefix[:], hash)
		isInConfirmed := transactionsDefinition.CheckFromDBPoolTx(common.TransactionDBPrefix[:], hash) //
		if !isInPoolEscrow && !isInPoolMultisign && !isInPoolMain && !isInPool && !isInConfirmed {
			hashes = append(hashes, hash)
		}
	}
	return hashes
}

func CheckBlockTransfers(block Block, lastBlock Block, tree *transactionsPool.MerkleTree, onlyCheck bool) (int64, int64, error) {
	txs := block.TransactionsHashes
	lastSupply := lastBlock.GetBlockSupply()
	accounts := map[[common.AddressLength]byte]account.Account{}
	stakingAccounts := map[[common.AddressLength]byte]account.StakingAccount{}
	totalFee := int64(0)
	// Cumulative EVM gas across the block. MaxGasUsage was documented as the
	// block limit but never summed anywhere, so a block full of maximal
	// transactions carried an unbounded aggregate compute budget
	// (QWID-2026-11). Checked during BOTH passes — verification rejects the
	// block before any state is touched.
	totalGas := int64(0)
	// badTxErr records the first "bad transaction" (unpayable / no-account /
	// malformed-multisig) found in the block. Such transactions are dropped and
	// BANNED from the pool as they are found, but scanning CONTINUES so the whole
	// pool is purged of them in ONE pass — otherwise a transactional DDoS (a
	// flood of insufficient-funds txs) drains one-per-block and stalls production
	// for hours (incident 2026-09-08). The block that contained them is still
	// rejected (badTxErr returned after the loop): the validity verdict is
	// unchanged, only pool hygiene improves, so the next production attempt builds
	// a clean block from the surviving good transactions.
	var badTxErr error
	// Name the pass. This function runs twice for every block — once to verify
	// it and once to apply it — and the two lines were identical, so a healthy
	// block looked like it was being processed twice.
	pass := "applying"
	if onlyCheck {
		pass = "verifying"
	}
	logger.GetLogger().Printf("CheckBlockTransfers[%s]: block %d has %d transactions, lastSupply=%d",
		pass, block.GetHeader().Height, len(txs), lastSupply)
	for i, tx := range txs {
		hash := tx.GetBytes()
		poolTx, err := transactionsDefinition.LoadFromDBPoolTx(common.TransactionPoolHashesDBPrefix[:], hash)
		if err != nil {
			transactionsDefinition.RemoveTransactionFromDBbyHash(common.TransactionPoolHashesDBPrefix[:], hash)
			poolTx, err = transactionsDefinition.LoadFromDBPoolTx(common.TransactionDBPrefix[:], hash)
			if err != nil {
				// Try to recover from bad transaction DB during sync
				poolTx, err = transactionsDefinition.LoadFromDBPoolTx(common.BadTransactionDBPrefix[:], hash)
				if err != nil {
					logger.GetLogger().Printf("  tx[%d] %x NOT FOUND in any DB", i, hash[:8])
					return 0, 0, err
				}
				// Validate recovered bad transaction
				if !poolTx.Verify(common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2()) {
					logger.GetLogger().Printf("  tx[%d] %x from badTx FAILED validation", i, hash[:8])
					return 0, 0, fmt.Errorf("bad transaction failed validation: %x", hash[:8])
				}
				// Store to confirmed DB so re-adding to pool DB below succeeds
				err = poolTx.StoreToDBPoolTx(common.TransactionDBPrefix[:])
				if err != nil {
					return 0, 0, err
				}
			} else {
				// TX was found in confirmed DB — check if it is already in a Merkle tree.
				// If so, return the error immediately WITHOUT re-adding to pool DB.
				// Re-adding first (old behaviour) left a stale pool DB entry that caused
				// every subsequent block containing the same tx to also fail.
				if checkErr := transactionsPool.CheckTransactionInDBAndInMarkleTrie(hash, tree); checkErr != nil {
					return 0, 0, checkErr
				}
			}
			err = poolTx.StoreToDBPoolTx(common.TransactionPoolHashesDBPrefix[:])
			if err != nil {
				return 0, 0, err
			}
		}
		err = transactionsPool.CheckTransactionInDBAndInMarkleTrie(hash, tree)
		if err != nil {
			return 0, 0, err
		}

		fee, feeErr := poolTx.CalcFee()
		if feeErr != nil {
			return 0, 0, feeErr
		}
		totalFee += fee
		if poolTx.GasUsage > 0 {
			// Bound the single addend BEFORE summing, regardless of any Verify
			// exemption. Nonce- and genesis-shaped transactions skip the
			// upper-gas check in Verify, so one could declare GasUsage=MaxInt64
			// and overflow totalGas to a negative value, silently disabling the
			// cap for the rest of the block (QWID-2026-38(b)). With every addend
			// <= MaxGasUsage and the running sum rejected once it passes
			// MaxGasUsage, totalGas can never exceed ~2*MaxGasUsage — no wrap.
			if poolTx.GasUsage > common.MaxGasUsage {
				return 0, 0, fmt.Errorf("block %d: transaction %x declares gas %d above the block maximum %d",
					block.GetHeader().Height, hash[:8], poolTx.GasUsage, common.MaxGasUsage)
			}
			totalGas += poolTx.GasUsage
			if totalGas > common.MaxGasUsagePerBlock {
				return 0, 0, fmt.Errorf("block %d exceeds the block gas limit: %d > %d",
					block.GetHeader().Height, totalGas, common.MaxGasUsagePerBlock)
			}
		}
		amount := poolTx.TxData.Amount
		total_amount := fee + amount
		address := poolTx.GetSenderAddress()
		recipientAddress := poolTx.TxData.Recipient
		if _, isCancellation := poolTx.CancellationTarget(); isCancellation {
			if _, err := validateEscrowCancellation(poolTx, block.GetHeader().Height); err != nil {
				return 0, 0, fmt.Errorf("invalid escrow cancellation: %w", err)
			}
		}
		// EvaluateSCForBlock cannot execute a deployment from an escrow or
		// multisig account, so accepting one would charge the fee for a
		// transaction that provably does nothing.
		if err := ValidateContractDeployment(poolTx); err != nil {
			return 0, 0, err
		}
		var n int
		if poolTx.GetLockedAmount() > 0 {
			n, err = account.IntDelegatedAccountFromAddress(poolTx.TxData.DelegatedAccountForLocking)
			if n <= 0 || n >= 256 || err != nil {
				return 0, 0, fmt.Errorf("DelegatedAccountForLocking must be a delegated account less than 256: CheckBlockTransfers")
			}
		} else {
			n, err = account.IntDelegatedAccountFromAddress(recipientAddress)
		}
		if err == nil && n < 512 { // delegated account
			stakingAcc := account.GetStakingAccountByAddressBytes(address.GetBytes(), n%256)
			if !bytes.Equal(stakingAcc.Address[:], address.GetBytes()) {

				logger.GetLogger().Println("no account found in check block transfer: CheckBlockTransfers")
				copy(stakingAcc.Address[:], address.GetBytes())
				copy(stakingAcc.DelegatedAccount[:], recipientAddress.GetBytes())

			}
			if _, ok := stakingAccounts[stakingAcc.Address]; ok {
				stakingAcc = stakingAccounts[stakingAcc.Address]
			}
			stakingAcc.StakedBalance += amount
			stakingAcc.StakingRewards += fee // just using for fee in the local copy
			stakingAccounts[stakingAcc.Address] = stakingAcc
			ret := CheckStakingTransaction(poolTx, stakingAccounts[stakingAcc.Address].StakedBalance, stakingAccounts[stakingAcc.Address].StakingRewards, block)
			if ret == false {
				// remove bad transaction from pool
				transactionsPool.RemoveBadTransactionByHash(poolTx.Hash.GetBytes(), block.GetHeader().Height, tree)
				return 0, 0, fmt.Errorf("staking transactions checking fails: CheckBlockTransfers")
			}
		}
		acc, exist := account.GetAccountByAddressBytes(address.GetBytes())
		if !exist || !bytes.Equal(acc.Address[:], address.GetBytes()) {
			// Sender account does not exist: drop+ban and keep scanning so the
			// whole flood is purged in one pass (see badTxErr).
			transactionsPool.RemoveBadTransactionByHash(poolTx.Hash.GetBytes(), block.GetHeader().Height, tree)
			if badTxErr == nil {
				badTxErr = fmt.Errorf("no account found in check block transafer: CheckBlockTransfers")
			}
			continue
		}
		if bytes.Equal(poolTx.TxParam.MultiSignTx.GetBytes(), ZerosHash) == false && (poolTx.TxData.Amount > 0 || len(poolTx.TxData.OptData) > 0 || poolTx.TxData.LockedAmount > 0 || poolTx.TxData.MultiSignNumber > 0) {
			transactionsPool.RemoveBadTransactionByHash(poolTx.Hash.GetBytes(), block.GetHeader().Height, tree)
			if badTxErr == nil {
				badTxErr = fmt.Errorf("transaction which confirms in multi signature account should have amount == 0, OptData = nil, LockedAmount = 0, MultiSignNumber = 0")
			}
			continue
		}

		// Running in-block balance for this sender.
		cur := acc
		if a, ok := accounts[acc.Address]; ok {
			cur = a
		}
		if cur.Balance-total_amount < 0 {
			// Unpayable — a transactional-DDoS transaction whose sender lacks the
			// funds. Drop+ban it and SKIP WITHOUT debiting, so other transactions
			// from the same sender are still judged against the true balance.
			// Keep scanning to purge every unpayable tx this pass (see badTxErr).
			transactionsPool.RemoveBadTransactionByHash(poolTx.Hash.GetBytes(), block.GetHeader().Height, tree)
			if badTxErr == nil {
				badTxErr = fmt.Errorf("not enough funds on account: CheckBlockTransfers")
			}
			continue
		}
		cur.Balance -= total_amount
		accounts[acc.Address] = cur

	}
	// Any bad transaction found above makes THIS block invalid (unchanged
	// verdict), but the pool has now been purged+banned of ALL of them in this
	// single pass, so the next production attempt builds a clean block instead of
	// re-selecting the same flood (stall incident 2026-09-08).
	if badTxErr != nil {
		return 0, 0, badTxErr
	}
	reward := account.GetReward(lastSupply)

	if lastSupply+reward != block.GetBlockSupply() {
		logger.GetLogger().Println("lastSupply:", lastSupply, "block.GetBlockSupply()", block.GetBlockSupply())
		return 0, 0, fmt.Errorf("block supply checking fails: CheckBlockTransfers")
	}

	return reward, totalFee, nil
}

func ProcessBlockTransfers(block Block, reward int64, tree *transactionsPool.MerkleTree) error {
	// Escrow settlement runs at the END of this function, not the start
	// (QWID-2026-37). It moves balances and then removes the escrow entry from
	// the pool and its DB mirror; running it first meant that when a LATER
	// per-transaction step failed and the whole block was rolled back via the
	// state snapshot, the escrow entry was already gone and never came back —
	// so re-application (or the canonical block at that height) settled nothing,
	// while nodes that did not process the failing candidate settled normally,
	// a silent permanent balance divergence. Deferring it past every failable
	// step means a settlement only happens when the block genuinely commits.

	txs := block.TransactionsHashes
	for _, tx := range txs {
		hash := tx.GetBytes()
		err := transactionsPool.CheckTransactionInDBAndInMarkleTrie(hash, tree)
		if err != nil {
			return err
		}
		poolTx, err := transactionsDefinition.LoadFromDBPoolTx(common.TransactionPoolHashesDBPrefix[:], hash)
		if err != nil {
			return err
		}

		// if poolTx.Height > block.GetHeader().Height {
		// 	transactionsPool.RemoveBadTransactionByHash(poolTx.Hash.GetBytes(), block.GetHeader().Height, tree)
		// 	return fmt.Errorf("transaction height is wrong: ProcessBlockTransfers")
		// }

		err = ProcessTransaction(poolTx, block.GetHeader().Height, block.GetBlockTimeStamp())
		if err != nil {
			// remove bad transaction from pool
			transactionsPool.RemoveBadTransactionByHash(poolTx.Hash.GetBytes(), block.GetHeader().Height, tree)
			return err
		}
		err = ProcessTransactionsMultiSign(poolTx, block.GetHeader().Height, tree)
		if err != nil {
			// remove bad transaction from pool
			transactionsPool.RemoveBadTransactionByHash(poolTx.Hash.GetBytes(), block.GetHeader().Height, tree)
			return err
		}
	}
	addr := block.BaseBlock.BaseHeader.OperatorAccount.ByteValue
	n, err := account.IntDelegatedAccountFromAddress(block.BaseBlock.BaseHeader.DelegatedAccount)
	if err != nil || n < 1 || n > 255 {
		return fmt.Errorf("wrong delegated account in block: ProcessBlockTransfers")
	}
	staked, sum, _ := account.GetStakedInDelegatedAccount(n)
	if sum <= 0 {
		return fmt.Errorf("no staked amount in delegated account which was rewarded: ProcessBlockTransfers")
	}

	rewardPerc := block.GetRewardPercentage()
	if rewardPerc > 500 {
		return fmt.Errorf("reward has to be smaller than 50")
	}
	// AC-H5/AC-M9: distribute rewards with exact integer arithmetic. Floating
	// point lost precision above 2^53 and was non-deterministic risk; big.Int
	// also prevents reward*balance from overflowing int64 before the divide.
	rewardOper := reward * int64(rewardPerc) / 1000

	err = account.Reward(addr[:], rewardOper, block.GetHeader().Height, n)
	if err != nil {
		return err
	}

	reward -= rewardOper
	rest := reward
	bigReward := big.NewInt(reward)
	bigSum := big.NewInt(sum)
	for _, acc := range staked {
		if acc.Balance > 0 {
			// userReward = reward * acc.Balance / sum, computed without overflow.
			userReward := new(big.Int).Div(
				new(big.Int).Mul(bigReward, big.NewInt(acc.Balance)),
				bigSum,
			).Int64()
			rest -= userReward // in the case when rounding lose some fraction of coins
			err := account.Reward(acc.Address[:], userReward, block.GetHeader().Height, n)
			if err != nil {
				return err
			}
		}
	}
	if rest > 0 {
		err := account.Reward(addr[:], rest, block.GetHeader().Height, n)
		if err != nil {
			return err
		}
	} else if rest < 0 {
		return fmt.Errorf("this shouldn't happen anytime: ProcessBlockTransfers")
	}

	// Last, after every failable step above: settle matured escrows. If this is
	// reached the block commits, so a settlement can no longer be stranded by a
	// later rollback (QWID-2026-37).
	if err := ProcessTransactionsEscrow(block.GetHeader().Height, tree); err != nil {
		logger.GetLogger().Println("ProcessTransactionsEscrow: ", err)
	}

	return nil
}

func RemoveAllTransactionsRelatedToBlock(newBlock Block) {
	txs := newBlock.TransactionsHashes
	for _, tx := range txs {
		hash := tx.GetBytes()
		transactionsPool.PoolsTx.RemoveTransactionByHash(hash)
		transactionsDefinition.RemoveTransactionFromDBbyHash(common.TransactionPoolHashesDBPrefix[:], hash)
	}
}

func EvaluateSmartContracts(bl *Block) bool {
	height := (*bl).GetHeader().Height
	if ok, logs, addresses, codes, _ := EvaluateSCForBlock(*bl); ok {
		StateMutex.Lock()
		State.SetSnapShotNum(height, State.Snapshot())
		for _, a := range addresses {
			State.RecordContractCreation(height, a.ByteValue)
		}
		StateMutex.Unlock()
		for th, a := range addresses {

			prefix := common.OutputLogsHashesDBPrefix[:]
			err := database.MainDB.Put(append(prefix, th[:]...), []byte(logs[th]))
			if err != nil {
				logger.GetLogger().Println("Cannot store output logs")
				return false
			}

			aa := [common.AddressLength]byte{}
			copy(aa[:], a.GetBytes())
			prefix = common.OutputAddressesHashesDBPrefix[:]
			err = database.MainDB.Put(append(prefix, th[:]...), codes[aa])
			if err != nil {
				logger.GetLogger().Println("Cannot store address codes")
				return false
			}
		}

	} else {
		logger.GetLogger().Println("Evaluating Smart Contract fails")
		return false
	}
	return true
}

// verifyBlockHeaderSignature authenticates the block producer's header
// signature against the encryption configuration in force BEFORE this block —
// the parent's, not the one this block declares.
//
// A block that changes the configuration is signed under the OLD rules, because
// that is all its producer had when it signed. Judging it by the rules it
// introduces makes it invalidate its own signature: a block announcing "the
// primary scheme is paused" is signed with the primary scheme, so verifying it
// under its own config rejects it, and the pause can never be recorded. The
// same holds for a scheme replacement. This was masked while two schemes were
// live at once and surfaced once exactly one scheme could be active.
//
// It is called FIRST in both apply paths (QWID-2026-07): the operator key is
// resolved from the registry (state before this block), so authentication needs
// nothing this block computes, and running it before transaction lookup, EVM
// execution, pool mutation, or the persistent public-key writes in
// ProcessBlockPubKey means a forged candidate cannot drive any expensive or
// persistent work — least of all a key registration that a later failed
// authentication would not roll back.
func verifyBlockHeaderSignature(newBlock *Block, lastBlock Block) error {
	head := newBlock.GetHeader()
	sigName, sigName2, isPaused, isPaused2, err := lastBlock.GetSigNames()
	if err != nil {
		return fmt.Errorf("%v: verifyBlockHeaderSignature", err)
	}
	if head.Verify(sigName, sigName2, isPaused, isPaused2) == false {
		return fmt.Errorf("header fails to verify")
	}
	return nil
}

func CheckBlockAndTransactions(newBlock *Block, lastBlock Block, merkleTrie *transactionsPool.MerkleTree, checkFinal bool) error {
	// Authenticate the producer BEFORE any expensive or persistent work
	// (QWID-2026-07). Unconditional, matching the original end-of-function
	// check this replaces; the operator key is already in the registry before
	// the block, so nothing this block computes is needed.
	if err := verifyBlockHeaderSignature(newBlock, lastBlock); err != nil {
		return fmt.Errorf("%v: CheckBlockAndTransactions", err)
	}

	// NOTE: deliberately NO deferred RemoveAllTransactionsRelatedToBlock here.
	// That defer ran on FAILURE too, so a block that could not apply because
	// SOME of its transactions were still in flight had ALL its already-fetched
	// transactions deleted from the pool DB - the next attempt then reported
	// the full set missing again and re-downloaded everything, forever (the
	// "downloads them and they go missing again" loop). A failed apply must
	// leave fetched transactions in place; the success path moves them to the
	// confirmed DB and cleans the pool itself (the txStore loop below), and
	// genuinely invalid transactions are removed point-wise by
	// RemoveBadTransactionByHash where they are detected.
	// Stake-snapshot-dependent checks, run against the parent (height-1) state
	// that is in memory before this block's transactions are applied.
	if err := VerifyStakeDependent(*newBlock); err != nil {
		return err
	}
	n, err := account.IntDelegatedAccountFromAddress(newBlock.GetHeader().DelegatedAccount)
	if err != nil || n < 1 || n > 255 {
		return fmt.Errorf("wrong delegated account: CheckBlockAndTransactions")
	}
	opAccBlockAddr := newBlock.GetHeader().OperatorAccount
	if _, sumStaked, opAcc := account.GetStakedInDelegatedAccount(n); int64(sumStaked) < common.MinStakingForNode || !bytes.Equal(opAcc.Address[:], opAccBlockAddr.GetBytes()) {
		return fmt.Errorf("not enough staked coins to be a node or not valid operetional account: CheckBlockAndTransactions")
	}

	reward, totalFee, err := CheckBlockTransfers(*newBlock, lastBlock, merkleTrie, true)
	if err != nil {
		return err
	}
	newBlock.BlockFee = totalFee + lastBlock.BlockFee

	if EvaluateSmartContracts(newBlock) == false {
		return fmt.Errorf("evaluation of smart contracts in block fails: CheckBlockAndTransactions")
	}

	staked, rewarded := GetSupplyInStakedAccounts()
	//coinsInDex := account.GetCoinLiquidityInDex()
	// AC-H7 invariant (check-only path): this function does NOT call
	// ProcessBlockTransfers, so it runs against state in which this block's
	// reward is already reflected in account/staking balances. The reward term
	// is therefore intentionally omitted here. Do NOT add `reward` to match
	// CheckBlockAndTransferFunds below — that path checks the invariant BEFORE
	// distributing the reward, which is why it includes it.
	if checkFinal && GetSupplyInAccounts()+staked+rewarded+lastBlock.BlockFee != newBlock.GetBlockSupply() {
		logger.GetLogger().Println("GetSupplyInAccounts()", GetSupplyInAccounts())
		logger.GetLogger().Println("staked:", staked)
		logger.GetLogger().Println("rewarded", rewarded)
		logger.GetLogger().Println("lastBlock.BlockFee", lastBlock.BlockFee)
		logger.GetLogger().Println("GetSupplyInAccounts()+staked+rewarded+reward+lastBlock.BlockFee:", GetSupplyInAccounts()+staked+rewarded+reward+lastBlock.BlockFee, "newBlock.GetBlockSupply():", newBlock.GetBlockSupply())
		return fmt.Errorf("block supply checking fails vs account balances: CheckBlockAndTransactions")
	}

	// Header signature already authenticated at the top of this function
	// (QWID-2026-07).
	return nil
}

// slowApplyThreshold is the per-block apply wall time above which the sub-phase
// breakdown below is logged. The sync batch summary only splits verify/funds;
// this names WHERE inside the funds phase a slow block spends its time.
const slowApplyThreshold = 300 * time.Millisecond

func CheckBlockAndTransferFunds(newBlock *Block, lastBlock Block, merkleTrie *transactionsPool.MerkleTree, checkWhenNotSync bool) error {

	applyStart := time.Now()
	var tStakeDep, tTransfers, tSC, tSupply, tPubKeys, tHeader, tProcess, tTxStore time.Duration
	defer func() {
		if total := time.Since(applyStart); total > slowApplyThreshold {
			logger.GetLogger().Printf("slow block apply %d (%d txs): total=%v stakeDep=%v transfers=%v evalSC=%v supply=%v pubkeys=%v headerVerify=%v processTransfers=%v txStore=%v",
				newBlock.GetHeader().Height, len(newBlock.TransactionsHashes),
				total.Truncate(time.Millisecond), tStakeDep.Truncate(time.Millisecond), tTransfers.Truncate(time.Millisecond),
				tSC.Truncate(time.Millisecond), tSupply.Truncate(time.Millisecond), tPubKeys.Truncate(time.Millisecond),
				tHeader.Truncate(time.Millisecond), tProcess.Truncate(time.Millisecond), tTxStore.Truncate(time.Millisecond))
		}
	}()

	// NOTE: deliberately NO deferred RemoveAllTransactionsRelatedToBlock here.
	// That defer ran on FAILURE too, so a block that could not apply because
	// SOME of its transactions were still in flight had ALL its already-fetched
	// transactions deleted from the pool DB - the next attempt then reported
	// the full set missing again and re-downloaded everything, forever (the
	// "downloads them and they go missing again" loop). A failed apply must
	// leave fetched transactions in place; the success path moves them to the
	// confirmed DB and cleans the pool itself (the txStore loop below), and
	// genuinely invalid transactions are removed point-wise by
	// RemoveBadTransactionByHash where they are detected.
	// Authenticate the producer BEFORE any expensive or persistent work
	// (QWID-2026-07): a forged candidate must not reach transaction lookup, EVM
	// execution, pool mutation, or the persistent public-key writes below. The
	// operator key is resolved from the registry (pre-block state).
	phase := time.Now()
	if err := verifyBlockHeaderSignature(newBlock, lastBlock); err != nil {
		return fmt.Errorf("%v: CheckBlockAndTransferFunds", err)
	}
	tHeader = time.Since(phase)

	// Stake-snapshot-dependent checks, run against the parent (height-1) state
	// that is in memory before this block's transactions are applied.
	phase = time.Now()
	if err := VerifyStakeDependent(*newBlock); err != nil {
		return err
	}
	tStakeDep = time.Since(phase)
	n, err := account.IntDelegatedAccountFromAddress(newBlock.GetHeader().DelegatedAccount)
	if err != nil || n < 1 || n > 255 {
		return fmt.Errorf("wrong delegated account: CheckBlockAndTransferFunds")
	}
	opAccBlockAddr := newBlock.GetHeader().OperatorAccount
	if _, sumStaked, opAcc := account.GetStakedInDelegatedAccount(n); int64(sumStaked) < common.MinStakingForNode || !bytes.Equal(opAcc.Address[:], opAccBlockAddr.GetBytes()) {
		return fmt.Errorf("not enough staked coins to be a node or not valid operetional account: CheckBlockAndTransferFunds %v %v %v %v", int64(sumStaked), common.MinStakingForNode, opAcc.Address[:5], opAccBlockAddr.GetBytes()[:5])
	}

	phase = time.Now()
	reward, totalFee, err := CheckBlockTransfers(*newBlock, lastBlock, merkleTrie, false)
	if err != nil {
		return err
	}
	tTransfers = time.Since(phase)
	newBlock.BlockFee = totalFee + lastBlock.BlockFee

	phase = time.Now()
	if EvaluateSmartContracts(newBlock) == false {
		return fmt.Errorf("evaluation of smart contracts in block fails: CheckBlockAndTransferFunds")
	}
	tSC = time.Since(phase)

	phase = time.Now()
	staked, rewarded := GetSupplyInStakedAccounts()
	//coinsInDex := account.GetCoinLiquidityInDex()
	supplyInAccounts := GetSupplyInAccounts()
	// AC-H7 invariant (pre-distribution path): ProcessBlockTransfers is called
	// later in this function, so the block reward has NOT yet been added to any
	// balance. It is added here explicitly. This is why the formula differs from
	// CheckBlockAndTransactions, which checks post-distribution state.
	calculatedSupply := supplyInAccounts + staked + rewarded + reward + lastBlock.BlockFee
	expectedSupply := newBlock.GetBlockSupply()
	if calculatedSupply != expectedSupply {
		logger.GetLogger().Println("=== SUPPLY MISMATCH DEBUG ===")
		logger.GetLogger().Println("GetSupplyInAccounts():", supplyInAccounts)
		logger.GetLogger().Println("staked:", staked)
		logger.GetLogger().Println("rewarded:", rewarded)
		logger.GetLogger().Println("reward:", reward)
		logger.GetLogger().Println("lastBlock.BlockFee:", lastBlock.BlockFee)
		logger.GetLogger().Println("totalFee:", totalFee)
		logger.GetLogger().Println("Calculated:", calculatedSupply)
		logger.GetLogger().Println("Expected (block):", expectedSupply)
		logger.GetLogger().Println("Difference:", calculatedSupply-expectedSupply)
		logger.GetLogger().Println("lastBlock.Height:", lastBlock.GetHeader().Height)
		logger.GetLogger().Println("lastBlock.Supply:", lastBlock.GetBlockSupply())
		logger.GetLogger().Println("=== END SUPPLY MISMATCH DEBUG ===")
		return fmt.Errorf("block supply checking fails vs account balances: CheckBlockAndTransferFunds")
	}
	tSupply = time.Since(phase)
	hashes := newBlock.GetBlockTransactionsHashes()
	logger.GetLogger().Println("Number of transactions in block: ", len(hashes))
	phase = time.Now()
	err = ProcessBlockPubKey(*newBlock)
	if err != nil {
		return err
	}
	tPubKeys = time.Since(phase)
	// Header signature already authenticated at the top of this function
	// (QWID-2026-07).
	phase = time.Now()
	err = merkleTrie.StoreTree(newBlock.GetHeader().Height)
	if err != nil {
		return err
	}
	err = ProcessBlockTransfers(*newBlock, reward, merkleTrie)
	if err != nil {
		return err
	}
	tProcess = time.Since(phase)
	phase = time.Now()
	// Batch every transaction's three DB writes — confirmed-store, included-mark
	// (QWID-2026-19) and pool-hash delete — into a SINGLE RocksDB write per block
	// instead of ~3 individually-locked ops per transaction. For a full 5000-tx
	// block that collapses ~15k locked cgo writes into one, which is what a weak
	// node needs to keep up during sync (sync-perf). It is also more atomic: the
	// whole block's tx-store either lands or does not.
	heightBytes := common.GetByteInt64(newBlock.GetHeader().Height)
	batch := database.NewBatch()
	for _, h := range hashes {
		hb := h.GetBytes()
		poolKey := append(append([]byte{}, common.TransactionPoolHashesDBPrefix[:]...), hb...)
		// Move the RAW stored bytes pool->confirmed. The transaction was already
		// decoded and verified earlier in this apply (CheckBlockTransfers), and
		// the stored form is exactly what a re-encode would produce, so decoding
		// it again here (the old LoadFromDBPoolTx + GetBytes) is pure wasted CPU
		// per transaction — costly on a weak node during sync (sync-perf).
		txBytes, err := database.MainDB.Get(poolKey)
		if err != nil || len(txBytes) == 0 {
			logger.GetLogger().Printf("commit: transaction %x missing from pool DB: %v", hb, err)
			continue
		}
		// Reproduce StoreToDBPoolTx(TransactionDBPrefix), MarkTxIncluded and
		// RemoveFromDBPoolTx(TransactionPoolHashesDBPrefix) as batch operations.
		// Fresh key slices (append onto []byte{}) so the 2-byte global prefixes
		// are never mutated.
		batch.Put(append(append([]byte{}, common.TransactionDBPrefix[:]...), hb...), txBytes)
		batch.Put(append(append([]byte{}, common.IncludedTxDBPrefix[:]...), hb...), heightBytes)
		batch.Delete(poolKey)
		transactionsPool.PoolsTx.RemoveTransactionByHash(hb)
	}
	if err := database.MainDB.CommitBatch(batch); err != nil {
		return err
	}
	tTxStore = time.Since(phase)
	// Success: sweep any in-memory pool remnants of this block (the loop above
	// already moved every transaction pool->confirmed; this is idempotent).
	RemoveAllTransactionsRelatedToBlock(*newBlock)
	err = ProcessBlockEncryption(*newBlock, lastBlock)
	if err != nil {
		// Deliberately logged and not returned: the block itself is valid and has
		// already been applied, so the node must keep following the chain. What
		// failed is this node's own adoption of the new signature scheme — most
		// often because the wallet has no recovery phrase to derive the new key
		// from (see AddNewEncryptionToActiveWallet). Consequence: the node stays
		// in sync but cannot sign under the new scheme until the operator
		// restores the wallet.
		logger.GetLogger().Println("WALLET DID NOT ADOPT THE CHAIN'S NEW ENCRYPTION SCHEME — node keeps syncing "+
			"but cannot produce blocks or sign transactions under it; operator action required:", err)
	}
	return nil
}
