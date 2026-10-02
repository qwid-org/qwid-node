package blocks

import (
	"bytes"
	"fmt"
	"math/big"
	"runtime"
	"sync"
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
// — the top-128 producer eligibility, the price oracle 2/3-stake threshold, the
// RANDAO reveal (S4-06) and the signature-scheme vote (S4-05). It must
// be called at block-application time, when the in-memory staking state reflects
// height-1 (the block's parent). Running these inside CheckBaseBlock was wrong for
// batched sync, where every batched block was verified against the same start-of-
// batch snapshot instead of its own parent's.
func VerifyStakeDependent(newBlock, lastBlock Block) error {
	blockHeight := newBlock.GetHeader().Height
	if blockHeight > 0 && !account.IsTop128StakingNode(
		mustDelegatedAccountID(newBlock.GetHeader().DelegatedAccount),
		newBlock.GetHeader().OperatorAccount,
	) {
		return fmt.Errorf("block producer is not an eligible top-128 staking node")
	}
	if err := AuthorizeOracleProofSigners(newBlock.BaseBlock.OracleProofs); err != nil {
		return fmt.Errorf("oracle proof authorization fails: %w", err)
	}
	if err := VerifyEncryptionVotes(newBlock, lastBlock); err != nil {
		return fmt.Errorf("scheme vote fails: %w", err)
	}
	totalStaked := account.GetStakedInAllDelegatedAccounts()
	// S4-06: a price that cannot be established carries the parent's forward,
	// so a producer embedding too few proofs can at most freeze it, never
	// publish 0.
	if !oracles.VerifyPriceOracle(blockHeight, totalStaked, newBlock.BaseBlock.PriceOracle, newBlock.BaseBlock.PriceOracleData, lastBlock.BaseBlock.PriceOracle) {
		return fmt.Errorf("price oracle check fails")
	}
	// RAND comes from RANDAO (S4-06): the reveal must open the operator's
	// commitment held in the parent state.
	if err := verifyRandaoReveal(newBlock); err != nil {
		return fmt.Errorf("rand oracle check fails: %w", err)
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
	// S3-07: reject an out-of-range reward percentage here, before any
	// transaction of the block is applied.
	if rp := newBlock.GetRewardPercentage(); rp < 0 || rp > 500 {
		return nil, fmt.Errorf("reward percentage %d outside 0..500", rp)
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
	// S3-03: proof-of-synergy above is judged on BlockHeaderHash, so it must be
	// the header's real hash - a free field let a producer win every lottery.
	header := newBlock.GetHeader()
	headerHash, err := header.CalcHash()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(headerHash.GetBytes(), newBlock.BaseBlock.BlockHeaderHash.GetBytes()) {
		return nil, fmt.Errorf("block header hash does not match the header")
	}
	// S3-04: the signed header commits to the body; an edited body is invalid.
	bodyHash, err := newBlock.BaseBlock.CalcBodyHash()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(bodyHash.GetBytes(), newBlock.GetHeader().BodyHash.GetBytes()) {
		return nil, fmt.Errorf("block body does not match the signed body hash")
	}
	// S4-06: RAND is the RANDAO mix of this block, built on the parent's.
	if err := verifyRandaoStateless(newBlock, lastBlock); err != nil {
		return nil, err
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
	if err := AuthenticateOracleProofs(newBlock, lastBlock); err != nil {
		return nil, fmt.Errorf("oracle proof authentication fails: %w", err)
	}
	if len(newBlock.BaseBlock.BaseHeader.Encryption1[:]) == 0 || len(newBlock.BaseBlock.BaseHeader.Encryption2[:]) == 0 {
		return nil, fmt.Errorf("encryption opt data should be always present in block")
	}
	err = validateBlockTimestamp(newBlock, lastBlock, forceShouldCheck)
	if err != nil {
		return nil, err
	}
	// Recompute the expected difficulty from the parent block and the committed
	// timestamps and reject any block that declares a different value. Without
	// this a producer could declare an arbitrarily low difficulty (consensus).
	// Genesis has no parent to derive a difficulty from (InitGenesis checks it
	// against itself); every later block must match its parent's.
	if blockHeight > 0 && !ValidDifficulty(
		newBlock.GetHeader().Difficulty,
		lastBlock.GetHeader().Difficulty,
		lastBlock.GetBlockTimeStamp(),
		newBlock.GetBlockTimeStamp(),
	) {
		return nil, fmt.Errorf("declared difficulty does not match expected difficulty derived from parent block")
	}
	// Signature-scheme changes are judged against the PARENT block's config,
	// on every path (S3-06): neither the node's own config nor IsSyncing - which
	// a peer can force - decides whether a block may change the scheme. The
	// stake vote is counted in VerifyStakeDependent (S4-05).
	for _, primary := range []bool{true, false} {
		slot := newBlock.BaseBlock.BaseHeader.Encryption1
		if !primary {
			slot = newBlock.BaseBlock.BaseHeader.Encryption2
		}
		changed, err := checkEncryptionChangeShape(slot, lastBlock, primary)
		if err != nil {
			return nil, fmt.Errorf("encryption %v: %w", map[bool]int{true: 1, false: 2}[primary], err)
		}
		if changed {
			if err := checkPauseLeavesRegisteredKey(newBlock, lastBlock, slot, primary); err != nil {
				return nil, err
			}
		}
	}
	return merkleTrie, nil
}

// checkPauseLeavesRegisteredKey: pausing one slot's scheme makes the other
// slot's scheme the active one. Refuse it unless this block's operator already
// has a registered key for that scheme - otherwise every following block owes
// a signature no node can verify while the paused scheme's signatures are
// rejected too, a permanent deadlock in which the new key can never even be
// registered (incident 2026-09-08). Register the spare while the current
// scheme is live, then pause.
func checkPauseLeavesRegisteredKey(newBlock, lastBlock Block, slot []byte, primary bool) error {
	next, err := oqs.FromBytesToEncryptionConfig(slot)
	if err != nil {
		return err
	}
	cur, err := parentSlotConfig(lastBlock, primary)
	if err != nil {
		return err
	}
	if !(next.IsPaused && !cur.IsPaused && next.SigName == cur.SigName) {
		return nil
	}
	becomesActive, err := parentSlotConfig(lastBlock, !primary)
	if err != nil {
		return err
	}
	op := newBlock.GetHeader().OperatorAccount
	if _, kerr := pubkeys.LoadPubKeyWithPrimaryOfLength(op, !primary, becomesActive.PubKeyLength); kerr != nil {
		return fmt.Errorf("refusing to pause %q: the scheme %q that becomes active has no registered key for operator %s - register it first, then pause",
			cur.SigName, becomesActive.SigName, op.GetHex())
	}
	return nil
}

// TransactionHeightInWindow reports whether a transaction stamped txHeight may
// be included in a block at blockHeight (S4-01): not above the block, and at
// most MaxTransactionAgeBlocks below it.
func TransactionHeightInWindow(txHeight, blockHeight int64) bool {
	return txHeight <= blockHeight && blockHeight-txHeight <= common.MaxTransactionAgeBlocks
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

// findTxInMemoryPools looks a transaction up in the three in-memory pools —
// the sources IsAllTransactions counts as "present" that the DB-only recovery
// in CheckBlockTransfers could not reach (sync stall, incident 2026-09-08).
func findTxInMemoryPools(hash []byte) (transactionsDefinition.Transaction, bool) {
	if tx, ok := transactionsPool.PoolsTx.GetTransactionByHash(hash); ok {
		return tx, true
	}
	if tx, ok := transactionsPool.PoolTxEscrow.GetTransactionByHash(hash); ok {
		return tx, true
	}
	if tx, ok := transactionsPool.PoolTxMultiSign.GetTransactionByHash(hash); ok {
		return tx, true
	}
	return transactionsDefinition.Transaction{}, false
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
	// Phase 1: load every transaction of the block.
	loaded := make([]transactionsDefinition.Transaction, 0, len(txs))
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
					// Last resort: the in-memory pools. A transaction can sit
					// there without a loadable pool-DB entry (e.g. escrow/
					// multisig pools persist under their own prefixes), and
					// IsAllTransactions counts those as PRESENT — so no
					// missing-tx request ever fired while this loop failed
					// forever with "NOT FOUND in any DB" (sync stall,
					// incident 2026-09-08).
					if memTx, ok := findTxInMemoryPools(hash); ok {
						poolTx = memTx
					} else {
						logger.GetLogger().Printf("  tx[%d] %x NOT FOUND in any DB", i, hash[:8])
						return 0, 0, err
					}
				}
				// Validate the recovered bad transaction against the scheme
				// config and key registry in force for THIS block - the
				// parent's (S3-06). This used to run under the node's current
				// config and registry, which differ from the block's while
				// syncing, so it was skipped then (incident 2026-09-08); since
				// IsSyncing can be forced by a peer (S2-03), that also let a
				// live node apply an unverified body.
				if !verifyAgainstParent(&poolTx, lastBlock) {
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
		loaded = append(loaded, poolTx)
	}

	// Phase 2: verify every signature as of the parent block. Pool bodies are
	// bound to their hashes (S3-01) but not authenticated: gossip verified
	// them under the node's state at arrival, and while syncing bx stores them
	// unverified because the keys of a historical transaction may not be
	// registered yet. Without this pass a syncing node - a mode a peer can
	// force (S2-03) - took the producer's word for every signature.
	// Done before the checks below, so a forged transaction never enters the
	// in-block balance accounting and gets a genuine one of the same sender
	// banned as unpayable.
	verified := verifyBlockTransactions(loaded, lastBlock)

	// Phase 3: per-transaction checks.
	for i := range loaded {
		poolTx := loaded[i]
		hash := poolTx.GetHash().GetBytes()
		var err error
		if !verified[i] {
			transactionsPool.RemoveBadTransactionByHash(hash, block.GetHeader().Height, tree)
			if badTxErr == nil {
				badTxErr = fmt.Errorf("transaction %x fails signature verification as of block %d", hash[:8], lastBlock.GetHeader().Height)
			}
			continue
		}
		if !TransactionHeightInWindow(poolTx.GetHeight(), block.GetHeader().Height) {
			transactionsPool.RemoveBadTransactionByHash(poolTx.Hash.GetBytes(), block.GetHeader().Height, tree)
			if badTxErr == nil {
				badTxErr = fmt.Errorf("transaction %x height %d outside the window for block %d", hash[:8], poolTx.GetHeight(), block.GetHeader().Height)
			}
			continue
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
				// Drop+ban and keep scanning, like the unpayable case below
				// (S4-04): returning here purged one invalid staking transaction
				// per production attempt, so a flood of them stalled production.
				// The block is still rejected through badTxErr.
				transactionsPool.RemoveBadTransactionByHash(poolTx.Hash.GetBytes(), block.GetHeader().Height, tree)
				if badTxErr == nil {
					badTxErr = fmt.Errorf("staking transactions checking fails: CheckBlockTransfers")
				}
				continue
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
	// The block's RANDAO commitment becomes its operator's live one (S4-06).
	if err := applyRandaoCommit(block); err != nil {
		return err
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
	// S3-05: the block must be built on the state we hold.
	if err := VerifyStateRoot(*newBlock); err != nil {
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
	if err := VerifyStakeDependent(*newBlock, lastBlock); err != nil {
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

// verifyAgainstParent verifies tx as of block lastBlock: under the signature
// schemes lastBlock leaves in force and against the keys registered by
// lastBlock or earlier (S3-06). Every input is chain state at a fixed height,
// so the verdict does not depend on the node's mode or its current tip.
func verifyAgainstParent(tx *transactionsDefinition.Transaction, lastBlock Block) bool {
	sigName, sigName2, isPaused, isPaused2, err := lastBlock.GetSigNames()
	if err != nil {
		return false
	}
	return tx.VerifyAsOf(sigName, sigName2, isPaused, isPaused2, lastBlock.GetHeader().Height)
}

// verifyBlockTransactions runs verifyAgainstParent for every transaction of a
// block, in parallel - signature checks dominate the cost, and a 5000-tx
// block verified serially would slow sync to a crawl. Each worker owns the
// slice elements it verifies (Verify recomputes the hash in place).
func verifyBlockTransactions(txs []transactionsDefinition.Transaction, lastBlock Block) []bool {
	ok := make([]bool, len(txs))
	sigName, sigName2, isPaused, isPaused2, err := lastBlock.GetSigNames()
	if err != nil {
		return ok
	}
	asOf := lastBlock.GetHeader().Height
	workers := min(runtime.NumCPU(), len(txs))
	next := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				ok[i] = txs[i].VerifyAsOf(sigName, sigName2, isPaused, isPaused2, asOf)
			}
		}()
	}
	for i := range txs {
		next <- i
	}
	close(next)
	wg.Wait()
	return ok
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
	// S3-05: the block must be built on the state we hold - checked before
	// anything is applied, so a divergence is caught here, one block after it
	// happened, instead of never.
	if err := VerifyStateRoot(*newBlock); err != nil {
		return fmt.Errorf("%v: CheckBlockAndTransferFunds", err)
	}
	tHeader = time.Since(phase)

	// Stake-snapshot-dependent checks, run against the parent (height-1) state
	// that is in memory before this block's transactions are applied.
	phase = time.Now()
	if err := VerifyStakeDependent(*newBlock, lastBlock); err != nil {
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
