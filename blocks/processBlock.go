package blocks

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/crypto/oqs"
	"github.com/wonabru/qwid-node/database"
	"github.com/wonabru/qwid-node/logger"
	"github.com/wonabru/qwid-node/oracles"
	"github.com/wonabru/qwid-node/transactionsDefinition"
	"github.com/wonabru/qwid-node/transactionsPool"
	"github.com/wonabru/qwid-node/voting"
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

	// 3. Reasonable progression
	maxTime := lastTime + common.MaxBlockTimeInterval
	if blockTime > maxTime {
		return fmt.Errorf("timestamp progression too large")
	}

	return nil
}

func CheckBaseBlock(newBlock Block, lastBlock Block, forceShouldCheck bool) (*transactionsPool.MerkleTree, error) {
	blockHeight := newBlock.GetHeader().Height
	if blockHeight > 0 && !account.IsTop128StakingNode(
		mustDelegatedAccountID(newBlock.GetHeader().DelegatedAccount),
		newBlock.GetHeader().OperatorAccount,
	) {
		return nil, fmt.Errorf("block producer is not an eligible top-128 staking node")
	}
	if newBlock.GetBlockSupply() > common.MaxTotalSupply {
		return nil, fmt.Errorf("supply is too high")
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
	txsBytes := make([][]byte, len(txs))
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
	totalStaked := account.GetStakedInAllDelegatedAccounts()
	// AC-C4 (CONSENSUS): verify oracles even while syncing. The checks are
	// deterministic in the block's own oracle data and the replay-reconstructed
	// staked total, so legitimately produced blocks still pass, while a malicious
	// sync peer can no longer inject blocks with fabricated oracle values.
	if !oracles.VerifyPriceOracle(blockHeight, totalStaked, newBlock.BaseBlock.PriceOracle, newBlock.BaseBlock.PriceOracleData) {
		return nil, fmt.Errorf("price oracle check fails")
	}
	if !oracles.VerifyRandOracle(blockHeight, totalStaked, newBlock.BaseBlock.RandOracle, newBlock.BaseBlock.RandOracleData) {
		return nil, fmt.Errorf("rand oracle check fails")
	}
	// Bind the embedded oracle values to signed nonce transactions: every price
	// and rand entry must be backed by a signature-verified, fresh proof so a
	// producer cannot fabricate values attributed to other validators.
	if blockHeight > 0 {
		if err := AuthenticateOracleProofs(blockHeight, newBlock.BaseBlock.OracleProofs, newBlock.BaseBlock.PriceOracleData, newBlock.BaseBlock.RandOracleData); err != nil {
			return nil, fmt.Errorf("oracle proof authentication fails: %w", err)
		}
	}
	if len(newBlock.BaseBlock.BaseHeader.Encryption1[:]) == 0 || len(newBlock.BaseBlock.BaseHeader.Encryption2[:]) == 0 {
		return nil, fmt.Errorf("encryption opt data should be always present in block")
	}
	blockTime := newBlock.GetBlockTimeStamp()
	currTime := common.GetCurrentTimeStampInSecond()
	shouldCheck := !((currTime - blockTime) > int64(common.BlockTimeInterval)*common.VotingHeightDistance)
	logger.GetLogger().Println("should check pausing:", shouldCheck)
	if forceShouldCheck == false {
		shouldCheck = false
	}
	err = validateBlockTimestamp(newBlock, lastBlock, forceShouldCheck)
	if err != nil {
		return nil, err
	}
	// Recompute the expected difficulty from the parent block and the committed
	// timestamps and reject any block that declares a different value. Without
	// this a producer could declare an arbitrarily low difficulty (consensus).
	if blockHeight > 0 && !ValidDifficulty(
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

		if enc1.SigName == common.SigName() && enc1.IsPaused == common.IsPaused() {
			//newBlock.BaseBlock.BaseHeader.Encryption1 = []byte{}
			logger.GetLogger().Println("no need to change encryption, so leave encryption 1 empty")
		} else {
			if !oqs.VerifyEncConfig(enc1) {
				return nil, fmt.Errorf("encryption 1 verification fails")
			}
			if shouldCheck && common.IsPaused() == false && common.SigName() != enc1.SigName {
				return nil, fmt.Errorf("you need to pause first to replace encryption, 1")
			}
			if enc1.IsPaused == true && common.IsPaused() == true && enc1.SigName == common.SigName() {
				return nil, fmt.Errorf("pausing fails, encryption is just puased, 1")
			}
			if shouldCheck && (enc1.SigName != common.SigName()) && (enc1.IsPaused == false) {
				return nil, fmt.Errorf("new encryption has to be paused, 1")
			}

			if shouldCheck && (enc1.SigName != common.SigName()) && !voting.VerifyEncryptionForReplacing(blockHeight, totalStaked, true) {
				return nil, fmt.Errorf("voting replacement encryption check fails, 1")
			}
			if shouldCheck && enc1.IsPaused == true && enc1.SigName == common.SigName() && !voting.VerifyEncryptionForPausing(blockHeight, totalStaked, true) {
				return nil, fmt.Errorf("voting pausing check fails, 1")
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
			if shouldCheck && (enc2.SigName != common.SigName2()) && !voting.VerifyEncryptionForReplacing(blockHeight, totalStaked, false) {
				return nil, fmt.Errorf("voting replacement encryption check fails, 2")
			}
			if shouldCheck && enc2.IsPaused == true && enc2.SigName == common.SigName2() && !voting.VerifyEncryptionForPausing(blockHeight, totalStaked, false) {
				return nil, fmt.Errorf("voting pausing check fails, 2")
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
	logger.GetLogger().Printf("CheckBlockTransfers: block %d has %d transactions, lastSupply=%d", block.GetHeader().Height, len(txs), lastSupply)
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
		amount := poolTx.TxData.Amount
		total_amount := fee + amount
		address := poolTx.GetSenderAddress()
		recipientAddress := poolTx.TxData.Recipient
		if _, isCancellation := poolTx.CancellationTarget(); isCancellation {
			if _, err := validateEscrowCancellation(poolTx, block.GetHeader().Height); err != nil {
				return 0, 0, fmt.Errorf("invalid escrow cancellation: %w", err)
			}
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
			// remove bad transaction from pool
			transactionsPool.RemoveBadTransactionByHash(poolTx.Hash.GetBytes(), block.GetHeader().Height, tree)
			return 0, 0, fmt.Errorf("no account found in check block transafer: CheckBlockTransfers")
		}
		if bytes.Equal(poolTx.TxParam.MultiSignTx.GetBytes(), ZerosHash) == false && (poolTx.TxData.Amount > 0 || len(poolTx.TxData.OptData) > 0 || poolTx.TxData.LockedAmount > 0 || poolTx.TxData.MultiSignNumber > 0) {
			transactionsPool.RemoveBadTransactionByHash(poolTx.Hash.GetBytes(), block.GetHeader().Height, tree)
			return 0, 0, fmt.Errorf("transaction which confirms in multi signature account should have amount == 0, OptData = nil, LockedAmount = 0, MultiSignNumber = 0")
		}

		if _, ok := accounts[acc.Address]; ok {
			acc = accounts[acc.Address]
			acc.Balance -= total_amount
			accounts[acc.Address] = acc
		} else {
			acc.Balance -= total_amount
			accounts[acc.Address] = acc
		}
		if acc.Balance < 0 {
			// remove bad transaction from pool
			transactionsPool.RemoveBadTransactionByHash(poolTx.Hash.GetBytes(), block.GetHeader().Height, tree)
			return 0, 0, fmt.Errorf("not enough funds on account: CheckBlockTransfers")
		}

	}
	reward := account.GetReward(lastSupply)

	if lastSupply+reward != block.GetBlockSupply() {
		logger.GetLogger().Println("lastSupply:", lastSupply, "block.GetBlockSupply()", block.GetBlockSupply())
		return 0, 0, fmt.Errorf("block supply checking fails: CheckBlockTransfers")
	}

	return reward, totalFee, nil
}

func ProcessBlockTransfers(block Block, reward int64, tree *transactionsPool.MerkleTree) error {
	err := ProcessTransactionsEscrow(block.GetHeader().Height, tree)
	if err != nil {
		logger.GetLogger().Println("ProcessTransactionsEscrow: ", err)
	}

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

func CheckBlockAndTransactions(newBlock *Block, lastBlock Block, merkleTrie *transactionsPool.MerkleTree, checkFinal bool) error {

	defer RemoveAllTransactionsRelatedToBlock(*newBlock)
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

	head := newBlock.GetHeader()
	sigName, sigName2, isPaused, isPaused2, err := newBlock.GetSigNames()
	if err != nil {
		// AC-M6: previously the fmt.Errorf result was discarded, swallowing the
		// GetSigNames failure and proceeding with zero-value sig names.
		return fmt.Errorf("%v: CheckBlockAndTransactions", err)
	}
	if head.Verify(sigName, sigName2, isPaused, isPaused2) == false {
		return fmt.Errorf("header fails to verify: CheckBlockAndTransactions")
	}
	return nil
}

func CheckBlockAndTransferFunds(newBlock *Block, lastBlock Block, merkleTrie *transactionsPool.MerkleTree, checkWhenNotSync bool) error {

	defer RemoveAllTransactionsRelatedToBlock(*newBlock)
	n, err := account.IntDelegatedAccountFromAddress(newBlock.GetHeader().DelegatedAccount)
	if err != nil || n < 1 || n > 255 {
		return fmt.Errorf("wrong delegated account: CheckBlockAndTransferFunds")
	}
	opAccBlockAddr := newBlock.GetHeader().OperatorAccount
	if _, sumStaked, opAcc := account.GetStakedInDelegatedAccount(n); int64(sumStaked) < common.MinStakingForNode || !bytes.Equal(opAcc.Address[:], opAccBlockAddr.GetBytes()) {
		return fmt.Errorf("not enough staked coins to be a node or not valid operetional account: CheckBlockAndTransferFunds %v %v %v %v", int64(sumStaked), common.MinStakingForNode, opAcc.Address[:5], opAccBlockAddr.GetBytes()[:5])
	}

	reward, totalFee, err := CheckBlockTransfers(*newBlock, lastBlock, merkleTrie, false)
	if err != nil {
		return err
	}
	newBlock.BlockFee = totalFee + lastBlock.BlockFee

	if EvaluateSmartContracts(newBlock) == false {
		return fmt.Errorf("evaluation of smart contracts in block fails: CheckBlockAndTransferFunds")
	}

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
	hashes := newBlock.GetBlockTransactionsHashes()
	logger.GetLogger().Println("Number of transactions in block: ", len(hashes))
	err = ProcessBlockPubKey(*newBlock)
	if err != nil {
		return err
	}
	head := newBlock.GetHeader()
	sigName, sigName2, isPaused, isPaused2, err := newBlock.GetSigNames()
	if err != nil {
		return fmt.Errorf("%v: CheckBlockAndTransferFunds", err)
	}
	if head.Verify(sigName, sigName2, isPaused, isPaused2) == false {
		return fmt.Errorf("header fails to verify: CheckBlockAndTransferFunds")
	}

	err = merkleTrie.StoreTree(newBlock.GetHeader().Height)
	if err != nil {
		return err
	}
	err = ProcessBlockTransfers(*newBlock, reward, merkleTrie)
	if err != nil {
		return err
	}
	for _, h := range hashes {
		tx, err := transactionsDefinition.LoadFromDBPoolTx(common.TransactionPoolHashesDBPrefix[:], h.GetBytes())
		if err != nil {
			logger.GetLogger().Println(err)
			continue
		}
		err = tx.StoreToDBPoolTx(common.TransactionDBPrefix[:])
		if err != nil {
			return err
		}
		transactionsPool.PoolsTx.RemoveTransactionByHash(h.GetBytes())
		err = tx.RemoveFromDBPoolTx(common.TransactionPoolHashesDBPrefix[:])
		if err != nil {
			logger.GetLogger().Println(err)
		}
	}
	err = ProcessBlockEncryption(*newBlock, lastBlock)
	if err != nil {
		logger.GetLogger().Println("process block encryption fails", err)
	}
	return nil
}
