package nonceServices

import (
	"runtime/debug"

	"github.com/wonabru/qwid-node/logger"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/blocks"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/message"
	"github.com/wonabru/qwid-node/oracles"
	"github.com/wonabru/qwid-node/pubkeys"
	"github.com/wonabru/qwid-node/services"
	"github.com/wonabru/qwid-node/services/transactionServices"
	"github.com/wonabru/qwid-node/statistics"
	"github.com/wonabru/qwid-node/tcpip"
	"github.com/wonabru/qwid-node/transactionsDefinition"
	"github.com/wonabru/qwid-node/transactionsPool"
	"github.com/wonabru/qwid-node/voting"
)

func OnMessage(addr [4]byte, m []byte) {
	if common.IsSyncing.Load() {
		return
	}

	h := common.GetHeight()

	defer func() {
		if r := recover(); r != nil {
			debug.PrintStack()
			logger.GetLogger().Println("recover (nonce Msg)", r)
		}

	}()

	isValid, amsg := message.CheckValidMessage(m)
	if isValid == false {
		logger.GetLogger().Println("nonce msg validation fails")
		tcpip.ReduceAndCheckIfBanIP(addr)
		return
	}
	tcpip.ValidRegisterPeer(addr)
	switch string(amsg.GetHead()) {
	case "nn": // nonce

		//common.NonceMutex.Lock()
		//defer common.NonceMutex.Unlock()
		//fmt.Printf("%v", nonceTransaction)
		//var topic [2]byte
		txn, err := amsg.(message.TransactionsMessage).GetTransactionsFromBytes(common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2())
		if err != nil {
			return
		}
		nonceTransaction := map[[2]byte]transactionsDefinition.Transaction{}

		for k, v := range txn {
			nonceTransaction[k] = v[0]
		}
		var transaction transactionsDefinition.Transaction
		for _, v := range nonceTransaction {
			transaction = v
			break
		}

		nonceHeight := transaction.GetHeight()
		// checking if proper height
		if nonceHeight < 1 || nonceHeight != h+1 {
			//logger.GetLogger().Print("nonce height invalid")
			return
		}
		//KU TEMP TODO
		isValid = transaction.Verify(common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2())
		if isValid == false {
			// Distinguish an unregistered/unknown sender (we may simply be behind,
			// or the sender has not registered its pubkey on-chain yet) from a
			// genuinely bad signature. Only the latter is malicious and warrants a
			// ban; banning on a missing pubkey would ban our own sync source.
			sender := transaction.GetSenderAddress()
			sigb := transaction.GetSignature().GetBytes()
			primary := len(sigb) > 0 && sigb[0] == 0
			if _, perr := pubkeys.LoadPubKeyWithPrimary(sender, primary); perr != nil {
				logger.GetLogger().Println("nonce from sender with unregistered pubkey, ignoring (not banning)")
				return
			}
			logger.GetLogger().Println("nonce signature is invalid")
			tcpip.ReduceAndCheckIfBanIP(addr)
			return
		}
		//register checked Node IP
		tcpip.NodeRegisterPeer(addr)
		txDelAcc := transaction.TxData.Recipient
		n, err := account.IntDelegatedAccountFromAddress(txDelAcc)
		if err != nil {
			return
		}
		// Authorize the sender before mutating any oracle or voting state.  The
		// recipient is supplied by the sender, so a valid signature alone does not
		// prove that the sender controls the delegated account named there.
		mainAddress := transaction.GetSenderAddress()
		if !account.IsTop128StakingNode(n, mainAddress) {
			logger.GetLogger().Println("sender is not an eligible top-128 staking node", n, mainAddress.GetBytes()[:5])
			tcpip.ReduceAndCheckIfBanIP(addr)
			return
		}
		//delMy := common.GetDelegatedAccount()
		//if addr != tcpip.MyIP && bytes.Equal(txDelAcc.GetBytes(), delMy.GetBytes()) && addr != [4]byte{0, 0, 0, 0} {
		//	MyIP2 = addr
		//}
		// get oracles from nonce transaction
		// NP-C7: validate length before slicing so a crafted short OptData
		// cannot panic the node. Need the 8-byte + hash header, plus 8 bytes for
		// price, 8 for rand.
		if len(transaction.TxData.OptData) < 8+common.HashLength+16 {
			logger.GetLogger().Println("nonce tx OptData too short for oracle/voting data")
			return
		}
		optData := transaction.TxData.OptData[8+common.HashLength:]
		_, stakedInDelAcc, _ := account.GetStakedInDelegatedAccount(n)
		stakedInDelAccInt := int64(stakedInDelAcc)

		err = oracles.SavePriceOracle(common.GetInt64FromByte(optData[:8]), nonceHeight, txDelAcc, stakedInDelAccInt)
		if err != nil {
			logger.GetLogger().Println("could not save price oracle", err)
		}
		err = oracles.SaveRandOracle(common.GetInt64FromByte(optData[8:16]), nonceHeight, txDelAcc, stakedInDelAccInt)
		if err != nil {
			logger.GetLogger().Println("could not save rand oracle", err)
		}
		// Retain the signed nonce transaction so it can be embedded in the block
		// as a provenance proof for the oracle values above.
		err = oracles.SaveOracleProof(txDelAcc, nonceHeight, transaction.GetBytes())
		if err != nil {
			logger.GetLogger().Println("could not save oracle proof", err)
		}

		vb, b2, err := common.BytesWithLenToBytes(optData[16:])
		if err != nil {
			logger.GetLogger().Println("could not save voting, parse bytes fails, 1", err)
		}
		err = voting.SaveVotesEncryption1(vb[:], nonceHeight, txDelAcc, stakedInDelAccInt)
		if err != nil {
			logger.GetLogger().Println("could not save voting, 1", err)
		}
		vb, b2, err = common.BytesWithLenToBytes(b2[:])
		if err != nil {
			logger.GetLogger().Println("could not save voting, parse bytes fails, 2", err)
		}
		err = voting.SaveVotesEncryption2(vb[:], nonceHeight, txDelAcc, stakedInDelAccInt)
		if err != nil {
			logger.GetLogger().Println("could not save voting, 2", err)
		}

		lastBlock, err := blocks.LoadBlock(h)
		if err != nil {
			logger.GetLogger().Println(err)
			return
		}

		rawTxs := transactionsPool.PoolsTx.PeekTransactions(int(common.MaxTransactionsPerBlock), nonceHeight)
		// Filter out transactions that are already confirmed in the blockchain.
		// Under concurrent load, the memory pool can still hold transactions that
		// were confirmed moments ago by a parallel block handler, causing
		// CheckBlockTransfers to fail with "previously added in chain".
		txs := rawTxs[:0]
		for _, tx := range rawTxs {
			if transactionsDefinition.CheckFromDBPoolTx(common.TransactionDBPrefix[:], tx.Hash.GetBytes()) {
				// Already confirmed — clean it out of the memory pool proactively.
				transactionsPool.PoolsTx.RemoveTransactionByHash(tx.Hash.GetBytes())
				continue
			}
			txs = append(txs, tx)
		}
		txsBytes := make([][]byte, len(txs))
		transactionsHashes := []common.Hash{}
		for _, tx := range txs {
			hash := tx.GetHash().GetBytes()
			transactionsHashes = append(transactionsHashes, tx.GetHash())
			txsBytes = append(txsBytes, hash)
		}
		merkleTrie, err := transactionsPool.BuildMerkleTree(h+1, txsBytes, transactionsPool.GlobalMerkleTree.DB)
		defer merkleTrie.Destroy()

		if err != nil {
			logger.GetLogger().Println("cannot build merkleTrie")
			return
		}

		newBlock, err := services.CreateBlockFromNonceMessage([]transactionsDefinition.Transaction{transaction},
			lastBlock,
			merkleTrie,
			transactionsHashes)

		if err != nil {
			logger.GetLogger().Println(err)
			return

		}

		if newBlock.CheckProofOfSynergy() {
			_, _, err := blocks.CheckBlockTransfers(newBlock, lastBlock, merkleTrie, false)
			if err == nil {
				services.BroadcastBlock(newBlock)
			} else {
				logger.GetLogger().Println("new block is not valid. Bad transactions included:", err)
			}
		} else {
			//logger.GetLogger().Println("new block is not valid")
		}
		return
	case "rb": //reject block

	case "bl": //block

		common.BlockMutex.Lock()
		defer common.BlockMutex.Unlock()

		// Re-read height under the lock: another goroutine may have advanced it
		// between the top-of-OnMessage read and acquiring BlockMutex.
		h = common.GetHeight()

		lastBlock, err := blocks.LoadBlock(h)
		if err != nil {
			logger.GetLogger().Println(err)
			return
		}
		logger.GetLogger().Printf("+++++ Processing block in nonce service ++++++")
		txnbytes := amsg.GetTransactionsBytes()
		bls := map[[2]byte]blocks.Block{}
		for k, v := range txnbytes {
			if k[0] == byte('N') {

				bls[k], err = bls[k].GetFromBytes(v[0])
				newBlock := bls[k]
				if err != nil {
					logger.GetLogger().Println(err)
					logger.GetLogger().Println("cannot load blocks from bytes")
					tcpip.ReduceAndCheckIfBanIP(addr)
					return
				}

				if newBlock.GetHeader().Height != h+1 {
					logger.GetLogger().Println("block of too short chain")
					return
				}
				merkleTrie, err := blocks.CheckBaseBlock(newBlock, lastBlock, true)
				defer merkleTrie.Destroy()
				if err != nil {
					logger.GetLogger().Println(err)
					tcpip.ReduceAndCheckIfBanIP(addr)
					return
				}
				hashesMissing := blocks.IsAllTransactions(newBlock)
				if len(hashesMissing) > 0 {
					transactionServices.SendGT(addr, hashesMissing, "st")
					return
				}

				err = blocks.CheckBlockAndTransferFunds(&newBlock, lastBlock, merkleTrie, true)
				if err != nil {
					// Locked variant: common.BlockMutex is held for this whole case.
					services.ResetAccountsAndBlocksSyncLocked(lastBlock.GetHeader().Height)
					logger.GetLogger().Println("check transfer transactions in block fails", err)
					return
				}
				err = newBlock.StoreBlock()
				if err != nil {
					logger.GetLogger().Println(err)
					logger.GetLogger().Println("cannot store block")
					services.ResetAccountsAndBlocksSyncLocked(lastBlock.GetHeader().Height)
					return
				}

				logger.GetLogger().Println("New Block success -------------------------------------", h+1)
				err = account.StoreAccounts(newBlock.GetHeader().Height)
				if err != nil {
					logger.GetLogger().Println(err)
				}
				// Store-on-change: a snapshot is written only when this block executed
				// a contract/DEX/token transaction, so the EV keyspace grows with
				// contract activity, not chain length.
				if err := blocks.CommitEVMStateIfChanged(newBlock.GetHeader().Height); err != nil {
					logger.GetLogger().Println("cannot store EVM state", err)
				}

				err = account.StoreStakingAccounts(newBlock.GetHeader().Height)
				if err != nil {
					logger.GetLogger().Println(err)
				}
				common.SetHeight(h + 1)
				sm := statistics.GetStatsManager()
				sm.UpdateStatistics(newBlock, lastBlock)
				logger.GetLogger().Println("TPS: ", sm.Stats.Tps)
				// NP-M11: release this iteration's merkle tree promptly instead of
				// letting deferred Destroy calls accumulate until the function
				// returns. Destroy is idempotent, so the defer above is harmless.
				merkleTrie.Destroy()
			}
		}
	default:
	}
}
