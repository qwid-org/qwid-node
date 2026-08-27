package transactionServices

import (
	"fmt"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/message"
	"github.com/qwid-org/qwid-node/pubkeys"
	"github.com/qwid-org/qwid-node/tcpip"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

func OnMessage(addr [4]byte, m []byte) {

	//logger.GetLogger().Println("New message nonce from:", addr)

	defer func() {
		if r := recover(); r != nil {
			//debug.PrintStack()
			logger.GetLogger().Println("recover (nonce Msg)", r)
		}

	}()

	isValid, amsg := message.CheckValidMessage(m)
	if isValid == false {
		logger.GetLogger().Println("transaction msg validation fails")
		tcpip.ReduceAndCheckIfBanIP(addr)
		return
	}

	switch string(amsg.GetHead()) {
	case "tx":

		msg := amsg.(message.TransactionsMessage)
		txn, err := msg.GetTransactionsFromBytes(common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2())
		if err != nil {
			return
		}
		//logger.GetLogger().Println("get tx from ", addr[:])
		if transactionsPool.PoolsTx.NumberOfTransactions() > common.MaxTransactionInPool {
			logger.GetLogger().Println("no more transactions can be accepted to the pool")
			return
		}
		// need to check transactions
		for _, v := range txn {
			for _, t := range v {
				//logger.GetLogger().Println("Processing transaction:", t.Hash.GetHex())
				// pk := t.TxData.Pubkey
				//if len(pk.GetBytes()) > 0 {
				//	logger.GetLogger().Println("  Transaction has pubkey, length:", len(pk.GetBytes()))
				//}
				if transactionsPool.PoolsTx.TransactionExists(t.Hash.GetBytes()) {
					//logger.GetLogger().Println("  Transaction already exists in Pool, skipping")
					// Even if already in pool, store the pubkey if present
					// if len(pk.GetBytes()) > 0 {
					// 	//logger.GetLogger().Println("  Storing pubkey from existing transaction")
					// 	storePubKeyFromTransaction(pk, t.GetSenderAddress())
					// }
					continue
				}
				if transactionsDefinition.CheckFromDBPoolTx(common.TransactionDBPrefix[:], t.Hash.GetBytes()) {
					//logger.GetLogger().Println("  Transaction already exists in DB, skipping")
					// Even if already in DB, store the pubkey if present
					// if len(pk.GetBytes()) > 0 {
					// 	//logger.GetLogger().Println("  Storing pubkey from existing transaction in DB")
					// 	storePubKeyFromTransaction(pk, t.GetSenderAddress())
					// }
					continue
				}

				// Route to appropriate pool based on sender's account settings
				// senderAddr := t.GetSenderAddress()
				// senderAcc, senderExist := account.GetAccountByAddressBytes(senderAddr.GetBytes())
				// var isAdded bool
				// if senderExist && senderAcc.TransactionDelay > 0 {
				// 	t.TxData.EscrowTransactionsDelay = senderAcc.TransactionDelay
				// 	isAdded = transactionsPool.PoolTxEscrow.AddTransaction(t, t.Hash)
				// } else if senderExist && senderAcc.MultiSignNumber > 0 {
				// 	isAdded = transactionsPool.PoolTxMultiSign.AddTransaction(t, t.Hash)
				// } else {
					// Reject non-staking transactions to delegated accounts
				if n, err := account.IntDelegatedAccountFromAddress(t.TxData.Recipient); err == nil && n > 0 && n < 256 {
					if t.TxData.Amount > 0 && t.TxData.Amount < common.MinStakingUser && t.GetLockedAmount() == 0 {
						logger.GetLogger().Println("Rejected: transfer to delegated account below minimum staking amount")
						continue
					}
				}
				isAdded := transactionsPool.PoolsTx.AddTransaction(t, t.Hash)
				// }
				if isAdded {
					err := t.StoreToDBPoolTx(common.TransactionPoolHashesDBPrefix[:])
					if err != nil {
						transactionsPool.PoolsTx.RemoveTransactionByHash(t.Hash.GetBytes())
						err := transactionsDefinition.RemoveTransactionFromDBbyHash(common.TransactionPoolHashesDBPrefix[:], t.Hash.GetBytes())
						if err != nil {
							logger.GetLogger().Println(err)
						}
						logger.GetLogger().Println(err)
						continue
					}
					// Store pubkey immediately so it's available for nonce verification
					// pk := t.TxData.Pubkey
					// if len(pk.GetBytes()) > 0 {
					// 	//logger.GetLogger().Println("Storing pubkey from transaction immediately")
					// 	storePubKeyFromTransaction(pk, t.GetSenderAddress())
					// }
					// Always broadcast local transactions (from RPC/wallet with addr 0.0.0.0)
					// For remote transactions, only broadcast if not syncing
					isLocalTx := addr == [4]byte{0, 0, 0, 0}
					if isLocalTx { // || !common.IsSyncing.Load() {
						BroadcastTxn(addr, m)
					}
				}
			}
		}
	case "bx":
		// transaction in sync - during sync, skip signature verification because
		// the syncing node may not have sender pubkeys yet (stored during block processing).
		// Block merkle tree guarantees transaction integrity.
		msg := amsg.(message.TransactionsMessage)
		rawTxn := msg.GetTransactionsBytes()

		// One bx answer carries a whole block's worth of transactions, and a node
		// catching up receives one per block. Logging a line per transaction made
		// the log — and the sync it was supposed to describe — crawl, so the loop
		// only counts. A single line per answer reports the batch and names the
		// FIRST failure of each kind, because a transaction dropped here is a block
		// that cannot be applied: the count alone would say sync is stuck without
		// saying why.
		storedCount := 0
		skippedExisting := 0
		undecodable := 0
		droppedCount := 0
		storeFailures := 0
		var firstDecodeErr error
		var firstDropReason string
		var firstStoreErr error
		for _, v := range rawTxn {
			for _, tb := range v {
				tx := transactionsDefinition.Transaction{}
				t, rest, err := tx.GetFromBytes(tb)
				if err != nil || len(rest) > 0 {
					undecodable++
					if firstDecodeErr == nil {
						if err == nil {
							err = fmt.Errorf("%v trailing bytes after transaction", len(rest))
						}
						firstDecodeErr = err
					}
					continue
				}
				if transactionsDefinition.CheckFromDBPoolTx(common.TransactionDBPrefix[:], t.Hash.GetBytes()) {
					skippedExisting++
					continue
				}
				if transactionsDefinition.CheckFromDBPoolTx(common.TransactionPoolHashesDBPrefix[:], t.Hash.GetBytes()) {
					skippedExisting++
					continue
				}
				// NP-C6: verify the signature whenever the sender's public key is
				// available (embedded in the tx, or already registered). Only skip
				// verification when the pubkey is genuinely not yet known during
				// sync — the signed block merkle root still enforces integrity when
				// the referencing block is later validated.
				sigBytes := t.GetSignature().GetBytes()
				if len(sigBytes) == 0 {
					droppedCount++
					if firstDropReason == "" {
						firstDropReason = fmt.Sprintf("tx %x has an empty signature", t.Hash.GetBytes()[:8])
					}
					continue
				}
				canVerify := len(t.TxData.GetPubKey().GetBytes()) > 0
				if !canVerify {
					if _, perr := pubkeys.LoadPubKeyWithPrimary(t.GetSenderAddress(), sigBytes[0] == 0); perr == nil {
						canVerify = true
					}
				}
				if canVerify && !t.Verify(common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2()) {
					droppedCount++
					if firstDropReason == "" {
						firstDropReason = fmt.Sprintf("tx %x failed signature verification", t.Hash.GetBytes()[:8])
					}
					continue
				}
				if err := t.StoreToDBPoolTx(common.TransactionPoolHashesDBPrefix[:]); err != nil {
					storeFailures++
					if firstStoreErr == nil {
						firstStoreErr = fmt.Errorf("tx %x: %w", t.Hash.GetBytes()[:8], err)
					}
					continue
				}
				storedCount++
			}
		}
		summary := fmt.Sprintf("bx: stored %d transaction(s), %d already present", storedCount, skippedExisting)
		if undecodable > 0 {
			summary += fmt.Sprintf("; %d undecodable (first: %v)", undecodable, firstDecodeErr)
		}
		if droppedCount > 0 {
			summary += fmt.Sprintf("; %d dropped (first: %s)", droppedCount, firstDropReason)
		}
		if storeFailures > 0 {
			summary += fmt.Sprintf("; %d store failure(s) (first: %v)", storeFailures, firstStoreErr)
		}
		logger.GetLogger().Println(summary)
	case "st":
		txn := amsg.(message.TransactionsMessage).GetTransactionsBytes()
		for topic, v := range txn {
			txs := []transactionsDefinition.Transaction{}
			for _, hs := range v {
				// First try to load from Pool
				t, err := transactionsDefinition.LoadFromDBPoolTx(common.TransactionPoolHashesDBPrefix[:], hs)
				if err != nil {
					// If not in Pool, try to load from confirmed DB
					t, err = transactionsDefinition.LoadFromDBPoolTx(common.TransactionDBPrefix[:], hs)
					if err != nil {
						// If not in confirmed DB, try bad transaction DB
						t, err = transactionsDefinition.LoadFromDBPoolTx(common.BadTransactionDBPrefix[:], hs)
						if err != nil {
							logger.GetLogger().Println("cannot load transaction from Pool, DB, or BadTx", err)
							continue
						}
					}
				}
				if len(t.GetBytes()) > 0 {
					txs = append(txs, t)
				}
			}
			transactionMsg, err := GenerateTransactionMsg(txs, []byte("tx"), topic)
			if err != nil {
				logger.GetLogger().Println("cannot generate transaction msg", err)
			}
			if !Send(addr, transactionMsg.GetBytes()) {
				logger.GetLogger().Println("could not send transaction in sync")
			}
			logger.GetLogger().Println("SENT transaction is sync st to ", addr[:])
		}
	case "bt":
		txn := amsg.(message.TransactionsMessage).GetTransactionsBytes()
		for topic, v := range txn {
			txs := []transactionsDefinition.Transaction{}
			for _, hs := range v {
				// First try to load from confirmed DB
				t, err := transactionsDefinition.LoadFromDBPoolTx(common.TransactionDBPrefix[:], hs)
				if err != nil {
					// If not in confirmed DB, try to load from Pool
					t, err = transactionsDefinition.LoadFromDBPoolTx(common.TransactionPoolHashesDBPrefix[:], hs)
					if err != nil {
						// If not in Pool, try bad transaction DB
						t, err = transactionsDefinition.LoadFromDBPoolTx(common.BadTransactionDBPrefix[:], hs)
						if err != nil {
							logger.GetLogger().Printf("  tx %x NOT FOUND in any DB", hs[:8])
							continue
						}
						// Validate recovered bad transaction
						if !t.Verify(common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2()) {
							logger.GetLogger().Printf("  tx %x from badTx FAILED validation", hs[:8])
							continue
						}
						// Store to confirmed DB
						err = t.StoreToDBPoolTx(common.TransactionDBPrefix[:])
						if err != nil {
							logger.GetLogger().Printf("  tx %x failed to store to confirmed DB: %v", hs[:8], err)
							continue
						}
					}
				}
				txs = append(txs, t)
			}
			logger.GetLogger().Println("  Found", len(txs), "transactions to send")
			transactionMsg, err := GenerateTransactionMsg(txs, []byte("bx"), topic)
			if err != nil {
				logger.GetLogger().Println("cannot generate transaction msg", err)
			}
			if !Send(addr, transactionMsg.GetBytes()) {
				logger.GetLogger().Println("could not send transaction is sync bt - Send failed")
			} else {
				logger.GetLogger().Println("SENT transaction is sync bt to ", addr[:], "count:", len(txs))
			}
		}
	default:
	}
}
