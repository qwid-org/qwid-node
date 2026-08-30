package transactionServices

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
	"runtime"
	"sync"
	"time"

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

		// Backpressure BEFORE the expensive work, not after it.
		//
		// GetTransactionsFromBytes verifies the post-quantum signature of every
		// transaction in the batch, and a batch runs to MaxTransactionsPerBlock.
		// With this check below the decode, a node whose pool was full verified
		// thousands of signatures per gossip message and then dropped the whole
		// batch unused — burning the CPU that block processing and sync need,
		// exactly while it was least able to spare it. The cost scales with the
		// scheme in force, and a voted-in scheme can be far dearer than the one
		// this was written under.
		//
		// This affects gossip only. The sync answers "bx"/"bt"/"st" carry no
		// such check and must not gain one: a node catching up has to accept the
		// transactions of every block it is importing, whatever its pool holds.
		if transactionsPool.PoolsTx.NumberOfTransactions() > common.MaxTransactionInPool {
			// A full pool is a STATE that persists for as long as it takes the
			// chain to drain it, not an event. Logging it on every gossip
			// message meant one line per message from every peer for minutes on
			// end; the logger writes synchronously to file and stdout, so under
			// load that write became the slowest thing in the receive path and
			// stalled the loop that also carries sync and nonce traffic —
			// which is block production. Report it periodically, with the
			// number of messages dropped meanwhile so the rate stays visible.
			if dropped := notePoolFullDrop(); dropped > 0 {
				logger.GetLogger().Printf("no more transactions can be accepted to the pool (%d gossip message(s) dropped since the last report)", dropped)
			}
			return
		}

		msg := amsg.(message.TransactionsMessage)
		txn, err := msg.GetTransactionsFromBytes(common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2())
		if err != nil {
			return
		}
		belowMinStaking := 0
		//logger.GetLogger().Println("get tx from ", addr[:])
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
						// Counted, not logged: this sat in the per-transaction
						// loop, so a sender emitting these at 500 TPS produced
						// 500 synchronous log writes per second in the receive
						// path. One line per message carries the same
						// information.
						belowMinStaking++
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
		if belowMinStaking > 0 {
			logger.GetLogger().Printf("rejected %d transfer(s) to a delegated account below the minimum staking amount", belowMinStaking)
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

		// The whole per-transaction pipeline (decode, dedup, signature verify,
		// store) runs in a small worker pool. One bx answer carries up to
		// MaxNumberTransactionInChunk transactions and signature verification
		// dominates the cost; processing them serially kept the receive loop
		// pinned to one core, the inbound queue backed up faster than it
		// drained, and block application starved for CPU. Two cores are left
		// free for the apply path and the other services.
		var resMutex sync.Mutex
		var wg sync.WaitGroup
		jobs := make(chan []byte, 2*common.MaxNumberTransactionInChunk)
		workers := runtime.NumCPU() - 2
		if workers < 2 {
			workers = 2
		}
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for tb := range jobs {
					tx := transactionsDefinition.Transaction{}
					t, rest, err := tx.GetFromBytes(tb)
					if err != nil || len(rest) > 0 {
						resMutex.Lock()
						undecodable++
						if firstDecodeErr == nil {
							if err == nil {
								err = fmt.Errorf("%v trailing bytes after transaction", len(rest))
							}
							firstDecodeErr = err
						}
						resMutex.Unlock()
						continue
					}
					if transactionsDefinition.CheckFromDBPoolTx(common.TransactionDBPrefix[:], t.Hash.GetBytes()) ||
						transactionsDefinition.CheckFromDBPoolTx(common.TransactionPoolHashesDBPrefix[:], t.Hash.GetBytes()) {
						resMutex.Lock()
						skippedExisting++
						resMutex.Unlock()
						continue
					}
					// NP-C6: verify the signature whenever the sender's public key is
					// available (embedded in the tx, or already registered). Only skip
					// verification when the pubkey is genuinely not yet known during
					// sync — the signed block merkle root still enforces integrity when
					// the referencing block is later validated.
					sigBytes := t.GetSignature().GetBytes()
					if len(sigBytes) == 0 {
						resMutex.Lock()
						droppedCount++
						if firstDropReason == "" {
							firstDropReason = fmt.Sprintf("tx %x has an empty signature", t.Hash.GetBytes()[:8])
						}
						resMutex.Unlock()
						continue
					}
					canVerify := len(t.TxData.GetPubKey().GetBytes()) > 0
					if !canVerify {
						if _, perr := pubkeys.LoadPubKeyWithPrimary(t.GetSenderAddress(), sigBytes[0] == 0); perr == nil {
							canVerify = true
						}
					}
					if canVerify && !t.Verify(common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2()) {
						resMutex.Lock()
						droppedCount++
						if firstDropReason == "" {
							firstDropReason = fmt.Sprintf("tx %x failed signature verification", t.Hash.GetBytes()[:8])
						}
						resMutex.Unlock()
						continue
					}
					if err := t.StoreToDBPoolTx(common.TransactionPoolHashesDBPrefix[:]); err != nil {
						resMutex.Lock()
						storeFailures++
						if firstStoreErr == nil {
							firstStoreErr = fmt.Errorf("tx %x: %w", t.Hash.GetBytes()[:8], err)
						}
						resMutex.Unlock()
						continue
					}
					resMutex.Lock()
					storedCount++
					resMutex.Unlock()
				}
			}()
		}
		for _, v := range rawTxn {
			for _, tb := range v {
				jobs <- tb
			}
		}
		close(jobs)
		wg.Wait()
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
	case "bz":
		// A bz payload is a whole serialized bx message, flate-compressed by
		// the bt handler when the answer is large. Transaction batches carry
		// mostly high-entropy post-quantum signatures, yet still shed ~25% of
		// their size - exactly what a saturated link needs. After validating
		// that the inflated bytes really are a bx message, it is fed back
		// through OnMessage, so the bx pipeline stays in one place; the head
		// check makes nested bz impossible.
		for _, v := range amsg.(message.TransactionsMessage).GetTransactionsBytes() {
			for _, zb := range v {
				fr := flate.NewReader(bytes.NewReader(zb))
				// Decompression-bomb guard: cap the inflated size at the wire
				// message limit; truncation then fails CheckValidMessage below.
				raw, err := io.ReadAll(io.LimitReader(fr, int64(common.MaxMessageSizeBytes)))
				fr.Close()
				if err != nil {
					logger.GetLogger().Println("bz: cannot decompress:", err)
					tcpip.ReduceAndCheckIfBanIP(addr)
					continue
				}
				ok, inner := message.CheckValidMessage(raw)
				if !ok || string(inner.GetHead()) != "bx" {
					logger.GetLogger().Println("bz: payload is not a valid bx message")
					tcpip.ReduceAndCheckIfBanIP(addr)
					continue
				}
				OnMessage(addr, raw)
			}
		}
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
		// A bt answer is a multi-MB message. When the outbound channel is
		// already backed up it would only be dropped on the way out (NP-M10) -
		// skip building it; the requester retries after its retry interval.
		if SendChannelCongested() {
			noteDroppedSend()
			return
		}
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
			out := transactionMsg.GetBytes()
			// Large answers go out flate-compressed as a bz message (~25% less
			// wire bytes for a few ms of CPU); small ones stay plain bx.
			if len(out) > compressBxThreshold {
				if zb, zerr := compressToBz(out, topic); zerr == nil {
					logger.GetLogger().Printf("bt answer compressed: %d -> %d bytes", len(out), len(zb))
					out = zb
				}
			}
			if !Send(addr, out) {
				logger.GetLogger().Println("could not send transaction is sync bt - Send failed")
			} else {
				logger.GetLogger().Println("SENT transaction is sync bt to ", addr[:], "count:", len(txs))
			}
		}
	default:
	}
}

// poolFullDrops counts gossip messages refused because the pool is full, and
// notePoolFullDrop reports how many have accumulated when it is time to log
// again. Returning the count rather than a bare bool keeps the suppressed
// volume visible: "dropped 4200 messages" and "dropped 3" describe very
// different situations and must not look alike in the log.
var (
	poolFullMutex     sync.Mutex
	poolFullDrops     int
	poolFullLastLog   time.Time
	poolFullLogPeriod = 10 * time.Second
)

func notePoolFullDrop() int {
	poolFullMutex.Lock()
	defer poolFullMutex.Unlock()
	poolFullDrops++
	now := time.Now()
	if !poolFullLastLog.IsZero() && now.Sub(poolFullLastLog) < poolFullLogPeriod {
		return 0
	}
	poolFullLastLog = now
	n := poolFullDrops
	poolFullDrops = 0
	return n
}
