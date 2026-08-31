package transactionServices

import (
	"bytes"
	"compress/flate"
	"sync"
	"time"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/message"
	"github.com/qwid-org/qwid-node/services"
	"github.com/qwid-org/qwid-node/tcpip"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

func InitTransactionService() {
	services.SendMutexTx.Lock()
	services.SendChanTx = make(chan []byte, 100)

	services.SendMutexTx.Unlock()
	startPublishingTransactionMsg()
	go broadcastTransactionsMsgInLoop()
}

func GenerateTransactionMsg(txs []transactionsDefinition.Transaction, mesgHead []byte, topic [2]byte) (message.TransactionsMessage, error) {

	bm := message.BaseMessage{
		Head:    mesgHead,
		ChainID: common.GetChainID(),
	}
	bb := [][]byte{}
	for _, tx := range txs {
		b := tx.GetBytes()
		bb = append(bb, b)
	}

	n := message.TransactionsMessage{
		BaseMessage:       bm,
		TransactionsBytes: map[[2]byte][][]byte{topic: bb},
	}
	return n, nil
}

func GenerateTransactionMsgGT(txsHashes [][]byte, mesgHead []byte, topic [2]byte) (message.TransactionsMessage, error) {

	bm := message.BaseMessage{
		Head:    mesgHead,
		ChainID: common.GetChainID(),
	}

	n := message.TransactionsMessage{
		BaseMessage:       bm,
		TransactionsBytes: map[[2]byte][][]byte{topic: txsHashes},
	}
	return n, nil
}

// selectNewTransactions returns the subset of txs whose hash is not already in
// seen (i.e. not yet re-broadcast by the periodic loop). Pure; does not mutate seen. NP-H10.
func selectNewTransactions(txs []transactionsDefinition.Transaction, seen map[common.Hash]struct{}) []transactionsDefinition.Transaction {
	out := make([]transactionsDefinition.Transaction, 0, len(txs))
	for _, tx := range txs {
		if _, ok := seen[tx.GetHash()]; !ok {
			out = append(out, tx)
		}
	}
	return out
}

// pruneSeen removes from seen every hash not present in txs, so entries for
// mined/dropped transactions do not accumulate. Mutates seen. NP-H10.
func pruneSeen(seen map[common.Hash]struct{}, txs []transactionsDefinition.Transaction) {
	if len(seen) == 0 {
		return
	}
	present := make(map[common.Hash]struct{}, len(txs))
	for _, tx := range txs {
		present[tx.GetHash()] = struct{}{}
	}
	for h := range seen {
		if _, ok := present[h]; !ok {
			delete(seen, h)
		}
	}
}

// transactionKeepaliveInterval paces the empty "tx" keepalive below. It must
// stay well under tcpip's quiet-connection timeout (3 min), or the watchdog
// keeps killing the idle-but-healthy transaction link.
const transactionKeepaliveInterval = time.Minute

func broadcastTransactionsMsgInLoop() {
	seen := make(map[common.Hash]struct{}) // NP-H10: hashes already re-broadcast by this loop (single-goroutine, no mutex)
	var lastNoPeerLog time.Time            // rate-limits the "nowhere to send" warning below
	lastOutbound := time.Now()             // last moment anything was sent on the transaction topic
	for {
		select {
		case <-tcpip.Quit:
			logger.GetLogger().Println("broadcastTransactionsMsgInLoop: EXIT")
			return
		default:
		}

		sentAnything := false
		txs := transactionsPool.PoolsTx.PeekTransactions(int(common.MaxTransactionsPerBlock), 0)
		pruneSeen(seen, txs)                       // NP-H10: drop mined/expired entries
		newTxs := selectNewTransactions(txs, seen) // NP-H10: send only the delta
		if len(newTxs) > 0 {
			topic := [2]byte{'T', 'T'}
			n, err := GenerateTransactionMsg(newTxs, []byte("tx"), topic)
			if err == nil {
				peers := tcpip.GetPeersConnected(tcpip.TransactionTopic)
				// With no peer on the transaction topic this loop sends nothing
				// and says nothing, so locally submitted transactions sit in the
				// pool as "pending" while the node looks perfectly healthy. Say
				// it out loud instead — the pool filling up with transactions
				// that have nowhere to go is a connectivity fault, not patience.
				if len(peers) == 0 {
					if time.Since(lastNoPeerLog) > time.Minute {
						logger.GetLogger().Printf("WARNING: %d transaction(s) waiting to be broadcast but no peer is connected on the transaction topic; "+
							"they cannot reach the network and will stay pending", len(newTxs))
						lastNoPeerLog = time.Now()
					}
				}
				delivered := false
				for topicip := range peers {
					var ip [4]byte
					copy(ip[:], topicip[2:])
					if !bytes.Equal(ip[:], tcpip.MyIP[:]) {
						if Send(ip, n.GetBytes()) {
							delivered = true
						}
					}
				}
				// Mark as re-broadcast ONLY when at least one remote peer
				// actually got the message. Marking with zero peers (or with
				// every Send failing) silenced these transactions forever: once
				// the transaction-topic connection came back, this loop
				// considered them already sent, so anything submitted during an
				// outage stayed pending until manually resubmitted.
				if delivered {
					for _, tx := range newTxs {
						seen[tx.GetHash()] = struct{}{}
					}
					sentAnything = true
				}
			}
		}

		// Keepalive: the transaction topic is naturally silent when no
		// transactions flow, so the quiet-connection watchdog kept killing the
		// idle-but-healthy link — and a transaction submitted right then found
		// no peer to go to. An empty, valid "tx" message once a minute keeps
		// the link demonstrably alive on both ends; receivers process it as a
		// no-op (no transactions inside), old nodes included.
		if !sentAnything && time.Since(lastOutbound) >= transactionKeepaliveInterval {
			if ka, err := GenerateTransactionMsg(nil, []byte("tx"), tcpip.TransactionTopic); err == nil {
				kb := ka.GetBytes()
				for topicip := range tcpip.GetPeersConnected(tcpip.TransactionTopic) {
					var ip [4]byte
					copy(ip[:], topicip[2:])
					if !bytes.Equal(ip[:], tcpip.MyIP[:]) {
						if Send(ip, kb) {
							sentAnything = true
						}
					}
				}
			}
		}
		if sentAnything {
			lastOutbound = time.Now()
		}

		time.Sleep(time.Second)
	}
}

func SendTransactionMsg(ip [4]byte, topic [2]byte) bool {
	isync := common.IsSyncing.Load()
	if isync == true {
		return true
	}
	txs := transactionsPool.PoolsTx.PeekTransactions(int(common.MaxTransactionsPerBlock), 0)
	n, err := GenerateTransactionMsg(txs, []byte("tx"), topic)
	if err != nil {
		logger.GetLogger().Println(err)
		return false
	}
	if !Send(ip, n.GetBytes()) {
		logger.GetLogger().Println("could not send standard transaction")
		return false
	}
	return true
}

func SendGT(ip [4]byte, txsHashes [][]byte, syncPre string) {
	topic := tcpip.TransactionTopic
	transactionMsg, err := GenerateTransactionMsgGT(txsHashes, []byte(syncPre), topic)
	if err != nil {
		logger.GetLogger().Println("cannot generate transaction msg", err)
	}
	if !Send(ip, transactionMsg.GetBytes()) {
		logger.GetLogger().Println("could not send send transaction in GT message")
	}
}

var (
	sendDropMutex   sync.Mutex
	sendDropCount   int
	sendDropLogTime time.Time
)

// compressBxThreshold is the serialized bx size above which the answer is sent
// as a flate-compressed bz message instead. Small answers are not worth the
// round trip through the compressor, and staying plain keeps them readable to
// any tooling that speaks only bx.
const compressBxThreshold = 4096

// compressToBz wraps a whole serialized bx message in a bz envelope:
// flate(BestSpeed) over the bytes, carried as the single payload of a "bz"
// TransactionsMessage. Measured on real stored transactions this sheds ~25% of
// the size (post-quantum signatures are high-entropy; the win comes from the
// structural bytes) at under 5ms per 500-transaction chunk.
func compressToBz(bxBytes []byte, topic [2]byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(bxBytes); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	n := message.TransactionsMessage{
		BaseMessage: message.BaseMessage{
			Head:    []byte("bz"),
			ChainID: common.GetChainID(),
		},
		TransactionsBytes: map[[2]byte][][]byte{topic: {buf.Bytes()}},
	}
	return n.GetBytes(), nil
}

// noteDroppedSend counts a dropped outbound message and emits at most one
// summary line a minute (see the NP-M10 comment in Send).
func noteDroppedSend() {
	sendDropMutex.Lock()
	sendDropCount++
	if time.Since(sendDropLogTime) > time.Minute {
		logger.GetLogger().Printf("NP-M10: tx send channel full - dropped %d outbound message(s) in the last minute "+
			"(outbound bandwidth saturated; peers re-request anything they miss)", sendDropCount)
		sendDropCount = 0
		sendDropLogTime = time.Now()
	}
	sendDropMutex.Unlock()
}

// SendChannelCongested reports whether the outbound transaction channel is
// nearly full. Building a multi-MB bt answer that will only be dropped on the
// way out wastes the CPU and memory the congestion is already short of.
func SendChannelCongested() bool {
	services.SendMutexTx.RLock()
	defer services.SendMutexTx.RUnlock()
	if services.SendChanTx == nil {
		return true
	}
	return len(services.SendChanTx) > 3*cap(services.SendChanTx)/4
}

func Send(addr [4]byte, nb []byte) bool {

	nb = append(addr[:], nb...)
	if services.SendMutexTx.TryLock() {
		defer services.SendMutexTx.Unlock()
		select {
		case services.SendChanTx <- nb:
			return true
		default:
			// NP-M10: best-effort gossip — the send channel is full, so drop this
			// message (propagation is still covered by the periodic delta loop
			// and the requester's bt retry). Blocking here would push
			// backpressure into the caller.
			//
			// Logged as a once-a-minute summary: under sustained load (serving
			// multi-MB bx answers over a link slower than they are produced) the
			// channel stays full for long stretches, and a line per dropped
			// message drowned the log and slowed the very sending it described.
			noteDroppedSend()
			return false
		}
	}
	return false
}

func startPublishingTransactionMsg() {
	tcpip.RegisterTopicHandler(tcpip.TransactionTopic, OnMessage)
	go tcpip.StartNewListener(tcpip.TransactionTopic)
	go tcpip.LoopSend(services.SendChanTx, tcpip.TransactionTopic)
}

func StartSubscribingTransactionMsg(ip [4]byte) {
	recvChan := make(chan []byte, 100) // Increased buffer size
	quit := false
	var ipr [4]byte
	go tcpip.StartNewConnection(ip, recvChan, tcpip.TransactionTopic)
	for !services.QUIT.Load() && !quit {
		select {
		case s := <-recvChan:
			if len(s) == 4 && bytes.Equal(s, []byte("EXIT")) {
				quit = true
				break
			}
			if len(s) > 4 {
				copy(ipr[:], s[:4])
				OnMessage(ipr, s[4:])
			}
		case <-tcpip.Quit:
			logger.GetLogger().Printf("Received quit signal for peer %v", ip)
			services.QUIT.Store(true)
		}
	}
}
