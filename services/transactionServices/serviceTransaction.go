package transactionServices

import (
	"bytes"
	"time"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"
	"github.com/wonabru/qwid-node/message"
	"github.com/wonabru/qwid-node/services"
	"github.com/wonabru/qwid-node/tcpip"
	"github.com/wonabru/qwid-node/transactionsDefinition"
	"github.com/wonabru/qwid-node/transactionsPool"
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

func broadcastTransactionsMsgInLoop() {
	seen := make(map[common.Hash]struct{}) // NP-H10: hashes already re-broadcast by this loop (single-goroutine, no mutex)
	for {
		select {
		case <-tcpip.Quit:
			logger.GetLogger().Println("broadcastTransactionsMsgInLoop: EXIT")
			return
		default:
		}

		txs := transactionsPool.PoolsTx.PeekTransactions(int(common.MaxTransactionsPerBlock), 0)
		pruneSeen(seen, txs)                       // NP-H10: drop mined/expired entries
		newTxs := selectNewTransactions(txs, seen) // NP-H10: send only the delta
		if len(newTxs) > 0 {
			topic := [2]byte{'T', 'T'}
			n, err := GenerateTransactionMsg(newTxs, []byte("tx"), topic)
			if err == nil {
				peers := tcpip.GetPeersConnected(tcpip.TransactionTopic)
				for topicip := range peers {
					var ip [4]byte
					copy(ip[:], topicip[2:])
					if !bytes.Equal(ip[:], tcpip.MyIP[:]) {
						Send(ip, n.GetBytes())
					}
				}
				for _, tx := range newTxs {
					seen[tx.GetHash()] = struct{}{}
				}
			}
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

func Send(addr [4]byte, nb []byte) bool {

	nb = append(addr[:], nb...)
	if services.SendMutexTx.TryLock() {
		defer services.SendMutexTx.Unlock()
		select {
		case services.SendChanTx <- nb:
			return true
		default:
			// NP-M10: best-effort gossip — the send channel is full, so drop this
			// message but log it (propagation is still covered by on-arrival
			// BroadcastTxn and the periodic delta loop). Blocking here would push
			// backpressure into the caller.
			logger.GetLogger().Println("NP-M10: tx send channel full, dropping outbound message")
			return false
		}
	}
	return false
}

func BroadcastTxn(ignoreAddr [4]byte, nb []byte) {
	var ip [4]byte
	var peers = tcpip.GetPeersConnected(tcpip.TransactionTopic)
	num_peers := len(peers)
	if num_peers == 0 {
		return
	}
	for topicip := range peers {
		// Send to all peers to ensure transactions reach mining nodes
		// Previously was randomly selecting ~1 peer which caused transactions to not propagate properly
		copy(ip[:], topicip[2:])
		if !bytes.Equal(ip[:], ignoreAddr[:]) && !bytes.Equal(ip[:], tcpip.MyIP[:]) {
			//logger.GetLogger().Println("send transactions to ", int(ip[0]), int(ip[1]), int(ip[2]), int(ip[3]))
			if !Send(ip, nb) {
				logger.GetLogger().Println("could not broadcast transaction")
			}
		}
	}
}

func startPublishingTransactionMsg() {
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
		default:
			time.Sleep(time.Millisecond * 100) // Reduced sleep time
		}
	}
}
