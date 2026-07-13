package syncServices

import (
	"bytes"
	"math/rand"
	"time"

	"github.com/wonabru/qwid-node/blocks"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"
	"github.com/wonabru/qwid-node/message"
	"github.com/wonabru/qwid-node/services"
	"github.com/wonabru/qwid-node/tcpip"
)

// sampleIPs returns up to n distinct entries of ips chosen at random (all of ips
// if len(ips) <= n). Preserves peer discovery without revealing the full peer set
// in any single 'hi' message. NP-M14.
func sampleIPs(ips [][]byte, n int) [][]byte {
	if len(ips) <= n {
		return ips
	}
	perm := rand.Perm(len(ips))[:n]
	out := make([][]byte, 0, n)
	for _, i := range perm {
		out = append(out, ips[i])
	}
	return out
}

func InitSyncService() {
	services.SendMutexSync.Lock()
	services.SendChanSync = make(chan []byte, 100)

	services.SendMutexSync.Unlock()
	startPublishingSyncMsg()
	time.Sleep(time.Second)
	go sendSyncMsgInLoop()
}

func generateSyncMsgHeight() []byte {
	h := common.GetHeight()
	bm := message.BaseMessage{
		Head:    []byte("hi"),
		ChainID: common.GetChainID(),
	}
	n := message.TransactionsMessage{
		BaseMessage:       bm,
		TransactionsBytes: map[[2]byte][][]byte{},
	}
	n.TransactionsBytes[[2]byte{'L', 'H'}] = [][]byte{common.GetByteInt64(h)}
	lastBlockHash, err := blocks.LoadHashOfBlock(h)
	if err != nil {
		logger.GetLogger().Printf("generateSyncMsgHeight: Can not load hash for block %d: %v", h, err)
		return []byte("")
	}
	n.TransactionsBytes[[2]byte{'L', 'B'}] = [][]byte{lastBlockHash}

	// NP-M14: share only a bounded random subset of connected peers, so no single
	// 'hi' message discloses the full topology, while peer discovery still works.
	peers := sampleIPs(tcpip.GetIPsConnected(), common.MaxPeersSharedInHi)

	n.TransactionsBytes[[2]byte{'P', 'P'}] = peers
	nb := n.GetBytes()
	return nb
}

func generateSyncMsgGetHeaders(height int64) []byte {
	if height <= 0 {
		return nil
	}
	eHeight := height
	h := common.GetHeight()
	s2p := height - h + 1
	if s2p > common.NumberOfHashesInBucket {
		s2p = common.NumberOfHashesInBucket
	}
	bHeight := height - s2p
	if bHeight < 2 {
		bHeight = 0
	}
	if bHeight > h {
		bHeight = h
		eHeight = h + s2p
		if eHeight > height {
			eHeight = height
		}
	}
	bm := message.BaseMessage{
		Head:    []byte("gh"),
		ChainID: common.GetChainID(),
	}
	n := message.TransactionsMessage{
		BaseMessage:       bm,
		TransactionsBytes: map[[2]byte][][]byte{},
	}
	n.TransactionsBytes[[2]byte{'B', 'H'}] = [][]byte{common.GetByteInt64(bHeight)}
	n.TransactionsBytes[[2]byte{'E', 'H'}] = [][]byte{common.GetByteInt64(eHeight)}
	nb := n.GetBytes()
	return nb
}

func generateSyncMsgSendHeaders(bHeight int64, height int64) []byte {
	if height < 0 {
		logger.GetLogger().Println("height cannot be smaller than 0")
		return []byte{}
	}
	h := common.GetHeight()
	if height > h {
		logger.GetLogger().Println("Warning: height cannot be larger than last height")
		height = h
	}
	if bHeight < 0 || bHeight > height {
		logger.GetLogger().Println("starting height cannot be smaller than 0")
		return []byte{}
	}
	bm := message.BaseMessage{
		Head:    []byte("sh"),
		ChainID: common.GetChainID(),
	}
	n := message.TransactionsMessage{
		BaseMessage:       bm,
		TransactionsBytes: map[[2]byte][][]byte{},
	}
	indices := [][]byte{}
	blcks := [][]byte{}
	for i := bHeight; i <= height; i++ {
		indices = append(indices, common.GetByteInt64(i))
		block, err := blocks.LoadBlock(i)
		if err != nil {
			logger.GetLogger().Printf("generateSyncMsgSendHeaders: failed to load block %d: %v", i, err)
			return []byte{}
		}
		blcks = append(blcks, block.GetBytes())
	}
	n.TransactionsBytes[[2]byte{'I', 'H'}] = indices
	n.TransactionsBytes[[2]byte{'H', 'V'}] = blcks
	nb := n.GetBytes()
	return nb
}

func SendHeaders(addr [4]byte, bHeight int64, height int64) {
	n := generateSyncMsgSendHeaders(bHeight, height)
	if len(n) == 0 {
		return
	}
	if !Send(addr, n) {
		logger.GetLogger().Printf("SendHeaders: could not send to %v", addr)
	}
}

func SendGetHeaders(addr [4]byte, height int64) {
	n := generateSyncMsgGetHeaders(height)
	if len(n) == 0 {
		return
	}
	if !Send(addr, n) {
		logger.GetLogger().Println("could not send get headers")
	}
}

func Send(addr [4]byte, nb []byte) bool {
	nb = append(addr[:], nb...)
	if services.SendMutexSync.TryLock() {
		defer services.SendMutexSync.Unlock()
		select {
		case services.SendChanSync <- nb:
			return true
		default:
			return false
		}
	}
	return false
}

func sendSyncMsgInLoop() {
	for {
		if len(tcpip.GetPeersConnected(tcpip.SyncTopic)) == 0 {
			time.Sleep(3 * time.Second)
			continue
		}
		n := generateSyncMsgHeight()
		if !Send([4]byte{0, 0, 0, 0}, n) {
			logger.GetLogger().Println("could not send 'hi' message")
		}
		time.Sleep(time.Second)
	}
}

func startPublishingSyncMsg() {

	go tcpip.StartNewListener(tcpip.SyncTopic)
	go tcpip.LoopSend(services.SendChanSync, tcpip.SyncTopic)
}

func StartSubscribingSyncMsg(ip [4]byte) {

	recvChan := make(chan []byte, 100) // Use a buffered channel
	quit := false
	var ipr [4]byte
	go tcpip.StartNewConnection(ip, recvChan, tcpip.SyncTopic)
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
			services.QUIT.Store(true)
		default:
			// Optional: Add a small sleep to prevent busy-waiting
			time.Sleep(time.Millisecond)
		}
	}
}
