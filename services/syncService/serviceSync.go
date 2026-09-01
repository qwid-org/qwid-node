package syncServices

import (
	"bytes"
	"math/rand"
	"sync"
	"time"

	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/message"
	"github.com/qwid-org/qwid-node/services"
	"github.com/qwid-org/qwid-node/tcpip"
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

// localGenesisHash is the hash of this node's block 0, the fingerprint of the
// chain it belongs to. Read once at startup: it cannot change while the process
// lives, and re-reading it per message would put a database read on the path of
// every 'hi'.
//
// It is read from the database rather than derived from the genesis config,
// because genesis.CreateBlockFromGenesis stores public keys as a side effect and
// so cannot be used to merely compute what our genesis hash would be.
var localGenesisHash []byte

// initLocalGenesisHash loads block 0's hash. Safe at this point in startup:
// cmd/mining/main.go creates the genesis block before it starts this service.
func initLocalGenesisHash() {
	h, err := blocks.LoadHashOfBlock(0)
	if err != nil {
		logger.GetLogger().Fatalf("cannot read the genesis block hash, refusing to start the sync service: %v", err)
		return
	}
	localGenesisHash = h
	logger.GetLogger().Printf("genesis block hash: %x", h)
}

func InitSyncService() {
	initLocalGenesisHash()
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

	// GB names the chain we are on. ChainID (int16) only says "some QWID chain";
	// two networks started from different genesis configs share it.
	n.TransactionsBytes[[2]byte{'G', 'B'}] = [][]byte{localGenesisHash}

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

// headerRequestMinInterval bounds how often ONE peer is asked for headers.
//
// 'hi' messages pile up in the receive queue behind a multi-second batch apply
// (the queue keeps filling while syncProcessMutex is held), and each one used
// to trigger its own header request - ~90 requests fired in a single second.
// That salvo tripped the peer's per-IP message rate limiter, which reduced
// trust and banned this node, so its 'hi' stopped arriving, every claim
// expired, and sync died precisely after it had sped up. One request a second
// is plenty: applying the answered batch takes far longer than that anyway.
const headerRequestMinInterval = time.Second

var (
	lastHeaderRequest      = map[[4]byte]time.Time{}
	lastHeaderRequestMutex sync.Mutex
)

// allowHeaderRequest reports whether a header request to addr may go out now,
// and if so records it. Bounded by the peer set, so the map cannot grow.
func allowHeaderRequest(addr [4]byte) bool {
	lastHeaderRequestMutex.Lock()
	defer lastHeaderRequestMutex.Unlock()
	if t, ok := lastHeaderRequest[addr]; ok && time.Since(t) < headerRequestMinInterval {
		return false
	}
	lastHeaderRequest[addr] = time.Now()
	return true
}

func SendGetHeaders(addr [4]byte, height int64) {
	if !allowHeaderRequest(addr) {
		return
	}
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

// syncProgress tracks how long the local height has stood still, so a sync that
// is waiting on data that will never arrive can be detected. Only ever touched
// by checkSyncStall, which runs on the single sendSyncMsgInLoop goroutine.
type syncProgress struct {
	height int64
	since  time.Time
	// noClaimRounds counts consecutive stall rounds with a connected sync peer
	// but zero live height claims - the signature of a half-dead sync link.
	noClaimRounds int
}

var progress = syncProgress{height: -1}

// checkSyncStall unsticks a sync that has stopped advancing for
// SyncStallTimeout, WITHOUT giving blocks back.
//
// The sync protocol has no retry of its own: a node that asked a peer for a
// block's transactions ("bt") and never got the answer ("bx") keeps re-checking
// the same incomplete block forever. That used to be solved by rewinding two
// blocks so the peer's next batch would overlap and the request be re-issued.
//
// Rewinding is gone. It treated a lost message by destroying confirmed local
// state, and it could not tell that case apart from the several others that
// look identical from here — a half-dead link, a peer that is simply behind,
// a claim that never arrived. When it guessed wrong it walked the chain
// backwards, and every rewind reopened a window for the accounting and supply
// invariants that the fork-resolution path already handles properly.
//
// What replaced it costs nothing if it guesses wrong: ask the peers directly
// for the next bucket of headers, and tear down a sync link that has gone
// quiet. A peer that is behind ignores the request; an ahead peer answers, and
// the answer both advances the chain and re-runs the missing-transaction
// census that the rewind was trying to trigger by force.

func checkSyncStall(now time.Time) {
	h := common.GetHeight()

	if h != progress.height {
		progress.height = h
		progress.since = now
		return
	}
	if !common.IsSyncing.Load() {
		// Standing still while caught up is the normal state, not a stall.
		progress.since = now
		return
	}
	if progress.since.IsZero() {
		progress.since = now
		return
	}
	if now.Sub(progress.since) < SyncStallTimeout {
		return
	}

	// syncPeers counts real peers only, so the log separates "nobody is
	// connected on the sync topic" from "connected, but their 'hi' is not
	// arriving" - the two need different fixes.
	_, live := peersAhead(h)
	syncPeers := tcpip.CountPeersOnTopic(tcpip.SyncTopic)
	logger.GetLogger().Printf("sync stalled at height %d for %s (livePeerClaims=%d syncPeers=%d)",
		h, now.Sub(progress.since).Truncate(time.Second), live, syncPeers)

	// A sync peer that is connected yet delivers no 'hi' for two full stall
	// rounds (and answers no blind header request either) is a half-dead
	// link - typically the peer's send side still points at a stream from
	// before our restart, which no timeout on our side can detect. Tear the
	// sync-topic connection down and re-dial, exactly as the missing-tx
	// path recycles the transaction topic.
	if live == 0 && syncPeers > 0 {
		progress.noClaimRounds++
		if progress.noClaimRounds >= 2 {
			progress.noClaimRounds = 0
			for topicip := range tcpip.GetPeersConnected(tcpip.SyncTopic) {
				var ip [4]byte
				copy(ip[:], topicip[2:])
				if tcpip.IsSelfIP(ip) {
					continue
				}
				logger.GetLogger().Printf("no 'hi' from %v for two stall rounds - recycling the sync-topic connection", ip)
				tcpip.RecycleTopicConnection(tcpip.SyncTopic, ip)
			}
		}
	} else {
		progress.noClaimRounds = 0
	}

	// Ask blindly rather than waiting for a claim that may never come. This is
	// sent to every sync peer, not only the ones known to be ahead: a peer
	// whose 'hi' is not reaching us has no recorded height, and it is exactly
	// the peer most likely to be the one holding up the sync.
	if syncPeers > 0 {
		sent := 0
		for topicip := range tcpip.GetPeersConnected(tcpip.SyncTopic) {
			var ip [4]byte
			copy(ip[:], topicip[2:])
			if tcpip.IsSelfIP(ip) {
				continue
			}
			SendGetHeaders(ip, h+common.NumberOfHashesInBucket)
			sent++
		}
		logger.GetLogger().Printf("sync stall recovery: blind header request up to height %d sent to %d sync peer(s)",
			h+common.NumberOfHashesInBucket, sent)
	} else {
		logger.GetLogger().Println("sync stall recovery: no sync peer is connected, so no batch can be requested")
	}

	// Pace this by SyncStallTimeout rather than repeating it every second.
	progress.height = common.GetHeight()
	progress.since = now
}

func sendSyncMsgInLoop() {
	for {
		if len(tcpip.GetPeersConnected(tcpip.SyncTopic)) == 0 {
			time.Sleep(3 * time.Second)
			continue
		}
		checkSyncStall(time.Now())
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
		}
	}
}
