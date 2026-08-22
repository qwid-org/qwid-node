package syncServices

import (
	"bytes"
	"math/rand"
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

// syncProgress tracks how long the local height has stood still, so a sync that
// is waiting on data that will never arrive can be detected. Only ever touched
// by checkSyncStall, which runs on the single sendSyncMsgInLoop goroutine.
type syncProgress struct {
	height int64
	since  time.Time
}

var progress = syncProgress{height: -1}

// checkSyncStall gives back a couple of blocks when the node has been syncing
// without advancing for SyncStallTimeout.
//
// The sync protocol has no retry of its own: a node that asked a peer for a
// block's transactions ("bt") and never got the answer ("bx") — because the
// connection dropped in between — keeps re-checking the same incomplete block
// forever. Rewinding makes the next batch from the peer overlap blocks we
// already hold, which re-runs the missing-transaction census in the "sh"
// handler and re-sends the request. The same recovery covers a batch that
// stalled on blocks rather than transactions.
// rewindLockWait bounds how long the stall watchdog waits for the block lock.
const rewindLockWait = 2 * time.Second

// lockBlocksForRewind takes common.BlockMutex for the stall rewind if it becomes
// free within rewindLockWait. Bounded, so the sync send loop this runs on is
// never parked behind a long batch.
func lockBlocksForRewind() bool {
	deadline := time.Now().Add(rewindLockWait)
	for {
		if common.BlockMutex.TryLock() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// stallRewindUseful reports whether rewinding could achieve anything from
// height, along with the number of live peer claims behind that answer.
//
// A rewind is only ever a way to make a peer re-send a batch. With nobody above
// us to ask, giving blocks back achieves nothing and costs SyncStallRewind
// blocks every SyncStallTimeout — a node left alone on the network (or one whose
// only "peer" is its own self-connection echoing our pre-rewind height) would
// walk its chain backwards for as long as it runs.
func stallRewindUseful(height int64) (useful bool, live int) {
	ahead, live := peersAhead(height)
	return len(ahead) > 0, live
}

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

	if canRewind, live := stallRewindUseful(h); !canRewind {
		// syncPeers counts real peers only, so the log separates "nobody is
		// connected on the sync topic" from "connected, but their 'hi' is not
		// arriving" - the two need different fixes.
		logger.GetLogger().Printf("sync stalled at height %d for %s, but no live peer is ahead of us "+
			"(livePeerClaims=%d syncPeers=%d) - not rewinding, waiting for a peer that can serve the batch",
			h, now.Sub(progress.since).Truncate(time.Second), live, tcpip.CountPeersOnTopic(tcpip.SyncTopic))
		// Pace this message by SyncStallTimeout rather than repeating it every second.
		progress.since = now
		return
	}

	// Rewind under the same lock the "sh" handler holds, so we never pull blocks
	// out from under a batch that is mid-apply. A held lock also means a batch is
	// actively running, which is not a stall — skip this round.
	if !syncProcessMutex.TryLock() {
		return
	}
	defer syncProcessMutex.Unlock()

	// syncProcessMutex alone is not enough: the nonce service applies live blocks
	// under common.BlockMutex without ever taking it. Rewinding the account state
	// from under such an application makes it store the rewound state under the
	// block's own height — balances then permanently disagree with the block fee
	// ledger and every following block is rejected on the supply invariant. A
	// held block lock also means a block is being applied, i.e. not a stall.
	//
	// Give it a moment rather than one TryLock: this is the only mechanism that
	// unsticks a stalled sync, so it must not be starved by a lock that happens
	// to be busy every time it looks. A skipped round is logged — silently doing
	// nothing here is indistinguishable from a node that has simply given up.
	if !lockBlocksForRewind() {
		logger.GetLogger().Printf("sync stalled at height %d for %s, but a block is being applied - "+
			"postponing the rewind to the next round", h, now.Sub(progress.since).Truncate(time.Second))
		return
	}
	defer common.BlockMutex.Unlock()

	target := h - SyncStallRewind
	if target < 0 {
		target = 0
	}
	logger.GetLogger().Printf("sync stalled at height %d for %s - rewinding to %d to re-request the batch",
		h, now.Sub(progress.since).Truncate(time.Second), target)
	services.ResetAccountsAndBlocksSyncLocked(target)

	// Push the request out ourselves rather than waiting for a peer's next 'hi'.
	// The rewind alone changes nothing if those messages are not reaching us.
	newHeight := common.GetHeight()
	sent, live := requestHeadersFromPeersAhead(newHeight)
	logger.GetLogger().Printf("sync stall recovery: height=%d target=%d syncing=%v livePeerClaims=%d headerRequestsSent=%d",
		newHeight, common.GetSyncTarget(), common.IsSyncing.Load(), live, sent)
	if live == 0 {
		logger.GetLogger().Println("sync stall recovery: no live peer height claims - " +
			"peers' 'hi' messages are not reaching us, so no batch can ever be requested")
	} else if sent == 0 {
		logger.GetLogger().Printf("sync stall recovery: %d live peer claim(s), none above our height %d - "+
			"the peers we can see are not ahead of us", live, newHeight)
	}

	// Restart the clock even if the rewind landed somewhere else than asked, so
	// a chain of rewinds is paced by SyncStallTimeout rather than firing every
	// second.
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
