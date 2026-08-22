package syncServices

import (
	"bytes"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/message"
	"github.com/qwid-org/qwid-node/tcpip"
)

// withTempDB points database.MainDB at a throwaway RocksDB so these tests never
// touch the operator's real blockchain database.
func withTempDB(t *testing.T) {
	t.Helper()
	db := &database.BlockchainDB{}
	pdb, err := db.InitPermanent(filepath.Join(t.TempDir(), "blockchain"))
	if err != nil {
		t.Skipf("RocksDB unavailable: %v", err)
	}
	saved := database.MainDB
	database.MainDB = pdb
	t.Cleanup(func() {
		pdb.Close()
		database.MainDB = saved
	})
}

// withGenesisHash pins the node's genesis hash for one test, so the check does
// not depend on whatever chain the suite's database happens to hold.
func withGenesisHash(t *testing.T, h []byte) {
	t.Helper()
	saved := localGenesisHash
	localGenesisHash = h
	t.Cleanup(func() { localGenesisHash = saved })
}

// ppAddrCounter backs freshPPAddr - see its doc comment.
var ppAddrCounter uint32

// freshPPAddr returns a PP-advertised address that is guaranteed distinct
// from every previous call in this test binary, including earlier
// repetitions of the same test under `go test -count=N`: connectingPeers and
// tcpip's own dial-dedup map (dialing, guarded by beginDial/endDial) are
// package-level state that persists across repetitions in the same process.
// Reusing a fixed address risks tcpip's "already active or pending" fast
// path on a second dial for the same (topic, ip): that path clears the
// connectingPeers flag from a background goroutine almost immediately,
// racing the test's synchronous read of it (observed directly: 5 probes of
// a fixed address gave true,true,true,FALSE,true). A never-before-dialled
// address instead takes the real dial/connect-refused/retry path, which is
// bounded below by several seconds of explicit retry backoff in
// tcpip.StartNewConnection - ample, non-flaky headroom for a check that
// happens in nanoseconds right after OnMessage returns.
func freshPPAddr(t *testing.T) []byte {
	t.Helper()
	n := atomic.AddUint32(&ppAddrCounter, 1)
	// Offset away from the low literal addresses (.9, .10, .20 and similar)
	// already hardcoded elsewhere in this file, and stay inside the
	// TEST-NET-3 block (RFC 5737) used throughout these tests.
	return []byte{203, 0, 113, byte(100 + n%150)}
}

// topicIPKey builds the [2]byte-topic + [4]byte-ip key used both by
// connectingPeers (the "hi" handler's own dial bookkeeping) and by
// tcpip.GetPeersConnected.
func topicIPKey(topic [2]byte, ip []byte) [6]byte {
	var key [6]byte
	copy(key[:2], topic[:])
	copy(key[2:], ip)
	return key
}

// ppDialKey is the connectingPeers bookkeeping key the "hi" handler sets
// synchronously, before spawning the dial goroutine, the instant it decides
// to connect to an address advertised in PP for the nonce topic.
func ppDialKey(ip []byte) [6]byte {
	return topicIPKey(tcpip.NonceTopic, ip)
}

func TestWithGenesisHashRestores(t *testing.T) {
	original := localGenesisHash

	t.Run("inner", func(t *testing.T) {
		withGenesisHash(t, []byte{1, 2, 3})
		if !bytes.Equal(localGenesisHash, []byte{1, 2, 3}) {
			t.Fatal("withGenesisHash did not set the hash")
		}
	})

	if !bytes.Equal(localGenesisHash, original) {
		t.Fatalf("withGenesisHash did not restore the hash: got %x, want %x", localGenesisHash, original)
	}
}

// TestGenerateSyncMsgHeightCarriesGenesis: a peer cannot check our chain against
// its own unless we say which chain we are on.
func TestGenerateSyncMsgHeightCarriesGenesis(t *testing.T) {
	withTempDB(t)

	want := bytes.Repeat([]byte{0xab}, 32)
	withGenesisHash(t, want)

	// Set up height and store a block hash so generateSyncMsgHeight can load it.
	height := int64(42)
	savedHeight := common.GetHeight()
	defer common.SetHeight(savedHeight)
	common.SetHeight(height)

	// Store the hash at the block-by-height key so LoadHashOfBlock can find it.
	blockHash := bytes.Repeat([]byte{0xcd}, 32)
	key := append(common.BlockByHeightDBPrefix[:], common.GetByteInt64(height)...)
	err := database.MainDB.Put(key, blockHash)
	if err != nil {
		t.Fatalf("failed to store block hash: %v", err)
	}

	raw := generateSyncMsgHeight()
	if len(raw) == 0 {
		t.Fatal("generateSyncMsgHeight produced empty bytes")
	}

	isValid, amsg := message.CheckValidMessage(raw)
	if !isValid {
		t.Fatal("generateSyncMsgHeight produced a message that does not validate")
	}
	txn := amsg.(message.TransactionsMessage).GetTransactionsBytes()

	got := txn[[2]byte{'G', 'B'}]
	if len(got) != 1 {
		t.Fatalf("GB entries = %d, expected 1", len(got))
	}
	if !bytes.Equal(got[0], want) {
		t.Fatalf("GB = %x, expected %x", got[0], want)
	}
}

func TestPeerGenesisAccepted(t *testing.T) {
	ours := bytes.Repeat([]byte{0x11}, 32)
	theirs := bytes.Repeat([]byte{0x22}, 32)
	withGenesisHash(t, ours)

	cases := []struct {
		name string
		txn  map[[2]byte][][]byte
		want bool
	}{
		{"same genesis", map[[2]byte][][]byte{{'G', 'B'}: {ours}}, true},
		{"different genesis", map[[2]byte][][]byte{{'G', 'B'}: {theirs}}, false},
		{"no GB tag at all", map[[2]byte][][]byte{}, false},
		{"empty GB list", map[[2]byte][][]byte{{'G', 'B'}: {}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := peerGenesisAccepted(tc.txn)
			if got != tc.want {
				t.Fatalf("peerGenesisAccepted = %v, expected %v (%s)", got, tc.want, reason)
			}
			if !got && reason == "" {
				t.Fatal("a rejection must carry a reason for the log")
			}
		})
	}
}

// TestHiWithOurGenesisRecordsHeightClaim is the positive control for the
// negative tests below. Those only assert that a height claim was NOT
// recorded and a PP-advertised address was NOT dialled, which also passes if
// the genesis check does not exist at all - any early return in the "hi"
// handler produces the same "nothing happened" state, and the PP-dial
// assertion in particular also passes vacuously whenever the PP block is
// skipped for any unrelated reason (peer cap reached, the address already
// connected, the address banned). This test proves the opposite path still
// works end to end: a 'hi' that DOES carry our own genesis hash must still
// have its height claim recorded AND must still dial an address it
// advertises in PP. Without this, the two negative tests below are evidence
// of nothing - they would pass identically against a handler that reached
// neither code path for reasons that have nothing to do with genesis.
func TestHiWithOurGenesisRecordsHeightClaim(t *testing.T) {
	withMyIP(t, [4]byte{10, 0, 0, 7})
	withGenesisHash(t, bytes.Repeat([]byte{0x11}, 32))

	peer := [4]byte{203, 0, 113, 20}
	ppAddr := freshPPAddr(t)
	dialKey := ppDialKey(ppAddr)

	bm := message.BaseMessage{Head: []byte("hi"), ChainID: common.GetChainID()}
	n := message.TransactionsMessage{
		BaseMessage:       bm,
		TransactionsBytes: map[[2]byte][][]byte{},
	}
	n.TransactionsBytes[[2]byte{'L', 'H'}] = [][]byte{common.GetByteInt64(999999)}
	n.TransactionsBytes[[2]byte{'L', 'B'}] = [][]byte{bytes.Repeat([]byte{0x33}, 32)}
	n.TransactionsBytes[[2]byte{'G', 'B'}] = [][]byte{bytes.Repeat([]byte{0x11}, 32)}
	n.TransactionsBytes[[2]byte{'P', 'P'}] = [][]byte{ppAddr}

	t.Cleanup(func() {
		connectingPeersMutex.Lock()
		delete(connectingPeers, dialKey)
		connectingPeersMutex.Unlock()
	})

	withClaims(t, map[[4]byte]peerHeightClaim{}, func() {
		OnMessage(peer, n.GetBytes())

		peerHeightClaimsMutex.RLock()
		claim, ok := peerHeightClaims[peer]
		peerHeightClaimsMutex.RUnlock()
		if !ok {
			t.Fatal("a peer on our own genesis did not have its height claim recorded")
		}
		if claim.height != 999999 {
			t.Fatalf("recorded height = %d, expected 999999", claim.height)
		}

		connectingPeersMutex.Lock()
		dialed := connectingPeers[dialKey]
		connectingPeersMutex.Unlock()
		if !dialed {
			t.Fatal("a peer on our own genesis did not have its PP-advertised address dialled")
		}
	})
}

// TestHiFromForeignGenesisRejectsPeerEntirely is the one that matters. The
// damage a foreign-genesis peer does is not importing its blocks - it is
// inflating networkHeight() through its height claim, after which the stall
// watchdog rewinds our chain chasing a height nobody honest can serve. This
// test proves the full rejection, not just one symptom of it:
//
//  1. no height claim recorded for the peer;
//  2. no dial attempted for an address the peer advertised in PP - or the
//     foreign network gets seeded into our peer table even while its own
//     height claim is rejected;
//  3. the existing sync connection to the peer is actually closed and
//     unregistered (DropTopicConnection ran, not a no-op);
//  4. no reconnection was queued for it - the distinguishing behaviour
//     between DropTopicConnection and RecycleTopicConnection. Points 3 and 4
//     together are what catch a future refactor that swaps back to
//     RecycleTopicConnection: 3 alone would not, since both functions close
//     and unregister the connection identically - only the absence of a
//     requeued reconnect (4) proves Drop, not Recycle, ran;
//  5. the peer is not added to any ban list - genesis mismatch is a refusal
//     to sync, not misbehaviour serious enough to ban for.
func TestHiFromForeignGenesisRejectsPeerEntirely(t *testing.T) {
	withMyIP(t, [4]byte{10, 0, 0, 7})
	withGenesisHash(t, bytes.Repeat([]byte{0x11}, 32))

	peer := [4]byte{203, 0, 113, 9}
	ppAddr := freshPPAddr(t)
	dialKey := ppDialKey(ppAddr)

	// Seed an existing sync connection for the peer, as if a "hi" handshake
	// had already brought one up earlier, so the test can prove
	// DropTopicConnection actually tears it down rather than merely reading
	// as a no-op that happens to leave no height claim behind either way.
	conn, peerConn := net.Pipe()
	t.Cleanup(func() { peerConn.Close() })
	tcpip.SeedConnectionForTest(tcpip.SyncTopic, peer, conn)
	t.Cleanup(func() { tcpip.DropTopicConnection(tcpip.SyncTopic, peer) })

	// Swap in a fresh ChanPeer so a queued reconnection - which is exactly
	// what RecycleTopicConnection, and only RecycleTopicConnection, would
	// queue - is directly observable.
	savedChanPeer := tcpip.ChanPeer
	tcpip.ChanPeer = make(chan []byte, 10)
	t.Cleanup(func() { tcpip.ChanPeer = savedChanPeer })

	bm := message.BaseMessage{Head: []byte("hi"), ChainID: common.GetChainID()}
	n := message.TransactionsMessage{
		BaseMessage:       bm,
		TransactionsBytes: map[[2]byte][][]byte{},
	}
	n.TransactionsBytes[[2]byte{'L', 'H'}] = [][]byte{common.GetByteInt64(999999)}
	n.TransactionsBytes[[2]byte{'L', 'B'}] = [][]byte{bytes.Repeat([]byte{0x33}, 32)}
	n.TransactionsBytes[[2]byte{'G', 'B'}] = [][]byte{bytes.Repeat([]byte{0x22}, 32)}
	n.TransactionsBytes[[2]byte{'P', 'P'}] = [][]byte{ppAddr}

	t.Cleanup(func() {
		connectingPeersMutex.Lock()
		delete(connectingPeers, dialKey)
		connectingPeersMutex.Unlock()
	})

	withClaims(t, map[[4]byte]peerHeightClaim{}, func() {
		OnMessage(peer, n.GetBytes())

		// 1. no height claim recorded.
		peerHeightClaimsMutex.RLock()
		_, hasClaim := peerHeightClaims[peer]
		peerHeightClaimsMutex.RUnlock()
		if hasClaim {
			t.Fatal("a peer on a different genesis had its height claim recorded")
		}

		// 2. no dial attempted for its PP-advertised address. dialKey is set
		// synchronously, before any goroutine or socket I/O, by the same "hi"
		// handler code this test is otherwise exercising; ppAddr is unique to
		// this call (see freshPPAddr), so this can only be true here because
		// the PP block itself was never reached.
		connectingPeersMutex.Lock()
		dialed := connectingPeers[dialKey]
		connectingPeersMutex.Unlock()
		if dialed {
			t.Fatal("a peer on a different genesis had a PP-advertised address dialled")
		}

		// 3. the seeded connection is gone - closed and unregistered. Closing
		// one end of a net.Pipe makes deadline calls on the OTHER end fail too
		// (io.ErrClosedPipe), so - exactly as tcpip's own
		// TestDropTopicConnectionClosesAndUnregisters does - the deadline
		// error is ignored and only the registration and the write outcome
		// are asserted.
		if _, stillRegistered := tcpip.GetPeersConnected(tcpip.SyncTopic)[topicIPKey(tcpip.SyncTopic, peer[:])]; stillRegistered {
			t.Fatal("a peer on a different genesis kept its sync connection registered")
		}
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write([]byte{1}); err == nil {
			t.Fatal("a peer on a different genesis kept its sync connection open")
		}

		// 4. no reconnection queued - proves DropTopicConnection ran, not
		// RecycleTopicConnection.
		select {
		case msg := <-tcpip.ChanPeer:
			t.Fatalf("a peer on a different genesis had a reconnection queued for it: %v", msg)
		case <-time.After(50 * time.Millisecond):
		}

		// 5. not banned - a genesis mismatch is a refusal to sync, not
		// misbehaviour worth banning for.
		if tcpip.IsIPBanned(peer) {
			t.Fatal("a peer on a different genesis was banned; genesis mismatch should refuse sync, not ban")
		}
	})
}

// TestHiWithoutGenesisTagRecordsNoHeightClaim covers the older-version case:
// a peer that sends no GB is rejected exactly like a mismatch.
func TestHiWithoutGenesisTagRecordsNoHeightClaim(t *testing.T) {
	withMyIP(t, [4]byte{10, 0, 0, 7})
	withGenesisHash(t, bytes.Repeat([]byte{0x11}, 32))

	peer := [4]byte{203, 0, 113, 10}
	bm := message.BaseMessage{Head: []byte("hi"), ChainID: common.GetChainID()}
	n := message.TransactionsMessage{
		BaseMessage:       bm,
		TransactionsBytes: map[[2]byte][][]byte{},
	}
	n.TransactionsBytes[[2]byte{'L', 'H'}] = [][]byte{common.GetByteInt64(999999)}
	n.TransactionsBytes[[2]byte{'L', 'B'}] = [][]byte{bytes.Repeat([]byte{0x33}, 32)}

	withClaims(t, map[[4]byte]peerHeightClaim{}, func() {
		OnMessage(peer, n.GetBytes())

		peerHeightClaimsMutex.RLock()
		defer peerHeightClaimsMutex.RUnlock()
		if _, ok := peerHeightClaims[peer]; ok {
			t.Fatal("a peer that sent no genesis hash had its height claim recorded")
		}
	})
}
