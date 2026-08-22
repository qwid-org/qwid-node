package syncServices

import (
	"bytes"
	"path/filepath"
	"testing"

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

// TestHiWithOurGenesisRecordsHeightClaim is the positive control for the two
// negative tests below. Those only assert that a height claim was NOT
// recorded, which also passes if the genesis check does not exist at all -
// any early return in the "hi" handler produces the same "no claim" state.
// This test proves the opposite path still works: a 'hi' that DOES carry our
// own genesis hash must still have its height claim recorded, which is what
// makes the negative tests meaningful evidence of a check that runs and
// discriminates, not just a handler that stopped recording claims entirely.
func TestHiWithOurGenesisRecordsHeightClaim(t *testing.T) {
	withMyIP(t, [4]byte{10, 0, 0, 7})
	withGenesisHash(t, bytes.Repeat([]byte{0x11}, 32))

	peer := [4]byte{203, 0, 113, 20}
	bm := message.BaseMessage{Head: []byte("hi"), ChainID: common.GetChainID()}
	n := message.TransactionsMessage{
		BaseMessage:       bm,
		TransactionsBytes: map[[2]byte][][]byte{},
	}
	n.TransactionsBytes[[2]byte{'L', 'H'}] = [][]byte{common.GetByteInt64(999999)}
	n.TransactionsBytes[[2]byte{'L', 'B'}] = [][]byte{bytes.Repeat([]byte{0x33}, 32)}
	n.TransactionsBytes[[2]byte{'G', 'B'}] = [][]byte{bytes.Repeat([]byte{0x11}, 32)}

	withClaims(t, map[[4]byte]peerHeightClaim{}, func() {
		OnMessage(peer, n.GetBytes())

		peerHeightClaimsMutex.RLock()
		defer peerHeightClaimsMutex.RUnlock()
		claim, ok := peerHeightClaims[peer]
		if !ok {
			t.Fatal("a peer on our own genesis did not have its height claim recorded")
		}
		if claim.height != 999999 {
			t.Fatalf("recorded height = %d, expected 999999", claim.height)
		}
	})
}

// TestHiFromForeignGenesisRecordsNoHeightClaim is the one that matters. The
// damage a foreign-genesis peer does is not importing its blocks - it is
// inflating networkHeight() through its height claim, after which the stall
// watchdog rewinds our chain chasing a height nobody honest can serve. It
// also proves the second half of the same hole: the handler must not dial a
// peer advertised in the foreign peer's PP list either, or the foreign
// network gets seeded into our peer table even while its own height claim is
// rejected - asserting only one of the two leaves the other half of the hole
// open.
func TestHiFromForeignGenesisRecordsNoHeightClaim(t *testing.T) {
	withMyIP(t, [4]byte{10, 0, 0, 7})
	withGenesisHash(t, bytes.Repeat([]byte{0x11}, 32))

	peer := [4]byte{203, 0, 113, 9}
	ppAddr := []byte{203, 0, 113, 99}
	bm := message.BaseMessage{Head: []byte("hi"), ChainID: common.GetChainID()}
	n := message.TransactionsMessage{
		BaseMessage:       bm,
		TransactionsBytes: map[[2]byte][][]byte{},
	}
	n.TransactionsBytes[[2]byte{'L', 'H'}] = [][]byte{common.GetByteInt64(999999)}
	n.TransactionsBytes[[2]byte{'L', 'B'}] = [][]byte{bytes.Repeat([]byte{0x33}, 32)}
	n.TransactionsBytes[[2]byte{'G', 'B'}] = [][]byte{bytes.Repeat([]byte{0x22}, 32)}
	n.TransactionsBytes[[2]byte{'P', 'P'}] = [][]byte{ppAddr}

	// dialKey is the bookkeeping key the "hi" handler sets, synchronously and
	// BEFORE spawning the dial goroutine, the instant it decides to connect to
	// an address from PP. Checking it - rather than the eventual outcome of a
	// real network dial to a reserved, non-routable TEST-NET-3 address - is the
	// least fragile way to observe "was a dial attempted": it needs no network
	// mocking, and is set unconditionally on the synchronous path that runs
	// before any goroutine or socket I/O.
	var dialKey [6]byte
	copy(dialKey[:2], tcpip.NonceTopic[:])
	copy(dialKey[2:], ppAddr)

	connectingPeersMutex.Lock()
	delete(connectingPeers, dialKey)
	connectingPeersMutex.Unlock()
	t.Cleanup(func() {
		connectingPeersMutex.Lock()
		delete(connectingPeers, dialKey)
		connectingPeersMutex.Unlock()
	})

	withClaims(t, map[[4]byte]peerHeightClaim{}, func() {
		OnMessage(peer, n.GetBytes())

		peerHeightClaimsMutex.RLock()
		if _, ok := peerHeightClaims[peer]; ok {
			peerHeightClaimsMutex.RUnlock()
			t.Fatal("a peer on a different genesis had its height claim recorded")
		}
		peerHeightClaimsMutex.RUnlock()

		connectingPeersMutex.Lock()
		dialed := connectingPeers[dialKey]
		connectingPeersMutex.Unlock()
		if dialed {
			t.Fatal("a peer on a different genesis had a PP-advertised address dialled")
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
