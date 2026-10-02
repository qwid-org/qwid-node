package syncServices

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/message"
)

// S2-04: one 'hi' must not start a dial lifecycle per advertised address -
// a peer only ever shares MaxPeersSharedInHi of them, so more is abuse.
func TestHiDialsAtMostMaxPeersSharedInHi(t *testing.T) {
	withTempDB(t)
	blocks.InitStateDB()
	storeTestChain(t, 2)
	withMyIP(t, [4]byte{10, 0, 0, 7})
	withGenesisHash(t, bytes.Repeat([]byte{0x11}, 32))
	pp := [][]byte{}
	for i := 0; i < 300; i++ {
		pp = append(pp, []byte{240, 201, byte(i >> 8), byte(i)}) // reserved, unroutable
	}
	pp = append(pp, []byte{240, 201}) // malformed: not 4 bytes
	m := message.TransactionsMessage{
		BaseMessage:       message.BaseMessage{Head: []byte("hi"), ChainID: common.GetChainID()},
		TransactionsBytes: map[[2]byte][][]byte{},
	}
	m.TransactionsBytes[[2]byte{'L', 'H'}] = [][]byte{common.GetByteInt64(1)}
	m.TransactionsBytes[[2]byte{'L', 'B'}] = [][]byte{bytes.Repeat([]byte{0x33}, 32)}
	m.TransactionsBytes[[2]byte{'G', 'B'}] = [][]byte{bytes.Repeat([]byte{0x11}, 32)}
	m.TransactionsBytes[[2]byte{'P', 'P'}] = pp

	withClaims(t, map[[4]byte]peerHeightClaim{}, func() {
		OnMessage([4]byte{203, 0, 113, 70}, m.GetBytes())
	})

	connectingPeersMutex.Lock()
	addrs := map[[4]byte]bool{}
	for k := range connectingPeers {
		if k[2] == 240 && k[3] == 201 {
			addrs[[4]byte{k[2], k[3], k[4], k[5]}] = true
		}
	}
	connectingPeersMutex.Unlock()
	if len(addrs) > common.MaxPeersSharedInHi {
		t.Fatalf("one hi started dialling %d addresses, want at most %d", len(addrs), common.MaxPeersSharedInHi)
	}
}
