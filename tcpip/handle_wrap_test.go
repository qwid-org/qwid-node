package tcpip

import (
	"encoding/binary"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

func resetHandles(t *testing.T) {
	t.Helper()
	handleMutex.Lock()
	handleByNodeID = map[[common.AddressLength]byte][4]byte{}
	realIPByHandle = map[[4]byte][4]byte{}
	nodeIDByHandle = map[[4]byte]common.Address{}
	handleLastUse = map[[4]byte]int64{}
	handlesByIP = map[[4]byte]map[[4]byte]struct{}{}
	nextHandle = 1
	handleMutex.Unlock()
}

func nodeIDn(n uint32) common.Address {
	b := make([]byte, common.AddressLength)
	binary.BigEndian.PutUint32(b[16:], n)
	b[0] = 0xEE
	a, _ := common.BytesToAddress(b)
	return a
}

// Every live handle belongs to exactly one nodeID.
func checkHandleInvariant(t *testing.T) {
	t.Helper()
	handleMutex.Lock()
	defer handleMutex.Unlock()
	for h, id := range nodeIDByHandle {
		var k [common.AddressLength]byte
		copy(k[:], id.GetBytes())
		if handleByNodeID[k] != h {
			t.Fatalf("handle %v is shared: nodeID %x maps to %v", h, id.GetBytes()[:4], handleByNodeID[k])
		}
	}
	if len(handleByNodeID) != len(nodeIDByHandle) {
		t.Fatalf("maps diverged: %d nodeIDs, %d handles", len(handleByNodeID), len(nodeIDByHandle))
	}
}

// S1-06: cheap nodeIDs from one address can neither wrap the counter onto an
// honest peer's handle nor grow the maps without bound.
func TestHandlesNeverCollideUnderNodeIDFlood(t *testing.T) {
	resetHandles(t)
	defer resetHandles(t)
	honestIP, attackerIP := [4]byte{198, 51, 100, 1}, [4]byte{203, 0, 113, 66}
	honest := HandleForPeer(nodeIDn(0), honestIP)
	for i := uint32(1); i <= 70_000; i++ {
		HandleForPeer(nodeIDn(i), attackerIP)
	}
	if real, _ := RealIPForHandle(honest); real != honestIP {
		t.Fatalf("honest handle now resolves to %v", real)
	}
	if got := HandleForPeer(nodeIDn(0), honestIP); got != honest {
		t.Fatal("honest peer lost its handle")
	}
	handleMutex.Lock()
	n := len(handlesByIP[attackerIP])
	handleMutex.Unlock()
	if n > maxHandlesPerIP {
		t.Fatalf("one address holds %d handles, cap %d", n, maxHandlesPerIP)
	}
	checkHandleInvariant(t)
}

// Even when the whole space is used up (many addresses), a handle is evicted
// before reuse, never shared.
func TestHandleSpaceExhaustionEvictsInsteadOfSharing(t *testing.T) {
	resetHandles(t)
	defer resetHandles(t)
	saved := handleSpace
	handleSpace = 8
	defer func() { handleSpace = saved }()
	for i := uint32(0); i < 50; i++ {
		HandleForPeer(nodeIDn(i), [4]byte{192, 0, 2, byte(i)})
		checkHandleInvariant(t)
	}
	handleMutex.Lock()
	n := len(nodeIDByHandle)
	handleMutex.Unlock()
	if n > 8 {
		t.Fatalf("%d live handles in a space of 8", n)
	}
}
