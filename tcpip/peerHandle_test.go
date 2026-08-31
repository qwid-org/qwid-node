package tcpip

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// Two distinct nodeIDs arriving from the SAME transport IP must get two
// distinct, stable handles — that separation is the whole point: two nodes
// behind one NAT used to collapse into a single peer and evict each other.
func TestHandlesSeparateNodesBehindOneIP(t *testing.T) {
	sharedIP := [4]byte{85, 1, 2, 3}
	idA, _ := common.BytesToAddress(bytes.Repeat([]byte{0xAA}, common.AddressLength))
	idB, _ := common.BytesToAddress(bytes.Repeat([]byte{0xBB}, common.AddressLength))

	hA := HandleForPeer(idA, sharedIP)
	hB := HandleForPeer(idB, sharedIP)
	if hA == hB {
		t.Fatal("two different nodeIDs behind one IP must get different handles")
	}
	if !IsPeerHandle(hA) || !IsPeerHandle(hB) {
		t.Fatal("handles must come from the 10.254/16 range")
	}
	if got := HandleForPeer(idA, sharedIP); got != hA {
		t.Fatal("a handle must be stable across reconnects of the same nodeID")
	}
	// Both handles resolve to the shared transport address for dial/ban/limits.
	if real, ok := RealIPForHandle(hA); !ok || real != sharedIP {
		t.Fatalf("RealIPForHandle(hA) = %v, %v; want %v", real, ok, sharedIP)
	}
	if canonicalIP(hB) != sharedIP {
		t.Fatal("canonicalIP must map a handle to its transport IP")
	}
	// A plain transport IP passes through untouched.
	if canonicalIP(sharedIP) != sharedIP {
		t.Fatal("canonicalIP must leave a transport IP unchanged")
	}
	if IsSelfIP(hA) {
		t.Fatal("a peer handle must never be classified as self")
	}
}

// The frame assembler must reproduce the receive-loop framing: reassemble
// fragments, strip the init marker, and flag violations.
func TestFrameAssembler(t *testing.T) {
	topic := TransactionTopic
	payload := []byte("hello-payload")
	wire := append(append(append([]byte{}, common.MessageInitialization[:]...), payload...), []byte("<-END->")...)

	// Whole frame in one chunk.
	fa := frameAssembler{topic: topic}
	msgs, viol := fa.push(wire)
	if viol || len(msgs) != 1 {
		t.Fatalf("single-chunk frame: msgs=%d viol=%v", len(msgs), viol)
	}
	if !bytes.HasPrefix(msgs[0], payload) {
		t.Fatal("payload must start right after the init marker")
	}

	// Split across two chunks.
	fa = frameAssembler{topic: topic}
	if msgs, viol = fa.push(wire[:5]); viol || len(msgs) != 0 {
		t.Fatalf("fragment must not complete a frame: msgs=%d viol=%v", len(msgs), viol)
	}
	msgs, viol = fa.push(wire[5:])
	if viol || len(msgs) != 1 || !bytes.HasPrefix(msgs[0], payload) {
		t.Fatalf("reassembled frame: msgs=%d viol=%v", len(msgs), viol)
	}

	// Wrong initialization marker is a violation.
	fa = frameAssembler{topic: topic}
	bad := append([]byte{9, 9, 9, 9}, wire[4:]...)
	if _, viol = fa.push(bad); !viol {
		t.Fatal("bad init marker must be flagged as a violation")
	}
}
