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

// The frame assembler must find delimiters INSIDE the buffer: multiple
// back-to-back frames in one chunk, frames split across chunks, and a
// delimiter split across chunk boundaries must all survive.
func TestFrameAssembler(t *testing.T) {
	topic := TransactionTopic
	mk := func(payload string) []byte {
		return append(append(append([]byte{}, common.MessageInitialization[:]...), []byte(payload)...), frameEnd...)
	}

	// Two glued frames in a single chunk - the case the old framing lost.
	fa := frameAssembler{topic: topic}
	msgs, viol := fa.push(append(mk("alpha"), mk("beta")...))
	if viol || len(msgs) != 2 || string(msgs[0]) != "alpha" || string(msgs[1]) != "beta" {
		t.Fatalf("glued frames: msgs=%q viol=%v", msgs, viol)
	}

	// One frame split across three chunks, with the delimiter itself split.
	fa = frameAssembler{topic: topic}
	wire := mk("gamma-payload")
	if msgs, viol = fa.push(wire[:5]); viol || len(msgs) != 0 {
		t.Fatalf("fragment 1: msgs=%d viol=%v", len(msgs), viol)
	}
	if msgs, viol = fa.push(wire[5 : len(wire)-3]); viol || len(msgs) != 0 {
		t.Fatalf("fragment 2 (split delimiter): msgs=%d viol=%v", len(msgs), viol)
	}
	msgs, viol = fa.push(wire[len(wire)-3:])
	if viol || len(msgs) != 1 || string(msgs[0]) != "gamma-payload" {
		t.Fatalf("reassembled: msgs=%q viol=%v", msgs, viol)
	}

	// Wrong initialization marker is a violation; the NEXT frame still parses.
	fa = frameAssembler{topic: topic}
	bad := append(append([]byte{9, 9, 9, 9}, []byte("junk")...), frameEnd...)
	msgs, viol = fa.push(append(bad, mk("delta")...))
	if !viol {
		t.Fatal("bad init marker must be flagged as a violation")
	}
	if len(msgs) != 1 || string(msgs[0]) != "delta" {
		t.Fatalf("frame after violation must survive: msgs=%q", msgs)
	}
}
