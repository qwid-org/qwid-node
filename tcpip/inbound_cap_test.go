package tcpip

import (
	"net"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

func TestInboundCapReached(t *testing.T) {
	topic := [2]byte{'Z', 'Z'} // a test-only topic, not a real one
	PeersMutex.Lock()
	tcpConnections[topic] = make(map[[4]byte]net.Conn)
	PeersMutex.Unlock()
	defer func() {
		PeersMutex.Lock()
		delete(tcpConnections, topic)
		PeersMutex.Unlock()
	}()

	if inboundCapReached(topic) {
		t.Fatal("empty topic must not be at cap")
	}

	// Fill to cap-1 distinct fake connections (nil net.Conn is fine — only the count matters).
	PeersMutex.Lock()
	for i := 0; i < common.MaxInboundConnectionsPerTopic-1; i++ {
		ip := [4]byte{byte(i / 256), byte(i % 256), 0, 0}
		tcpConnections[topic][ip] = nil
	}
	PeersMutex.Unlock()
	if inboundCapReached(topic) {
		t.Fatalf("cap-1 (%d) connections must not be at cap", common.MaxInboundConnectionsPerTopic-1)
	}

	// One more reaches the cap.
	PeersMutex.Lock()
	tcpConnections[topic][[4]byte{255, 255, 255, 255}] = nil
	PeersMutex.Unlock()
	if !inboundCapReached(topic) {
		t.Fatalf("%d connections must be at cap", common.MaxInboundConnectionsPerTopic)
	}
}
