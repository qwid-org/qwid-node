package tcpip

import (
	"net"
	"testing"
)

// TestCloseAndRemovePeerTopicRemovesBothStreams is the regression test for the
// quiet-death cleanup: when a peer goes silent, BOTH the registered send stream
// (possibly an accepted connection) and the accepted-connection registry entry
// must be dropped, so a fresh dial does not adopt the stale accepted stream as
// its send path and keep sending into the void.
func TestCloseAndRemovePeerTopicRemovesBothStreams(t *testing.T) {
	topic := TransactionTopic
	ip := [4]byte{10, 20, 30, 41}
	resetConnectionLifecycleTestState(topic, ip)
	t.Cleanup(func() { resetConnectionLifecycleTestState(topic, ip) })

	outbound, outboundPeer := net.Pipe()
	accepted, acceptedPeer := net.Pipe()
	defer outboundPeer.Close()
	defer acceptedPeer.Close()
	defer outbound.Close()

	PeersMutex.Lock()
	if _, ok := tcpConnections[topic]; !ok {
		tcpConnections[topic] = make(map[[4]byte]net.Conn)
	}
	tcpConnections[topic][ip] = outbound
	PeersMutex.Unlock()
	publishAcceptedConn(topic, ip, accepted)

	deleted := closeAndRemovePeerTopic(topic, ip)
	if len(deleted) == 0 {
		t.Fatal("expected the registered connection to be reported as deleted")
	}

	PeersMutex.RLock()
	_, sendEntry := tcpConnections[topic][ip]
	_, acceptedEntry := acceptedConnections[topic][ip]
	PeersMutex.RUnlock()
	if sendEntry {
		t.Fatal("send stream must be removed from tcpConnections")
	}
	if acceptedEntry {
		t.Fatal("accepted stream must be removed from acceptedConnections")
	}

	// The accepted stream must actually be closed, not merely unregistered.
	buf := make([]byte, 1)
	if _, err := acceptedPeer.Read(buf); err == nil {
		t.Fatal("accepted stream should be closed after quiet-death cleanup")
	}
}
