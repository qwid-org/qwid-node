package tcpip

import (
	"net"
	"testing"
	"time"
)

// TestDropTopicConnectionDoesNotAskForRedial: rejecting a peer must not queue a
// reconnection. RecycleTopicConnection deliberately does, which is why it cannot
// be used to turn a peer away - the peer would come straight back.
func TestDropTopicConnectionDoesNotAskForRedial(t *testing.T) {
	saved := ChanPeer
	ChanPeer = make(chan []byte, 10)
	t.Cleanup(func() { ChanPeer = saved })

	DropTopicConnection(SyncTopic, [4]byte{203, 0, 113, 5})

	select {
	case msg := <-ChanPeer:
		t.Fatalf("DropTopicConnection queued a reconnection for %v", msg)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestDropTopicConnectionClosesAndUnregisters: DropTopicConnection's contract is
// "closes and unregisters", not just "stays quiet" - a connection actually
// registered for (topic, ip) must be closed and removed from tcpConnections. A
// stub that only logs and never calls closeAndRemovePeerTopic would leave the
// entry in place and the pipe writable, so this fails against that stub.
func TestDropTopicConnectionClosesAndUnregisters(t *testing.T) {
	topic := SyncTopic
	ip := [4]byte{203, 0, 113, 8}
	resetConnectionLifecycleTestState(topic, ip)
	t.Cleanup(func() { resetConnectionLifecycleTestState(topic, ip) })

	conn, peerConn := net.Pipe()
	defer peerConn.Close()

	PeersMutex.Lock()
	tcpConnections[topic][ip] = conn
	PeersMutex.Unlock()

	saved := ChanPeer
	ChanPeer = make(chan []byte, 10)
	t.Cleanup(func() { ChanPeer = saved })

	DropTopicConnection(topic, ip)

	PeersMutex.RLock()
	_, stillRegistered := tcpConnections[topic][ip]
	PeersMutex.RUnlock()
	if stillRegistered {
		t.Fatal("DropTopicConnection left the connection registered in tcpConnections")
	}

	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte{1}); err == nil {
		t.Fatal("DropTopicConnection did not close the underlying connection")
	}
}

// TestRecycleTopicConnectionStillAsksForRedial pins the behaviour we are
// deliberately not reusing, so a future edit cannot quietly make the two
// functions identical.
func TestRecycleTopicConnectionStillAsksForRedial(t *testing.T) {
	saved := ChanPeer
	ChanPeer = make(chan []byte, 10)
	t.Cleanup(func() { ChanPeer = saved })

	RecycleTopicConnection(SyncTopic, [4]byte{203, 0, 113, 6})

	select {
	case <-ChanPeer:
	case <-time.After(50 * time.Millisecond):
		t.Fatal("RecycleTopicConnection no longer asks discovery to reconnect")
	}
}
