package tcpip

import (
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
