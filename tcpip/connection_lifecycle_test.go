package tcpip

import (
	"errors"
	"net"
	"testing"
	"time"
)

func resetConnectionLifecycleTestState(topic [2]byte, ip [4]byte) {
	PeersMutex.Lock()
	if conn := tcpConnections[topic][ip]; conn != nil {
		_ = conn.Close()
	}
	delete(tcpConnections[topic], ip)
	delete(acceptedConnections[topic], ip)
	var key [6]byte
	copy(key[:2], topic[:])
	copy(key[2:], ip[:])
	delete(peersConnected, key)
	PeersMutex.Unlock()
	endDial(topic, ip)
}

func TestPublishAcceptedConnDoesNotCloseOutboundReceiveStream(t *testing.T) {
	topic := SyncTopic
	ip := [4]byte{10, 20, 30, 40}
	resetConnectionLifecycleTestState(topic, ip)
	t.Cleanup(func() { resetConnectionLifecycleTestState(topic, ip) })

	outbound, outboundPeer := net.Pipe()
	accepted, acceptedPeer := net.Pipe()
	defer outboundPeer.Close()
	defer acceptedPeer.Close()

	PeersMutex.Lock()
	tcpConnections[topic][ip] = outbound
	PeersMutex.Unlock()
	publishAcceptedConn(topic, ip, accepted)

	// The outbound side remains the subscriber's receive stream even though the
	// accepted side replaced it as the LoopSend target.
	assertPipeWorks(t, outbound, outboundPeer)
	PeersMutex.RLock()
	got := tcpConnections[topic][ip]
	PeersMutex.RUnlock()
	if got != accepted {
		t.Fatal("accepted connection must become the send target")
	}
}

func assertPipeWorks(t *testing.T, writer, reader net.Conn) {
	t.Helper()
	_ = writer.SetWriteDeadline(time.Now().Add(time.Second))
	_ = reader.SetReadDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := reader.Read(buf)
		done <- err
	}()
	if _, err := writer.Write([]byte{1}); err != nil {
		t.Fatalf("connection was unexpectedly closed: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("peer could not read: %v", err)
	}
}

func TestBeginDialDeduplicatesTopicAndIP(t *testing.T) {
	topic := SyncTopic
	ip := [4]byte{10, 20, 30, 41}
	endDial(topic, ip)
	if !beginDial(topic, ip) {
		t.Fatal("first dial should be admitted")
	}
	if beginDial(topic, ip) {
		t.Fatal("parallel duplicate dial should be rejected")
	}
	endDial(topic, ip)
	if !beginDial(topic, ip) {
		t.Fatal("dial should be admitted after previous lifecycle ends")
	}
	endDial(topic, ip)
}

func TestHandshakeViolationClassification(t *testing.T) {
	if isHandshakeProtocolViolation(errors.New("read: connection reset by peer")) {
		t.Fatal("transport reset must not be classified as protocol abuse")
	}
	if isHandshakeProtocolViolation(errors.New("EOF")) {
		t.Fatal("EOF must not be classified as protocol abuse")
	}
	if !isHandshakeProtocolViolation(errors.New("handshake: responder signature invalid")) {
		t.Fatal("invalid signature must be classified as protocol abuse")
	}
	if !isHandshakeProtocolViolation(errors.New("handshake: frame length 99999 exceeds max 1024")) {
		t.Fatal("oversized handshake frame must be classified as protocol abuse")
	}
}
