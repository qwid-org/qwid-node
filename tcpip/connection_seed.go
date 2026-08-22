package tcpip

import "net"

// SeedConnectionForTest registers conn as the tracked connection for
// (topic, ip), exactly as accepting a real peer connection would populate
// tcpConnections and peersConnected.
//
// It exists purely so tests in OTHER packages can exercise
// DropTopicConnection / RecycleTopicConnection end-to-end - in particular
// services/syncService, whose "hi" handler drives the sync connection
// lifecycle through these two functions and needs to prove which one runs.
// A Go _test.go file is invisible to importing packages (unlike within a
// single package's own tests, an export_test.go seam does not cross a
// package boundary), so the existing tcpip-internal test helpers
// (resetConnectionLifecycleTestState and friends) cannot be reused from
// there directly; this small, clearly-named export is the alternative to
// reaching into tcpConnections directly, which is unexported.
//
// Not called from any production code path.
func SeedConnectionForTest(topic [2]byte, ip [4]byte, conn net.Conn) {
	var topicipBytes [6]byte
	copy(topicipBytes[:2], topic[:])
	copy(topicipBytes[2:], ip[:])

	PeersMutex.Lock()
	defer PeersMutex.Unlock()
	if _, ok := tcpConnections[topic]; !ok {
		tcpConnections[topic] = make(map[[4]byte]net.Conn)
	}
	tcpConnections[topic][ip] = conn
	peersConnected[topicipBytes] = topic
}
