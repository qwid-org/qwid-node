package tcpip

import (
	"net"
	"testing"
)

// withTestTopic installs an empty connection map for a topic that no real
// service uses, and removes it afterwards.
func withTestTopic(t *testing.T, topic [2]byte, conns map[[4]byte]net.Conn) {
	t.Helper()
	PeersMutex.Lock()
	tcpConnections[topic] = conns
	PeersMutex.Unlock()
	t.Cleanup(func() {
		PeersMutex.Lock()
		delete(tcpConnections, topic)
		PeersMutex.Unlock()
	})
}

// withTestMyIP pins MyIP/MyIPSelfNonce so "is this address ours" does not depend
// on the interfaces of the machine running the suite.
func withTestMyIP(t *testing.T, ip [4]byte) {
	t.Helper()
	savedIP, savedSelf := MyIP, MyIPSelfNonce
	MyIP, MyIPSelfNonce = ip, ip
	t.Cleanup(func() { MyIP, MyIPSelfNonce = savedIP, savedSelf })
}

// TestCountPeersOnTopicSkipsSelf: the self-connection is present on the sync
// topic even on a node that is completely alone. Counting it told the mining
// loop the node was connected, so it never re-dialled its bootstrap peers while
// the only chain data reaching it was its own.
func TestCountPeersOnTopicSkipsSelf(t *testing.T) {
	withTestMyIP(t, [4]byte{10, 0, 0, 7})
	topic := [2]byte{'Z', 'Z'}

	withTestTopic(t, topic, map[[4]byte]net.Conn{
		{127, 0, 0, 1}: nil,
		{10, 0, 0, 7}:  nil,
	})
	if got := CountPeersOnTopic(topic); got != 0 {
		t.Fatalf("CountPeersOnTopic = %d, expected 0 - these are all self-connections", got)
	}

	PeersMutex.Lock()
	tcpConnections[topic][[4]byte{178, 182, 254, 9}] = nil
	PeersMutex.Unlock()
	if got := CountPeersOnTopic(topic); got != 1 {
		t.Fatalf("CountPeersOnTopic = %d, expected 1 - a real peer must count", got)
	}
}

// TestGetIPsConnectedNeverAdvertisesSelf: 127.0.0.1 means "itself" to whoever
// reads it, so a peer that learns it from us dials its own listener and ends up
// syncing against itself.
func TestGetIPsConnectedNeverAdvertisesSelf(t *testing.T) {
	withTestMyIP(t, [4]byte{10, 0, 0, 7})
	topic := [2]byte{'Z', 'Z'}
	withTestTopic(t, topic, map[[4]byte]net.Conn{
		{127, 0, 0, 1}: nil,
		{10, 0, 0, 7}:  nil,
	})

	// Every other topic map must be empty for this to be conclusive.
	PeersMutex.Lock()
	saved := tcpConnections
	tcpConnections = map[[2]byte]map[[4]byte]net.Conn{topic: saved[topic]}
	PeersMutex.Unlock()
	defer func() {
		PeersMutex.Lock()
		tcpConnections = saved
		PeersMutex.Unlock()
	}()

	if ips := GetIPsConnected(); len(ips) != 0 {
		t.Fatalf("GetIPsConnected = %v, expected an empty list - we would be advertising our own addresses", ips)
	}
}

func TestIsSelfIP(t *testing.T) {
	withTestMyIP(t, [4]byte{10, 0, 0, 7})
	savedSelf := MyIPSelfNonce
	MyIPSelfNonce = [4]byte{192, 168, 1, 5}
	defer func() { MyIPSelfNonce = savedSelf }()

	selfs := [][4]byte{{127, 0, 0, 1}, {10, 0, 0, 7}, {192, 168, 1, 5}}
	for _, ip := range selfs {
		if !IsSelfIP(ip) {
			t.Fatalf("IsSelfIP(%v) = false, expected true", ip)
		}
	}
	if IsSelfIP([4]byte{178, 182, 254, 9}) {
		t.Fatal("IsSelfIP: a foreign address was treated as our own")
	}
}
