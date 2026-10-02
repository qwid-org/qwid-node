package tcpip

import (
	"net"
	"testing"
)

// S1-05: the services ban misbehaving peers through ReduceAndCheckIfBanIP; the
// ban must also sever the peer's live connections.
func TestReduceAndCheckIfBanIPClosesTheConnection(t *testing.T) {
	ip := [4]byte{198, 51, 100, 77}
	a, b := net.Pipe()
	defer b.Close()
	PeersMutex.Lock()
	tcpConnections[TransactionTopic][ip] = a
	validPeersConnected[ip] = 1
	PeersMutex.Unlock()
	t.Cleanup(func() {
		PeersMutex.Lock()
		delete(tcpConnections[TransactionTopic], ip)
		delete(validPeersConnected, ip)
		PeersMutex.Unlock()
		bannedIPMutex.Lock()
		delete(bannedIP, ip)
		bannedIPMutex.Unlock()
	})

	ReduceAndCheckIfBanIP(ip)

	PeersMutex.RLock()
	_, still := tcpConnections[TransactionTopic][ip]
	PeersMutex.RUnlock()
	if !IsIPBanned(ip) || still {
		t.Fatalf("banned=%v connectionStillRegistered=%v", IsIPBanned(ip), still)
	}
	if _, err := a.Write([]byte("x")); err == nil {
		t.Fatal("connection of a banned peer is still open")
	}
}
