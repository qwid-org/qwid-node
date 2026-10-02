package tcpip

import (
	"net"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// S1-09: trust is kept per transport source, connections per handle. Closing
// the last connection from a source must drop that source's trust entry, and
// closing one of two nodes behind the same source must not.
func TestDisconnectClearsTrustOfTheTransportSource(t *testing.T) {
	resetHandles(t)
	defer resetHandles(t)
	src := [4]byte{198, 51, 100, 23}
	hA := HandleForPeer(nodeIDn(1), src)
	hB := HandleForPeer(nodeIDn(2), src)
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	defer a2.Close()
	defer b2.Close()

	PeersMutex.Lock()
	defer PeersMutex.Unlock()
	if tcpConnections[SyncTopic] == nil {
		tcpConnections[SyncTopic] = map[[4]byte]net.Conn{}
	}
	tcpConnections[SyncTopic][hA] = a1
	tcpConnections[SyncTopic][hB] = b1
	validPeersConnected[src] = common.ConnectionMaxTries
	nodePeersConnected[src] = common.ConnectionMaxTries
	defer func() {
		delete(tcpConnections[SyncTopic], hA)
		delete(tcpConnections[SyncTopic], hB)
		delete(validPeersConnected, src)
		delete(nodePeersConnected, src)
	}()

	CloseAndRemoveConnection(a1)
	if _, ok := validPeersConnected[src]; !ok {
		t.Fatal("trust dropped while another node from the same source is connected")
	}
	CloseAndRemoveConnection(b1)
	if _, ok := validPeersConnected[src]; ok {
		t.Fatal("trust of a fully disconnected source left behind")
	}
	if _, ok := nodePeersConnected[src]; ok {
		t.Fatal("node entry of a fully disconnected source left behind")
	}
}
