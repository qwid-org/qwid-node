package tcpip

import (
	"net"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// S1-04: every generated key is a new handle, so the inbound cap must also be
// enforced per source IP, or one machine fills every slot.
func TestInboundCapPerSource(t *testing.T) {
	src := [4]byte{203, 0, 113, 95}
	topic := TransactionTopic
	keys := [][4]byte{}
	for i := byte(0); i < maxInboundPerSource; i++ {
		var id common.Address
		id.ByteValue[0], id.ByteValue[1] = 0xD1, i
		h := HandleForPeer(id, src)
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		PeersMutex.Lock()
		tcpConnections[topic][h] = a
		PeersMutex.Unlock()
		keys = append(keys, h)
	}
	t.Cleanup(func() {
		PeersMutex.Lock()
		for _, k := range keys {
			delete(tcpConnections[topic], k)
		}
		PeersMutex.Unlock()
	})
	if !inboundPerSourceCapReached(topic, src) {
		t.Fatalf("%d connections from one source did not reach the per-source cap", maxInboundPerSource)
	}
	if inboundPerSourceCapReached(topic, [4]byte{203, 0, 113, 96}) {
		t.Fatal("another source was refused")
	}
}
