package tcpip

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/wallet"
)

// withListenerWallet installs a real active wallet, which Accept needs to
// answer handshakes.
func withListenerWallet(t *testing.T) {
	t.Helper()
	w := wallet.EmptyWallet(250, common.SigName(), common.SigName2())
	w.SetPassword("listener-test-password")
	acc, err := wallet.GenerateNewAccount(w, common.SigName())
	if err != nil {
		t.Skipf("cannot build wallet: %v", err)
	}
	w.Account1 = acc
	prev := wallet.GetActiveWallet()
	wallet.SetActiveWallet(&w)
	t.Cleanup(func() { wallet.SetActiveWallet(prev) })
}

// S1-02: connections that never speak must not hold up the accept loop - an
// honest peer's handshake has to complete promptly behind them.
func TestSilentConnectionsDoNotDelayHonestHandshake(t *testing.T) {
	withListenerWallet(t)
	topic := SyncTopic
	oldPort := Ports[topic]
	Ports[topic] = 46924 // isolated test port, not a node port
	t.Cleanup(func() { Ports[topic] = oldPort })
	go StartNewListener(topic)
	time.Sleep(300 * time.Millisecond)
	addr := fmt.Sprintf("127.0.0.1:%d", Ports[topic])

	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	time.Sleep(100 * time.Millisecond)

	honest, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer honest.Close()
	start := time.Now()
	_, _, hsErr := HandshakeInitiator(honest, newTestIdentity(t))
	if el := time.Since(start); hsErr != nil || el > 2*time.Second {
		t.Fatalf("honest handshake behind 3 silent connections: err=%v after %s", hsErr, el.Truncate(time.Millisecond))
	}
}

// One source cannot hold more than its share of handshake slots.
func TestHandshakeSlotsAreBoundedPerSource(t *testing.T) {
	ip := [4]byte{198, 51, 100, 9}
	for i := 0; i < maxPendingHandshakesPerIP; i++ {
		if !tryReserveHandshake(ip) {
			t.Fatalf("slot %d refused", i)
		}
	}
	if tryReserveHandshake(ip) {
		t.Fatal("source got more than maxPendingHandshakesPerIP slots")
	}
	if !tryReserveHandshake([4]byte{198, 51, 100, 10}) {
		t.Fatal("another source was refused")
	}
	releaseHandshake([4]byte{198, 51, 100, 10})
	for i := 0; i < maxPendingHandshakesPerIP; i++ {
		releaseHandshake(ip)
	}
	if !tryReserveHandshake(ip) {
		t.Fatal("slot not returned after release")
	}
	releaseHandshake(ip)
}
