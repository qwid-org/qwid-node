package tcpip

import (
	"testing"
	"time"

	"github.com/qwid-org/qwid-node/common"
)

// S1-07: violations are counted per source across reconnects; a reconnect
// (which resets connection trust) no longer wipes them, and alternating
// garbage with valid messages does not either.
func TestViolationsSurviveReconnectAndLeadToBan(t *testing.T) {
	ip := [4]byte{203, 0, 113, 77}
	resetViolations()
	defer resetViolations()
	for i := 1; i < common.ConnectionMaxTries; i++ {
		PeersMutex.Lock()
		validPeersConnected[ip] = common.ConnectionMaxTries // a fresh connection
		ban := ReduceTrustRegisterPeer(ip)
		PeersMutex.Unlock()
		ValidRegisterPeer(ip) // a valid message in between
		if ban {
			t.Fatalf("banned after only %d violations", i)
		}
	}
	PeersMutex.Lock()
	validPeersConnected[ip] = common.ConnectionMaxTries
	ban := ReduceTrustRegisterPeer(ip)
	PeersMutex.Unlock()
	if !ban {
		t.Fatalf("not banned after %d violations", common.ConnectionMaxTries)
	}
}

func TestViolationsAreForgivenOverTime(t *testing.T) {
	ip := [4]byte{203, 0, 113, 78}
	resetViolations()
	defer resetViolations()
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < common.ConnectionMaxTries-1; i++ {
		recordViolation(ip, now)
	}
	later := now.Add(time.Duration(common.ConnectionMaxTries) * violationForgiveInterval)
	if recordViolation(ip, later) {
		t.Fatal("old violations must decay")
	}
}
