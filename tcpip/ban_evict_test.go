package tcpip

import (
	"testing"

	"github.com/wonabru/qwid-node/common"
)

func TestIsIPBannedEvictsExpired(t *testing.T) {
	ip := [4]byte{10, 0, 0, 1}
	now := common.GetCurrentTimeStampInSecond()
	bannedIPMutex.Lock()
	bannedIP[ip] = now - 1 // already expired
	bannedIPMutex.Unlock()

	if IsIPBanned(ip) {
		t.Fatal("expired ban should report not banned")
	}
	bannedIPMutex.RLock()
	_, present := bannedIP[ip]
	bannedIPMutex.RUnlock()
	if present {
		t.Fatal("expired ban entry should have been evicted from the map")
	}
}

func TestBanIPSweepsExpired(t *testing.T) {
	stale := [4]byte{10, 0, 0, 2}
	fresh := [4]byte{10, 0, 0, 3}
	now := common.GetCurrentTimeStampInSecond()
	bannedIPMutex.Lock()
	bannedIP[stale] = now - 1 // expired
	bannedIPMutex.Unlock()

	BanIP(fresh) // triggers the opportunistic sweep + records the new ban

	bannedIPMutex.RLock()
	_, staleP := bannedIP[stale]
	_, freshP := bannedIP[fresh]
	bannedIPMutex.RUnlock()
	if staleP {
		t.Fatal("BanIP should have swept the expired entry")
	}
	if !freshP {
		t.Fatal("BanIP should have recorded the new ban")
	}
	bannedIPMutex.Lock()
	delete(bannedIP, fresh)
	bannedIPMutex.Unlock()
}
