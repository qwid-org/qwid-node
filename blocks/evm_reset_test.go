package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

// TestResetTransientClearsAccessListAndSuicided is a regression test for the
// final-review Issue 1 leak: EvaluateSCDex and GetViewFunctionReturns invoke
// the VM against the shared singleton blocks.State without resetting
// transient per-tx execution state, so a warmed access-list address or a
// suicided address from a previous execution would leak into the next one.
//
// This test asserts the fix directly at the stateDB level: after warming an
// address into the EIP-2929 access list and marking another address
// suicided, calling State.ResetTransient() must clear both back to cold /
// not-suicided. It needs no live DB.
func TestResetTransientClearsAccessListAndSuicided(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	InitStateDB()

	var addrBytes [common.AddressLength]byte
	addrBytes[0] = 0xAB
	warmAddr, err := common.BytesToAddress(addrBytes[:])
	if err != nil {
		t.Fatalf("BytesToAddress: %v", err)
	}

	var suicidedBytes [common.AddressLength]byte
	suicidedBytes[0] = 0xCD
	suicidedAddr, err := common.BytesToAddress(suicidedBytes[:])
	if err != nil {
		t.Fatalf("BytesToAddress: %v", err)
	}

	StateMutex.Lock()
	State.CreateAccount(suicidedAddr)
	State.AddAddressToAccessList(warmAddr)
	State.Suicide(suicidedAddr)
	StateMutex.Unlock()

	StateMutex.RLock()
	warmBefore := State.AddressInAccessList(warmAddr)
	suicidedBefore := State.HasSuicided(suicidedAddr)
	StateMutex.RUnlock()

	if !warmBefore {
		t.Fatal("setup failed: address should be warm before reset")
	}
	if !suicidedBefore {
		t.Fatal("setup failed: address should be suicided before reset")
	}

	StateMutex.Lock()
	State.ResetTransient()
	StateMutex.Unlock()

	StateMutex.RLock()
	warmAfter := State.AddressInAccessList(warmAddr)
	suicidedAfter := State.HasSuicided(suicidedAddr)
	StateMutex.RUnlock()

	if warmAfter {
		t.Fatal("ResetTransient did not clear the access list: address is still warm")
	}
	if suicidedAfter {
		t.Fatal("ResetTransient did not clear the suicided set: address is still suicided")
	}
}
