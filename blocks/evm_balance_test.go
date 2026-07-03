package blocks

import (
	"testing"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"
)

// TestSelfdestructConservesSupply exercises the balance sequence that
// opSelfdestruct performs (credit beneficiary, debit contract) and asserts total
// supply is unchanged and the contract balance is zeroed.
func TestSelfdestructConservesSupply(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	account.AccountsRWMutex.Lock()
	account.Accounts.AllAccounts = make(map[[common.AddressLength]byte]account.Account)
	account.AccountsRWMutex.Unlock()
	InitStateDB()

	var contract, beneficiary common.Address
	contract.ByteValue[0] = 0x30
	beneficiary.ByteValue[0] = 0x31
	account.SetBalance(contract.ByteValue, 700)
	account.SetBalance(beneficiary.ByteValue, 100)
	before := GetSupplyInAccounts()

	// The exact sequence opSelfdestruct performs (verified by Step 3):
	bal := State.GetBalance(contract)
	State.AddBalance(beneficiary, bal)
	State.SubBalance(contract, bal)

	if account.GetBalance(beneficiary.ByteValue) != 100+700 {
		t.Fatalf("beneficiary = %d, want 800", account.GetBalance(beneficiary.ByteValue))
	}
	if account.GetBalance(contract.ByteValue) != 0 {
		t.Fatalf("contract balance not zeroed: %d", account.GetBalance(contract.ByteValue))
	}
	if after := GetSupplyInAccounts(); after != before {
		t.Fatalf("supply changed: before=%d after=%d", before, after)
	}
}
