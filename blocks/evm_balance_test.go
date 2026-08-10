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

	// The exact sequence opSelfdestruct performs (fixed: re-read balance
	// after the credit so the debit zeroes the contract in both the
	// general case and the self-destruct-to-self case):
	bal := State.GetBalance(contract)
	State.AddBalance(beneficiary, bal)
	State.SubBalance(contract, State.GetBalance(contract))

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

// TestSelfdestructToSelfBurns exercises the self-destruct-to-self case
// (beneficiary == contract) using the fixed opSelfdestruct sequence: the
// debit re-reads the contract's current balance (post-credit), so the
// balance is burned rather than doubled.
func TestSelfdestructToSelfBurns(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	account.AccountsRWMutex.Lock()
	account.Accounts.AllAccounts = make(map[[common.AddressLength]byte]account.Account)
	account.AccountsRWMutex.Unlock()
	InitStateDB()

	var self common.Address
	self.ByteValue[0] = 0x32
	account.SetBalance(self.ByteValue, 500)
	before := GetSupplyInAccounts()

	// The exact sequence opSelfdestruct performs, with beneficiary == self:
	bal := State.GetBalance(self)
	State.AddBalance(self, bal)
	State.SubBalance(self, State.GetBalance(self)) // re-read => zeroes

	if account.GetBalance(self.ByteValue) != 0 {
		t.Fatalf("self balance not burned: %d", account.GetBalance(self.ByteValue))
	}
	if after := GetSupplyInAccounts(); after != before-500 {
		t.Fatalf("supply not decreased by burned amount: before=%d after=%d", before, after)
	}
}
