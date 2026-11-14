package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

// Audit 2026-11-13 (F-TX-01, rest): an escrow or multisig account creates no
// lock at all, not even in its own staking account. A lock released at one
// base unit a block froze the account's coins for good, applied at once -
// past the escrow delay the owner could cancel in, past every approval.
func TestEscrowAndMultisigAccountsCreateNoLocks(t *testing.T) {
	logger.InitLogger()
	withBalanceTestDB(t)
	initTestAccounts()
	initTestStaking()
	withFreshHeldPools(t)
	amount := 10 * common.MinStakingUser
	blk := Block{BaseBlock: BaseBlock{BaseHeader: BaseHeader{Height: 100}}}
	ownLock := func(a common.Address, marker byte) (bool, error) {
		tx := transferTx(t, a, a, amount, common.EmptyHash(), marker)
		tx.TxData.LockedAmount = amount
		tx.TxData.ReleasePerBlock = 1
		tx.TxData.DelegatedAccountForLocking = common.GetDelegatedAccountAddress(1)
		_ = tx.CalcHashAndSet()
		return CheckStakingTransaction(tx, amount, 1, blk), ProcessTransaction(tx, 100, 1000)
	}
	for _, c := range []struct {
		name string
		addr byte
		acc  account.Account
	}{
		{"escrow", 40, account.Account{TransactionDelay: 60480}},
		{"multisig", 41, account.Account{MultiSignNumber: 1, MultiSignAddresses: [][common.AddressLength]byte{testAddress(43).ByteValue}}},
	} {
		name, acc, a := c.name, c.acc, testAddress(c.addr)
		acc.Address, acc.Balance = a.ByteValue, amount+1_000_000
		account.Accounts.AllAccounts[a.ByteValue] = acc
		ok, err := ownLock(a, 2)
		if ok {
			t.Errorf("%s: the block check accepts a lock in the account's own stake", name)
		}
		if err == nil {
			t.Errorf("%s: a lock in the account's own stake was applied", name)
		}
		if st := account.GetStakingAccountByAddressBytes(a.GetBytes(), 1); st.StakedBalance != 0 {
			t.Errorf("%s: %d were locked", name, st.StakedBalance)
		}
	}
	plain := testAddress(44)
	account.Accounts.AllAccounts[plain.ByteValue] = account.Account{Address: plain.ByteValue, Balance: amount + 1_000_000}
	if ok, err := ownLock(plain, 3); !ok || err != nil {
		t.Fatalf("an ordinary account could not lock its own stake: check=%v apply=%v", ok, err)
	}
}
