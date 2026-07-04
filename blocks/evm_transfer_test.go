package blocks

import (
	"math/big"
	"testing"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"
)

func initNativeAccountsBlocks() {
	account.AccountsRWMutex.Lock()
	account.Accounts.AllAccounts = make(map[[common.AddressLength]byte]account.Account)
	account.AccountsRWMutex.Unlock()
}

func TestEvmTransferMovesValueAndCanTransfer(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initNativeAccountsBlocks()
	InitStateDB()

	var from, to common.Address
	from.ByteValue[0] = 0x50
	to.ByteValue[0] = 0x51
	account.SetBalance(from.ByteValue, 1000)

	if !evmCanTransfer(&State, from, big.NewInt(400)) {
		t.Fatal("CanTransfer should allow 400 from balance 1000")
	}
	if evmCanTransfer(&State, from, big.NewInt(1001)) {
		t.Fatal("CanTransfer should reject 1001 from balance 1000")
	}
	evmTransfer(&State, from, to, big.NewInt(400))
	if account.GetBalance(from.ByteValue) != 600 || account.GetBalance(to.ByteValue) != 400 {
		t.Fatalf("transfer wrong: from=%d to=%d", account.GetBalance(from.ByteValue), account.GetBalance(to.ByteValue))
	}
}
