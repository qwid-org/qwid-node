package transactionsDefinition

import (
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
)

func TestRequiredHoldFee(t *testing.T) {
	tx := Transaction{TxData: TxData{Recipient: common.EmptyAddress(), Amount: 5}}
	if RequiredHoldFee(tx, account.Account{}, true) != 0 {
		t.Fatal("an ordinary account's transfer owes a hold fee")
	}
	escrow := account.Account{TransactionDelay: common.MaxTransactionDelay / 2}
	if got := RequiredHoldFee(tx, escrow, true); got != common.HoldFee(common.MaxTransactionDelay/2) {
		t.Fatalf("escrow transfer owes %d", got)
	}
	ms := account.Account{MultiSignNumber: 2, MultiSignAddresses: make([][common.AddressLength]byte, 3)}
	if got := RequiredHoldFee(tx, ms, true); got != 4*common.HoldFee(common.MaxTransactionInMultiSigPool) {
		t.Fatalf("multisig transaction owes %d, want its slot and one per signer for the window", got)
	}
	approval := tx
	approval.TxParam.MultiSignTx = common.Hash{1}
	approval.TxData.Amount = 0
	if RequiredHoldFee(approval, account.Account{}, true) != 0 {
		t.Fatal("an approval owes a hold fee - its transaction paid for it")
	}
	staking := Transaction{TxData: TxData{Recipient: common.GetDelegatedAccountAddress(1), Amount: 5}}
	if RequiredHoldFee(staking, escrow, true) != 0 {
		t.Fatal("a staking transaction of an escrow account is not held")
	}
}

func TestApplyHoldFeeCoversTheMinimumPlusTheHold(t *testing.T) {
	for _, hold := range []int64{0, 10_000_000, common.HoldFee(common.MaxTransactionDelay), 50 * common.HeldTxFeePerWeek} {
		tx := Transaction{TxData: TxData{Recipient: common.EmptyAddress(), Amount: 5}, GasPrice: 3}
		tx.GasUsage = tx.GasUsageEstimate()
		if err := ApplyHoldFee(&tx, hold); err != nil {
			t.Fatalf("hold %d: %v", hold, err)
		}
		fee, _ := tx.CalcFee()
		if fee < tx.MinGasUsage()+hold || tx.GasPrice > common.MaxGasPrice || tx.GasUsage > common.MaxGasUsage {
			t.Fatalf("hold %d: fee %d price %d gas %d", hold, fee, tx.GasPrice, tx.GasUsage)
		}
		if hold == 0 && tx.GasPrice != 3 {
			t.Fatal("no hold changed the price")
		}
	}
}

// What wallets call with the node's ACCT answer for the sender.
func TestApplyHoldFeeFromAccountReply(t *testing.T) {
	var sender common.Address
	sender.ByteValue[0] = 0x21
	acc := account.Account{Address: sender.ByteValue, TransactionDelay: common.MaxTransactionDelay}
	tx := Transaction{TxParam: TxParam{Sender: sender}, TxData: TxData{Recipient: common.EmptyAddress(), Amount: 5}, GasPrice: 1}
	tx.GasUsage = tx.GasUsageEstimate()
	if err := ApplyHoldFeeFromAccount(&tx, acc.Marshal()); err != nil {
		t.Fatal(err)
	}
	if !PaysHoldFee(tx, common.HeldTxFeePerWeek) {
		t.Fatal("the wallet's transaction from a week-delay escrow account does not pay for the week")
	}
	plain := Transaction{TxParam: TxParam{Sender: sender}, TxData: TxData{Recipient: common.EmptyAddress(), Amount: 5}, GasPrice: 1}
	plain.GasUsage = plain.GasUsageEstimate()
	other := account.Account{Address: sender.ByteValue}
	if err := ApplyHoldFeeFromAccount(&plain, other.Marshal()); err != nil || plain.GasPrice != 1 {
		t.Fatal("an ordinary account's transaction was charged a hold fee")
	}
}
