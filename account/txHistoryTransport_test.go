package account

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

// Account.TransactionsSender/TransactionsRecipient stopped being state and
// became transport containers that the RPC layer fills from the history index.
// handleACCT was updated for that; handleDETS was not, so every client that
// looks an account up by address — the wallet's Details tab, the public
// explorer, the website — received an account with empty history lists and
// rendered a summary with no transactions.
//
// The fill now lives here so both handlers share one implementation and cannot
// drift apart again.

func TestWithTxHistoryFillsTransportSlices(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withHistoryTempDB(t)
	withFreshAccounts(t)

	addr := [common.AddressLength]byte{}
	addr[0] = 7
	AddTransactionsSender(addr, hashOf(1))
	AddTransactionsSender(addr, hashOf(2))
	AddTransactionsRecipient(addr, hashOf(3))

	AccountsRWMutex.RLock()
	acc := Accounts.AllAccounts[addr]
	AccountsRWMutex.RUnlock()

	// Straight out of the state map the lists are empty: the history is in the
	// index, not in the account.
	if len(acc.TransactionsSender) != 0 || len(acc.TransactionsRecipient) != 0 {
		t.Fatalf("state account unexpectedly carries history: sent=%d recv=%d",
			len(acc.TransactionsSender), len(acc.TransactionsRecipient))
	}

	filled := WithTxHistory(acc, addr, 50)

	if len(filled.TransactionsSender) != 2 {
		t.Errorf("TransactionsSender = %d entries, want 2", len(filled.TransactionsSender))
	}
	if len(filled.TransactionsRecipient) != 1 {
		t.Errorf("TransactionsRecipient = %d entries, want 1", len(filled.TransactionsRecipient))
	}
	// Counters describe the whole history and must survive the fill, so a
	// client can tell a capped list from a complete one.
	if filled.SentCount != 2 || filled.ReceivedCount != 1 {
		t.Errorf("counters clobbered: sent=%d recv=%d", filled.SentCount, filled.ReceivedCount)
	}
}

func TestWithTxHistoryCapsToLastN(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withHistoryTempDB(t)
	withFreshAccounts(t)

	addr := [common.AddressLength]byte{}
	addr[0] = 8
	for i := byte(1); i <= 5; i++ {
		AddTransactionsSender(addr, hashOf(i))
	}

	AccountsRWMutex.RLock()
	acc := Accounts.AllAccounts[addr]
	AccountsRWMutex.RUnlock()

	filled := WithTxHistory(acc, addr, 2)

	if len(filled.TransactionsSender) != 2 {
		t.Fatalf("TransactionsSender = %d entries, want the last 2", len(filled.TransactionsSender))
	}
	// The tail is what a wallet wants: the most recent activity.
	if filled.TransactionsSender[1] != hashOf(5) {
		t.Errorf("last entry is not the newest transaction")
	}
	if filled.SentCount != 5 {
		t.Errorf("SentCount = %d, want 5 — the true total, not the capped length", filled.SentCount)
	}
}

func TestWithTxHistoryLeavesUnknownAccountEmpty(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withHistoryTempDB(t)
	withFreshAccounts(t)

	addr := [common.AddressLength]byte{}
	addr[0] = 9

	filled := WithTxHistory(Account{Address: addr}, addr, 50)

	if len(filled.TransactionsSender) != 0 || len(filled.TransactionsRecipient) != 0 {
		t.Error("an account with no history came back with entries")
	}
}
