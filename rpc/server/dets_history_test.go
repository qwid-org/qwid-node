package serverrpc

import (
	"path/filepath"
	"testing"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/database"
)

// TestHandleDETSFillsTxHistory: the address-details views (webui explorer,
// history) are built from the DETS reply. Since the account state stopped
// carrying the history lists, DETS must fill them from the DB index like ACCT
// does - the regression here was a details view showing only the counters and
// no individual transactions.
func TestHandleDETSFillsTxHistory(t *testing.T) {
	db := &database.BlockchainDB{}
	pdb, err := db.InitPermanent(filepath.Join(t.TempDir(), "blockchain"))
	if err != nil {
		t.Skipf("RocksDB unavailable: %v", err)
	}
	savedDB := database.MainDB
	database.MainDB = pdb
	t.Cleanup(func() {
		pdb.Close()
		database.MainDB = savedDB
	})

	account.AccountsRWMutex.Lock()
	savedAccounts := account.Accounts
	account.Accounts = account.AccountsType{AllAccounts: map[[common.AddressLength]byte]account.Account{}}
	account.AccountsRWMutex.Unlock()
	t.Cleanup(func() {
		account.AccountsRWMutex.Lock()
		account.Accounts = savedAccounts
		account.AccountsRWMutex.Unlock()
	})

	var addr [common.AddressLength]byte
	addr[0] = 0xDE
	account.AccountsRWMutex.Lock()
	account.Accounts.AllAccounts[addr] = account.Account{Address: addr, Balance: 42}
	account.AccountsRWMutex.Unlock()

	sent := common.Hash{}
	sent[0] = 0x11
	recv := common.Hash{}
	recv[0] = 0x22
	account.AddTransactionsSender(addr, sent)
	account.AddTransactionsRecipient(addr, recv)

	var reply []byte
	handleDETS(addr[:], &reply)

	if len(reply) < 2 || string(reply[:2]) != "AC" {
		t.Fatalf("odpowiedź DETS = %q, oczekiwano prefiksu AC", reply[:2])
	}
	acc := account.Account{}
	if err := acc.Unmarshal(reply[2:]); err != nil {
		t.Fatalf("Unmarshal odpowiedzi DETS: %v", err)
	}
	if len(acc.TransactionsSender) != 1 || acc.TransactionsSender[0] != sent {
		t.Fatalf("wysłane w odpowiedzi DETS = %v, oczekiwano [%x] - widok szczegółów adresu "+
			"pokazywałby tylko liczniki bez transakcji", acc.TransactionsSender, sent[:4])
	}
	if len(acc.TransactionsRecipient) != 1 || acc.TransactionsRecipient[0] != recv {
		t.Fatalf("odebrane w odpowiedzi DETS = %v, oczekiwano [%x]", acc.TransactionsRecipient, recv[:4])
	}
	if acc.SentCount != 1 || acc.ReceivedCount != 1 {
		t.Fatalf("liczniki = %d/%d, oczekiwano 1/1", acc.SentCount, acc.ReceivedCount)
	}
}
