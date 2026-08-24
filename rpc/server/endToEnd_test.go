package serverrpc

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsPool"
	"github.com/qwid-org/qwid-node/wallet"
)

// End-to-end over the real RPC entry point.
//
// The unit tests check key selection and the handlers separately, with stand-in
// one-byte keys. They cannot catch a wire-format mistake: that the framing
// SignMessage produces is the framing Send expects, that the scheme selector
// byte in a real signature picks the right half, or that a genuine Falcon-512
// signature from a wallet OTHER than the mining one actually verifies against
// the public key read out of its wallet file.
//
// So this drives Listener.Send with real post-quantum signatures from two
// generated wallets: one is the node's mining wallet, the other stands in for
// the operator's wallet 10.

// newTestWallet builds a usable wallet the way cmd/generateNewWallet does,
// minus the mnemonic: both scheme key pairs, real signers, no file written.
func newTestWallet(t *testing.T, number uint8) *wallet.Wallet {
	t.Helper()
	w := wallet.EmptyWallet(number, common.SigName(), common.SigName2())
	w.SetPassword("end-to-end-test")
	w.Iv = wallet.GenerateNewIv()

	acc, err := wallet.GenerateNewAccount(w, w.SigName)
	if err != nil {
		t.Fatalf("wallet %d primary key: %v", number, err)
	}
	w.MainAddress = acc.Address
	acc.PublicKey.MainAddress = w.MainAddress
	w.Account1 = acc

	acc2, err := wallet.GenerateNewAccount(w, w.SigName2)
	if err != nil {
		t.Fatalf("wallet %d secondary key: %v", number, err)
	}
	acc2.PublicKey.MainAddress = w.MainAddress
	w.Account2 = acc2

	return &w
}

// signRequest is byte-for-byte what cmd/webui/handlers.SignMessage does for an
// operation that needs verification: length-prefix the line, sign that, append
// the signature.
func signRequest(t *testing.T, w *wallet.Wallet, line []byte, primary bool) []byte {
	t.Helper()
	framed := common.BytesToLenAndBytes(line)
	sign, err := w.Sign(framed, primary)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}
	return append(framed, sign.GetBytes()...)
}

// localCall is a request arriving on the loopback RPC socket, the only place
// signed operations are accepted from.
func localCall(t *testing.T, w *wallet.Wallet, line []byte, primary bool) string {
	t.Helper()
	l := &Listener{remoteIP: "127.0.0.1"}
	var reply []byte
	if err := l.Send(signRequest(t, w, line, primary), &reply); err != nil {
		t.Fatalf("Send returned an error: %v", err)
	}
	return string(reply)
}

// withNodeAndUserWallets sets up the situation the operator is actually in: the
// node mines with one wallet, and a second wallet — "wallet 10" — sits in the
// wallet directory and drives the webui. Neither has an on-chain key here, so
// this exercises the path a freshly generated wallet takes.
func withNodeAndUserWallets(t *testing.T) (miner, user *wallet.Wallet) {
	t.Helper()
	miner = newTestWallet(t, 0)
	user = newTestWallet(t, 10)

	savedActive := wallet.GetActiveWallet()
	wallet.SetActiveWallet(miner)
	t.Cleanup(func() { wallet.SetActiveWallet(savedActive) })

	withStubbedLocalWallets(t, []wallet.WalletPublicKeys{
		{Number: 0, MainAddress: miner.MainAddress,
			Primary: miner.Account1.PublicKey.GetBytes(), Secondary: miner.Account2.PublicKey.GetBytes()},
		{Number: 10, MainAddress: user.MainAddress,
			Primary: user.Account1.PublicKey.GetBytes(), Secondary: user.Account2.PublicKey.GetBytes()},
	})
	// No key trie in a unit test; an unregistered account is also the realistic
	// state of a wallet that has not yet had a transaction processed.
	withStubbedPubKeyLookup(t, nil, errNoSuchKey)
	return miner, user
}

// The original complaint: a wallet other than the mining one got "Invalid
// signature" for everything and the webui showed nothing.
func TestWallet10IsAcceptedOverTheRealRPCPath(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withEmptyPools(t)
	_, user := withNodeAndUserWallets(t)

	reply := localCall(t, user, append([]byte("PEND"), user.MainAddress.GetBytes()...), true)

	if strings.Contains(reply, "Invalid signature") {
		t.Fatalf("wallet 10 was still rejected: %q", reply)
	}
	if !strings.HasPrefix(reply, "[") {
		t.Fatalf("PEND did not answer a JSON list: %q", reply)
	}
}

// Exactly one scheme is usable at a time, so a secondary-scheme signature is
// accepted precisely when the primary is paused — and refused otherwise.
//
// This test used to assert that the secondary always authenticates, which was
// true when both schemes ran live side by side. Under the single-active-scheme
// invariant that would mean two usable schemes at once; the property worth
// pinning is the swap itself, because it is what makes a pause recoverable: a
// node whose primary is paused must still be able to sign, or the vote that
// lifts the pause can never be cast.
func TestSecondarySchemeIsAcceptedOnlyWhileThePrimaryIsPaused(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withEmptyPools(t)
	_, user := withNodeAndUserWallets(t)

	// Primary live: the spare is in reserve and must not authenticate.
	reply := localCall(t, user, append([]byte("PEND"), user.MainAddress.GetBytes()...), false)
	if !strings.Contains(reply, "Invalid signature") {
		t.Fatalf("a spare-scheme signature authenticated while the primary was live: %q", reply)
	}

	// Pause the primary: the spare takes over and must authenticate.
	common.GetEncryptionConfigInstance().SetEncryption(common.SigName(), common.PubKeyLength(false),
		common.PrivateKeyLength(), common.SignatureLength(false), true, true)
	t.Cleanup(func() {
		common.GetEncryptionConfigInstance().SetEncryption(common.SigName(), common.PubKeyLength(false),
			common.PrivateKeyLength(), common.SignatureLength(false), false, true)
	})

	reply = localCall(t, user, append([]byte("PEND"), user.MainAddress.GetBytes()...), false)
	if strings.Contains(reply, "Invalid signature") {
		t.Fatalf("the spare scheme was rejected while the primary was paused, so a paused node cannot sign at all: %q", reply)
	}
}

// What the webui actually shows: only this wallet's own traffic.
func TestWallet10SeesOnlyItsOwnPendingTransactions(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withEmptyPools(t)
	miner, user := withNodeAndUserWallets(t)

	mine := txFrom(user.MainAddress, 61)
	theirs := txFrom(miner.MainAddress, 62)
	transactionsPool.PoolsTx.AddTransaction(mine, mine.Hash)
	transactionsPool.PoolsTx.AddTransaction(theirs, theirs.Hash)

	reply := localCall(t, user, append([]byte("PEND"), user.MainAddress.GetBytes()...), true)

	var txs []struct {
		Sender string `json:"sender"`
	}
	if err := json.Unmarshal([]byte(reply), &txs); err != nil {
		t.Fatalf("PEND did not answer JSON: %v (%q)", err, reply)
	}
	if len(txs) != 1 || txs[0].Sender != user.MainAddress.GetHex() {
		t.Fatalf("wallet 10 saw %+v, want only its own transaction", txs)
	}
}

// Cancelling was the operation that failed outright: the node compared the
// pooled sender against ITS OWN wallet, so wallet 10 was told it did not own
// its own transaction.
func TestWallet10CancelsItsOwnTransaction(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withEmptyPools(t)
	_, user := withNodeAndUserWallets(t)

	tx := txFrom(user.MainAddress, 63)
	transactionsPool.PoolsTx.AddTransaction(tx, tx.Hash)

	line := append([]byte("CNCL"), user.MainAddress.GetBytes()...)
	reply := localCall(t, user, append(line, tx.Hash.GetBytes()...), true)

	if !strings.Contains(reply, "cancelled") {
		t.Fatalf("wallet 10 could not cancel its own transaction: %q", reply)
	}
	if transactionsPool.PoolsTx.TransactionExists(tx.Hash.GetBytes()) {
		t.Error("the transaction survived cancellation")
	}
}

// ...and must not gain the ability to cancel the mining wallet's.
func TestWallet10CannotCancelTheMinersTransaction(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withEmptyPools(t)
	miner, user := withNodeAndUserWallets(t)

	tx := txFrom(miner.MainAddress, 64)
	transactionsPool.PoolsTx.AddTransaction(tx, tx.Hash)

	// Wallet 10 signs, but names the miner's address to aim at its transaction.
	line := append([]byte("CNCL"), miner.MainAddress.GetBytes()...)
	reply := localCall(t, user, append(line, tx.Hash.GetBytes()...), true)

	// It is stopped a layer earlier than the ownership check: naming an account
	// means being verified against THAT account's key, which wallet 10 cannot
	// produce a signature for. Asserting the reason keeps the test honest — a
	// bare "not cancelled" would also pass on an unrelated error.
	if !strings.Contains(reply, "Invalid signature") {
		t.Fatalf("wallet 10 was not refused as the wrong signer: %q", reply)
	}
	if !transactionsPool.PoolsTx.TransactionExists(tx.Hash.GetBytes()) {
		t.Error("a refused cancellation still dropped the transaction")
	}
}

// The node's single vote belongs to the account it stakes with.
func TestWallet10CannotCastTheNodesVote(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	_, user := withNodeAndUserWallets(t)

	reply := localCall(t, user, append([]byte("VOTE"), votePayload(user.MainAddress)...), true)

	if strings.Contains(reply, "successful") {
		t.Fatalf("wallet 10 cast the node's vote: %q", reply)
	}
}

func TestTheMiningWalletStillCastsTheVote(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	miner, _ := withNodeAndUserWallets(t)

	reply := localCall(t, miner, append([]byte("VOTE"), votePayload(miner.MainAddress)...), true)

	if !strings.Contains(reply, "successful") {
		t.Fatalf("the node refused its own operator's vote: %q", reply)
	}
}

// A wallet that is neither registered on-chain nor present on this machine is
// still refused — the point was to admit the operator's own wallets, not
// everybody's.
func TestAStrangersWalletIsStillRefused(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withEmptyPools(t)
	withNodeAndUserWallets(t)

	stranger := newTestWallet(t, 200)

	reply := localCall(t, stranger, append([]byte("PEND"), stranger.MainAddress.GetBytes()...), true)

	if !strings.Contains(reply, "Invalid signature") {
		t.Fatalf("a wallet unknown to this node was accepted: %q", reply)
	}
}

// Signed operations are loopback-only; the address in the payload is not a
// second way in.
func TestWallet10IsRefusedFromOffHost(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	_, user := withNodeAndUserWallets(t)

	l := &Listener{remoteIP: "203.0.113.7"}
	var reply []byte
	line := append([]byte("PEND"), user.MainAddress.GetBytes()...)
	if err := l.Send(signRequest(t, user, line, true), &reply); err != nil {
		t.Fatalf("Send returned an error: %v", err)
	}

	if !strings.Contains(string(reply), "localhost") {
		t.Fatalf("a remote caller was not refused: %q", reply)
	}
}
