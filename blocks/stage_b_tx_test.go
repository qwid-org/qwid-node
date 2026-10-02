package blocks

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"github.com/qwid-org/qwid-node/pubkeys"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

type stageBKey struct {
	s    oqs.Signature
	pub  []byte
	addr common.Address
}

func registeredStageBKey(t *testing.T) stageBKey {
	t.Helper()
	withBalanceTestDB(t)
	saved := pubkeys.GlobalMerkleTree
	pubkeys.InitPermanentTrie()
	t.Cleanup(func() { pubkeys.GlobalMerkleTree = saved })
	var k stageBKey
	if err := k.s.Init(common.SigName(), nil); err != nil {
		t.Skipf("liboqs unavailable: %v", err)
	}
	var err error
	if k.pub, err = k.s.GenerateKeyPair(); err != nil {
		t.Fatal(err)
	}
	if k.addr, err = common.PubKeyToAddress(k.pub, true); err != nil {
		t.Fatal(err)
	}
	var pk common.PubKey
	if err := pk.Init(k.pub, k.addr); err != nil {
		t.Fatal(err)
	}
	pk.MainAddress = k.addr
	if err := StorePubKey(pk); err != nil {
		t.Fatal(err)
	}
	if err := StorePubKeyInPatriciaTrie(pk); err != nil {
		t.Fatal(err)
	}
	return k
}

func (k stageBKey) sign(t *testing.T, tx *transactionsDefinition.Transaction) {
	t.Helper()
	if err := tx.CalcHashAndSet(); err != nil {
		t.Fatal(err)
	}
	raw, err := k.s.Sign(tx.Hash.GetBytes())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := common.GetSignatureFromBytes(append([]byte{0}, raw...), k.addr)
	if err != nil {
		t.Fatal(err)
	}
	tx.Signature = sig
}

func verifyNow(tx transactionsDefinition.Transaction) bool {
	return tx.Verify(common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2())
}

// S3-02: the token a DEX order trades is part of what the sender signs.
func TestDexTokenAddressIsSigned(t *testing.T) {
	k := registeredStageBKey(t)
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: k.addr, SendingTime: 1, Nonce: 1},
		TxData:  transactionsDefinition.TxData{Recipient: common.GetDelegatedAccountAddress(512 + 3), OptData: common.GetByteInt64(1000)},
		Height:  common.GetHeight(), GasPrice: 1, GasUsage: 300000, // above the DEX minimum incl. DexTokenCallGas (S6-03)
	}
	tx.ContractAddress.ByteValue[19] = 0xA1
	k.sign(t, &tx)
	if !verifyNow(tx) {
		t.Fatal("the honest DEX order does not verify")
	}
	variant := tx
	variant.ContractAddress.ByteValue[19] = 0xB2
	if verifyNow(variant) {
		t.Fatal("swapping the token of a signed DEX order kept the signature valid")
	}
}

// A contract's address written into the transaction after execution must not
// change its hash: for calls and deployments ContractAddress is an output.
func TestContractAddressOutputDoesNotChangeHashOfCalls(t *testing.T) {
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: testAddress(0x01), Nonce: 1},
		TxData:  transactionsDefinition.TxData{Recipient: common.EmptyAddress(), OptData: []byte{0x60, 0x00}},
		Height:  5, GasPrice: 1, GasUsage: 100000,
	}
	if err := tx.CalcHashAndSet(); err != nil {
		t.Fatal(err)
	}
	before := append([]byte{}, tx.Hash.GetBytes()...)
	tx.ContractAddress.ByteValue[19] = 0xC3 // what EvaluateSCForBlock records
	if !tx.HashMatchesBody() || !bytes.Equal(before, tx.Hash.GetBytes()) {
		t.Fatal("recording the deployed address changed the transaction's hash")
	}
}

func plainTransfer(k stageBKey, height, gasPrice, gasUsage int64) transactionsDefinition.Transaction {
	return transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: k.addr, SendingTime: 1, Nonce: 2},
		TxData:  transactionsDefinition.TxData{Recipient: testAddress(0x61), Amount: 5},
		Height:  height, GasPrice: gasPrice, GasUsage: gasUsage,
	}
}

// S4-01: Height=0 does not make an ordinary transaction a genesis one.
func TestHeightZeroGetsNoGenesisExemption(t *testing.T) {
	k := registeredStageBKey(t)
	tx := plainTransfer(k, 0, 0, 0)
	k.sign(t, &tx)
	if verifyNow(tx) {
		t.Fatal("a zero-fee transaction verified because it claims Height 0")
	}
	foreign := plainTransfer(k, 0, 1, 100000)
	foreign.TxParam.ChainID = 99
	k.sign(t, &foreign)
	if verifyNow(foreign) {
		t.Fatal("a foreign-chain transaction verified because it claims Height 0")
	}
}

// Genesis transactions keep verifying - through their own, explicit check.
func TestGenesisTransactionsVerifyExplicitly(t *testing.T) {
	k := registeredStageBKey(t)
	tx := plainTransfer(k, 0, 0, 0)
	k.sign(t, &tx)
	if !tx.VerifyGenesis(common.SigName(), common.SigName2(), false, false) {
		t.Fatal("a genesis transaction no longer verifies")
	}
	later := plainTransfer(k, 7, 0, 0)
	k.sign(t, &later)
	if later.VerifyGenesis(common.SigName(), common.SigName2(), false, false) {
		t.Fatal("VerifyGenesis accepted a transaction from height 7")
	}
}

// S4-04: a nonce-shaped transfer is not free in the pool - only nonce
// messages, verified as such, are exempt from gas.
func TestNonceShapedTransferIsNotFree(t *testing.T) {
	k := registeredStageBKey(t)
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: k.addr, SendingTime: 1, Nonce: 3},
		TxData:  transactionsDefinition.TxData{Recipient: common.GetDelegatedAccountAddress(5), OptData: make([]byte, 4096)},
		Height:  common.GetHeight(),
	}
	k.sign(t, &tx)
	if verifyNow(tx) {
		t.Fatal("a zero-fee nonce-shaped transaction verified as an ordinary transaction")
	}
	if !tx.VerifyNonce(common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2()) {
		t.Fatal("a nonce no longer verifies as a nonce")
	}
	notNonce := plainTransfer(k, common.GetHeight(), 0, 0)
	k.sign(t, &notNonce)
	if notNonce.VerifyNonce(common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2()) {
		t.Fatal("VerifyNonce accepted a transfer that is not nonce-shaped")
	}
}

// S4-03: while the primary scheme is paused, only a pure key registration
// (amount 0, no data, to itself) may still be signed with it.
func TestPauseExemptionCoversOnlyPureRegistration(t *testing.T) {
	k := registeredStageBKey(t)
	var pk common.PubKey
	if err := pk.Init(k.pub, k.addr); err != nil {
		t.Fatal(err)
	}
	pk.MainAddress = k.addr
	mk := func(recipient common.Address, opt []byte) transactionsDefinition.Transaction {
		tx := transactionsDefinition.Transaction{
			TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: k.addr, SendingTime: 1, Nonce: 4},
			TxData:  transactionsDefinition.TxData{Recipient: recipient, OptData: opt, Pubkey: pk},
			Height:  common.GetHeight(), GasPrice: 1, GasUsage: 1_000_000,
		}
		k.sign(t, &tx)
		return tx
	}
	const paused = true
	registration := mk(k.addr, nil)
	dex := mk(common.GetDelegatedAccountAddress(512+3), common.GetByteInt64(1_000_000))
	call := mk(testAddress(0x99), []byte{0xa9, 0x05, 0x9c, 0xbb})
	if !registration.Verify(common.SigName(), common.SigName2(), paused, !paused) {
		t.Fatal("a pure registration is refused while the primary is paused")
	}
	if dex.Verify(common.SigName(), common.SigName2(), paused, !paused) {
		t.Fatal("a DEX order was authorised by a paused scheme")
	}
	if call.Verify(common.SigName(), common.SigName2(), paused, !paused) {
		t.Fatal("a contract call was authorised by a paused scheme")
	}
}

// S4-02: the escrow delay runs from the block that includes the transfer, not
// from the Height its signer chose.
func TestEscrowDelayCountsFromInclusion(t *testing.T) {
	withBalanceTestDB(t)
	escrow, thief := testAddress(0x71), testAddress(0x72)
	account.Accounts = account.AccountsType{AllAccounts: map[[common.AddressLength]byte]account.Account{
		escrow.ByteValue: {Address: escrow.ByteValue, Balance: 1_000_000, TransactionDelay: 60480},
		thief.ByteValue:  {Address: thief.ByteValue},
	}}
	t.Cleanup(func() { transactionsPool.PoolTxEscrow.Clear() })
	backdated := transferTx(t, escrow, thief, 900_000, common.Hash{}, 2)
	backdated.Height = 0
	if err := ProcessTransaction(backdated, 200_000, 0); err != nil {
		t.Fatal(err)
	}
	if got := balanceOf(t, thief); got != 0 {
		t.Fatalf("a back-dated escrow transfer paid out %d immediately", got)
	}
}

// S4-01: a block may only include transactions whose Height lies in the
// recent window; anything else is a replay or a forged exemption.
func TestBlockRejectsTransactionOutsideHeightWindow(t *testing.T) {
	withBalanceTestDB(t)
	sender := testAddress(0x73)
	account.Accounts = account.AccountsType{AllAccounts: map[[common.AddressLength]byte]account.Account{
		sender.ByteValue: {Address: sender.ByteValue, Balance: 1_000_000_000},
	}}
	const blockHeight = 100_000
	check := func(txHeight int64) error {
		tx := transferTx(t, sender, testAddress(0x74), 5, common.Hash{}, byte(txHeight%250))
		tx.Height = txHeight
		if err := tx.CalcHashAndSet(); err != nil {
			t.Fatal(err)
		}
		if err := tx.StoreToDBPoolTx(common.TransactionPoolHashesDBPrefix[:]); err != nil {
			t.Fatal(err)
		}
		last := Block{BaseBlock: BaseBlock{BaseHeader: BaseHeader{Height: blockHeight - 1}, Supply: 1_000_000_000_000}}
		blk := Block{
			BaseBlock:          BaseBlock{BaseHeader: BaseHeader{Height: blockHeight}, Supply: last.GetBlockSupply() + account.GetReward(last.GetBlockSupply())},
			TransactionsHashes: []common.Hash{tx.Hash},
		}
		_, _, err := CheckBlockTransfers(blk, last, nil, true)
		return err
	}
	if err := check(blockHeight - 1); err != nil {
		t.Fatalf("a fresh transaction was rejected: %v", err)
	}
	if check(0) == nil {
		t.Fatal("a transaction claiming Height 0 was accepted at height 100000")
	}
	if check(blockHeight+5) == nil {
		t.Fatal("a transaction from the future was accepted")
	}
}
