package blocks

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

func rootNow(t *testing.T) common.Hash {
	t.Helper()
	h, err := ComputeStateRoot()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestStateRootCoversRecoveryState(t *testing.T) {
	a := testAddress(0x31)
	account.Accounts = account.AccountsType{AllAccounts: map[[common.AddressLength]byte]account.Account{
		a.ByteValue: {Address: a.ByteValue, Balance: 1},
	}}
	r0 := rootNow(t)

	acc := account.Accounts.AllAccounts[a.ByteValue]
	acc.RecoveryPendingCommit[0] = 1
	account.Accounts.AllAccounts[a.ByteValue] = acc
	r1 := rootNow(t)
	if r1 == r0 {
		t.Fatal("pending recovery commitment not in the state root")
	}

	account.AddRecoveryBind([32]byte{9}, account.RecoveryBind{Identity: a.ByteValue, Height: 5})
	if rootNow(t) == r1 {
		t.Fatal("recovery bind not in the state root")
	}
}

func recoverySecret(b byte) []byte { return bytes.Repeat([]byte{b}, common.RecoverySecretLength) }

func freshPrimaryKey(t *testing.T) stageBKey {
	t.Helper()
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
	return k
}

type recoveryFixture struct {
	owner  stageBKey
	newKey stageBKey
	secret []byte
	next   common.Address
}

// newRecoveryFixture: a funded identity holding both keys, whose active
// recovery commitment opens with recoverySecret(1).
func newRecoveryFixture(t *testing.T) recoveryFixture {
	t.Helper()
	owner := registeredStageBKey(t)
	fund(owner.addr)
	f := recoveryFixture{owner: owner, newKey: freshPrimaryKey(t), secret: recoverySecret(1)}
	f.next, _ = common.RecoveryCommitment(recoverySecret(2))
	c, err := common.RecoveryCommitment(f.secret)
	if err != nil {
		t.Fatal(err)
	}
	acc := account.Accounts.AllAccounts[owner.addr.ByteValue]
	acc.RecoveryCommit = c.ByteValue
	account.Accounts.AllAccounts[owner.addr.ByteValue] = acc
	return f
}

// bindFor records a bind of secret for newKey, `age` blocks old at the height
// the next block is judged at.
func (f recoveryFixture) bindFor(t *testing.T, secret []byte, newKey common.Address, age int64) bool {
	t.Helper()
	tag, _ := common.RecoveryTag(secret)
	payload, _ := common.RecoveryPayload(f.owner.addr, newKey, f.next, secret)
	return account.AddRecoveryBind(common.RecoveryBindKey(f.owner.addr, tag), account.RecoveryBind{
		Identity: f.owner.addr.ByteValue, Payload: payload, Height: common.GetHeight() + 1 - age,
	})
}

func (f recoveryFixture) reveal(t *testing.T, secret []byte, key, signer stageBKey) transactionsDefinition.Transaction {
	t.Helper()
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: f.owner.addr, SendingTime: 1, Nonce: 11},
		TxData: transactionsDefinition.TxData{
			Recipient: common.RecoveryRevealAddress,
			OptData:   transactionsDefinition.BuildRecoveryRevealOptData(secret, f.next),
			Pubkey:    enclosed(t, key, f.owner.addr, true),
		},
		Height: common.GetHeight(), GasPrice: 1, GasUsage: 1_000_000,
	}
	signIn(t, &tx, signer, true)
	return tx
}

// Both of the identity's schemes may be broken: the reveal needs neither.
func TestRevealRegistersNewKeyWhileItsSchemeIsPaused(t *testing.T) {
	f := newRecoveryFixture(t)
	f.bindFor(t, f.secret, f.newKey.addr, common.RecoveryBindDelayBlocks)
	tx := f.reveal(t, f.secret, f.newKey, f.newKey)
	if !tx.Verify(common.SigName(), common.SigName2(), true, true) {
		t.Fatal("a valid reveal was refused")
	}
}

func TestRevealRejectsSecretThatDoesNotOpenTheCommitment(t *testing.T) {
	f := newRecoveryFixture(t)
	wrong := recoverySecret(3)
	f.bindFor(t, wrong, f.newKey.addr, common.RecoveryBindDelayBlocks)
	if verifyNow(f.reveal(t, wrong, f.newKey, f.newKey)) {
		t.Fatal("a secret that does not open the commitment was accepted")
	}
}

func TestRevealNeedsAMaturedBind(t *testing.T) {
	f := newRecoveryFixture(t)
	f.bindFor(t, f.secret, f.newKey.addr, common.RecoveryBindDelayBlocks-1)
	if verifyNow(f.reveal(t, f.secret, f.newKey, f.newKey)) {
		t.Fatal("reveal accepted before its bind matured")
	}
}

func TestRevealRejectsExpiredBind(t *testing.T) {
	f := newRecoveryFixture(t)
	f.bindFor(t, f.secret, f.newKey.addr, common.RecoveryBindExpiryBlocks+1)
	if verifyNow(f.reveal(t, f.secret, f.newKey, f.newKey)) {
		t.Fatal("reveal accepted against an expired bind")
	}
}

// The attacker sees S in the mempool and binds its own key: too late, the
// first bind per tag wins and its payload names the owner's key.
func TestMempoolCopyOfSecretCannotRedirectTheReveal(t *testing.T) {
	f := newRecoveryFixture(t)
	f.bindFor(t, f.secret, f.newKey.addr, common.RecoveryBindDelayBlocks)
	attacker := freshPrimaryKey(t)
	if f.bindFor(t, f.secret, attacker.addr, common.RecoveryBindExpiryBlocks) {
		t.Fatal("a second bind for the same tag replaced the first")
	}
	if verifyNow(f.reveal(t, f.secret, attacker, attacker)) {
		t.Fatal("the attacker's key was registered with the owner's secret")
	}
}

func TestRevealMustBeSignedByTheRevealedKey(t *testing.T) {
	f := newRecoveryFixture(t)
	f.bindFor(t, f.secret, f.newKey.addr, common.RecoveryBindDelayBlocks)
	if verifyNow(f.reveal(t, f.secret, f.newKey, f.owner)) {
		t.Fatal("a reveal signed by another key was accepted")
	}
}

// Setting a commitment is the one registration a paused scheme may never sign.
func TestCommitmentRegistrationNeedsALiveScheme(t *testing.T) {
	owner := registeredStageBKey(t)
	c, _ := common.RecoveryCommitment(recoverySecret(5))
	reg := pureRegistration(t, owner.addr, enclosed(t, owner, owner.addr, true), owner, true)
	reg.TxData.Recipient = c
	signIn(t, &reg, owner, true)
	if !reg.Verify(common.SigName(), common.SigName2(), false, true) {
		t.Fatal("live primary could not set a commitment")
	}
	if reg.Verify(common.SigName(), common.SigName2(), true, false) {
		t.Fatal("a paused primary set a recovery commitment")
	}
}

func TestBootstrapUnderPauseCannotCarryACommitment(t *testing.T) {
	registeredStageBKey(t) // fresh registry
	k := freshPrimaryKey(t)
	c, _ := common.RecoveryCommitment(recoverySecret(6))
	reg := pureRegistration(t, k.addr, enclosed(t, k, k.addr, true), k, true)
	reg.TxData.Recipient = c
	signIn(t, &reg, k, true)
	if reg.Verify(common.SigName(), common.SigName2(), true, false) {
		t.Fatal("a bootstrap signed under a pause planted a commitment")
	}
}

func TestBindShape(t *testing.T) {
	payer := registeredStageBKey(t)
	fund(payer.addr)
	mk := func(amount int64, opt []byte) transactionsDefinition.Transaction {
		tx := transactionsDefinition.Transaction{
			TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: payer.addr, SendingTime: 1, Nonce: 12},
			TxData:  transactionsDefinition.TxData{Recipient: common.RecoveryBindAddress, Amount: amount, OptData: opt},
			Height:  common.GetHeight(), GasPrice: 1, GasUsage: 1_000_000,
		}
		signIn(t, &tx, payer, true)
		return tx
	}
	good := transactionsDefinition.BuildRecoveryBindOptData(testAddress(0x77), [32]byte{1}, [32]byte{2})
	if !verifyNow(mk(0, good)) {
		t.Fatal("a well-formed bind was refused")
	}
	if verifyNow(mk(5, good)) {
		t.Fatal("a bind moving coins was accepted")
	}
	if verifyNow(mk(0, good[:10])) {
		t.Fatal("a truncated bind was accepted")
	}
}

func TestCommitmentRegistrationSetsPendingWithoutCreatingAccount(t *testing.T) {
	owner := registeredStageBKey(t)
	fund(owner.addr)
	c, _ := common.RecoveryCommitment(recoverySecret(5))
	reg := pureRegistration(t, owner.addr, enclosed(t, owner, owner.addr, true), owner, true)
	reg.TxData.Recipient = c
	signIn(t, &reg, owner, true)
	before := balanceOf(t, owner.addr)
	if err := ProcessTransaction(reg, 100, 0); err != nil {
		t.Fatal(err)
	}
	acc, _ := account.GetAccountByAddressBytes(owner.addr.GetBytes())
	if acc.RecoveryPendingCommit != c.ByteValue || acc.RecoveryPendingHeight != 100 {
		t.Fatalf("pending commitment not set: %+v", acc)
	}
	if _, exists := account.GetAccountByAddressBytes(c.GetBytes()); exists {
		t.Fatal("an account was created for the commitment address")
	}
	if balanceOf(t, owner.addr) >= before {
		t.Fatal("no fee charged")
	}
}

func TestBindApplyKeepsTheFirst(t *testing.T) {
	payer := registeredStageBKey(t)
	fund(payer.addr)
	id := testAddress(0x77)
	mk := func(payload byte, nonce int64) transactionsDefinition.Transaction {
		tx := transactionsDefinition.Transaction{
			TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: payer.addr, SendingTime: 1, Nonce: nonce},
			TxData: transactionsDefinition.TxData{Recipient: common.RecoveryBindAddress,
				OptData: transactionsDefinition.BuildRecoveryBindOptData(id, [32]byte{1}, [32]byte{payload})},
			Height: 100, GasPrice: 1, GasUsage: 1_000_000,
		}
		signIn(t, &tx, payer, true)
		return tx
	}
	if err := ProcessTransaction(mk(1, 1), 100, 0); err != nil {
		t.Fatal(err)
	}
	if err := ProcessTransaction(mk(2, 2), 101, 0); err != nil {
		t.Fatal(err)
	}
	b, ok := account.GetRecoveryBind(common.RecoveryBindKey(id, [32]byte{1}))
	if !ok || b.Payload != ([32]byte{1}) || b.Height != 100 {
		t.Fatalf("first bind not kept: %+v", b)
	}
}

func TestRevealConsumesCommitmentAndBind(t *testing.T) {
	f := newRecoveryFixture(t)
	f.bindFor(t, f.secret, f.newKey.addr, common.RecoveryBindDelayBlocks)
	tx := f.reveal(t, f.secret, f.newKey, f.newKey)
	if err := ProcessTransaction(tx, common.GetHeight()+1, 0); err != nil {
		t.Fatal(err)
	}
	acc, _ := account.GetAccountByAddressBytes(f.owner.addr.GetBytes())
	if acc.RecoveryCommit != f.next.ByteValue {
		t.Fatal("reveal did not install the next commitment")
	}
	tag, _ := common.RecoveryTag(f.secret)
	if _, ok := account.GetRecoveryBind(common.RecoveryBindKey(f.owner.addr, tag)); ok {
		t.Fatal("consumed bind kept")
	}
}

func TestRevealFailsIfCommitmentChangedFirst(t *testing.T) {
	f := newRecoveryFixture(t)
	f.bindFor(t, f.secret, f.newKey.addr, common.RecoveryBindDelayBlocks)
	tx := f.reveal(t, f.secret, f.newKey, f.newKey)
	other, _ := common.RecoveryCommitment(recoverySecret(9))
	if err := account.ConsumeAccountRecoveryCommit(f.owner.addr.ByteValue, other.ByteValue); err != nil {
		t.Fatal(err)
	}
	if err := ProcessTransaction(tx, common.GetHeight()+1, 0); err == nil {
		t.Fatal("a reveal applied against a commitment that changed earlier in the block")
	}
}

func TestRecoveryTransactionsAreNotContractCalls(t *testing.T) {
	for _, r := range []common.Address{common.RecoveryBindAddress, common.RecoveryRevealAddress} {
		tx := transactionsDefinition.Transaction{TxData: transactionsDefinition.TxData{Recipient: r, OptData: []byte{1}}}
		if isContractCallTx(tx, account.Account{}, 1) {
			t.Fatalf("%s routed to the EVM", r.GetHex())
		}
	}
}

func TestFilterKeepsOneRevealPerIdentity(t *testing.T) {
	id := testAddress(0x42)
	mk := func(nonce int64) transactionsDefinition.Transaction {
		tx := transactionsDefinition.Transaction{
			TxParam: transactionsDefinition.TxParam{Sender: id, Nonce: nonce},
			TxData:  transactionsDefinition.TxData{Recipient: common.RecoveryRevealAddress},
			Height:  100,
		}
		_ = tx.CalcHashAndSet()
		return tx
	}
	if got := FilterUnbuildableTransactions([]transactionsDefinition.Transaction{mk(1), mk(2)}, 100); len(got) != 1 {
		t.Fatalf("kept %d reveals for one identity, want 1", len(got))
	}
}

// A pending commitment is voided only when a block marks a scheme as broken:
// the primary paused, or the spare replaced. Replacing an already-paused
// primary or un-pausing changes nothing about which key could have been
// forged, so those must keep it - otherwise the commitments users set with
// the live spare right after a break would be voided again by the very
// changes that follow it (replace, un-pause), which can come blocks apart.
func TestMaintenanceVoidsPendingOnlyOnBreakage(t *testing.T) {
	logger.InitLogger()
	withBalanceTestDB(t)
	mlDSA44 := encCfg(t, "ML-DSA-44", 1312, 2560, 2420, true)
	cases := []struct {
		name         string
		parent, next [2][]byte
		voids        bool
	}{
		{"no change", [2][]byte{falcon512(t, false), mayo5(t)}, [2][]byte{falcon512(t, false), mayo5(t)}, false},
		{"primary paused", [2][]byte{falcon512(t, false), mayo5(t)}, [2][]byte{falcon512(t, true), mayo5(t)}, true},
		{"paused primary replaced", [2][]byte{falcon512(t, true), mayo5(t)}, [2][]byte{falcon1024(t, true), mayo5(t)}, false},
		{"primary un-paused", [2][]byte{falcon1024(t, true), mayo5(t)}, [2][]byte{falcon1024(t, false), mayo5(t)}, false},
		{"spare replaced", [2][]byte{falcon512(t, false), mayo5(t)}, [2][]byte{falcon512(t, false), mlDSA44}, true},
	}
	for _, c := range cases {
		a := testAddress(0x51)
		account.Accounts = account.AccountsType{AllAccounts: map[[common.AddressLength]byte]account.Account{
			a.ByteValue: {Address: a.ByteValue, RecoveryPendingCommit: [common.AddressLength]byte{1}, RecoveryPendingHeight: 100},
		}}
		applyRecoveryMaintenance(blockWithEnc(101, c.next[0], c.next[1]), blockWithEnc(100, c.parent[0], c.parent[1]))
		voided := account.Accounts.AllAccounts[a.ByteValue].RecoveryPendingCommit == ([common.AddressLength]byte{})
		if voided != c.voids {
			t.Errorf("%s: voided=%v, want %v", c.name, voided, c.voids)
		}
	}
}

// A commitment change hands over control of the account after a scheme break,
// so it is exactly as important as a transfer: an escrow account must get its
// delay and the chance to cancel, a multisig account its approvals. It used to
// be set at inclusion for every account, its maturity counted from there.

func commitmentRegistration(t *testing.T, owner stageBKey, c common.Address, nonce int64) transactionsDefinition.Transaction {
	t.Helper()
	reg := pureRegistration(t, owner.addr, enclosed(t, owner, owner.addr, true), owner, true)
	reg.TxParam.Nonce = nonce
	reg.TxData.Recipient = c
	signIn(t, &reg, owner, true)
	return reg
}

func withAccountPolicy(t *testing.T, a common.Address, delay int64, signers ...common.Address) {
	t.Helper()
	acc := account.Accounts.AllAccounts[a.ByteValue]
	acc.TransactionDelay = delay
	for _, s := range signers {
		acc.MultiSignAddresses = append(acc.MultiSignAddresses, s.ByteValue)
	}
	acc.MultiSignNumber = uint8(len(signers))
	account.Accounts.AllAccounts[a.ByteValue] = acc
}

func freshPolicyPools(t *testing.T) {
	t.Helper()
	savedE, savedM := transactionsPool.PoolTxEscrow, transactionsPool.PoolTxMultiSign
	transactionsPool.PoolTxEscrow = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 1)
	transactionsPool.PoolTxMultiSign = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 2)
	t.Cleanup(func() { transactionsPool.PoolTxEscrow, transactionsPool.PoolTxMultiSign = savedE, savedM })
}

func pendingCommit(a common.Address) ([common.AddressLength]byte, int64) {
	acc, _ := account.GetAccountByAddressBytes(a.GetBytes())
	return acc.RecoveryPendingCommit, acc.RecoveryPendingHeight
}

func TestEscrowCommitmentAppliesWhenTheDelayEnds(t *testing.T) {
	owner := registeredStageBKey(t)
	fund(owner.addr)
	freshPolicyPools(t)
	withAccountPolicy(t, owner.addr, 10)
	c, _ := common.RecoveryCommitment(recoverySecret(5))
	reg := commitmentRegistration(t, owner, c, 21)

	if err := ProcessTransaction(reg, 100, 0); err != nil {
		t.Fatal(err)
	}
	if p, _ := pendingCommit(owner.addr); p != ([common.AddressLength]byte{}) {
		t.Fatal("an escrow account's commitment was set at inclusion, before its delay")
	}
	if !transactionsPool.PoolTxEscrow.HasTransaction(reg.Hash.GetBytes()) {
		t.Fatal("the commitment change is not held in escrow")
	}
	_ = ProcessTransactionsEscrow(109, nil)
	if p, _ := pendingCommit(owner.addr); p != ([common.AddressLength]byte{}) {
		t.Fatal("the commitment applied before the escrow delay ended")
	}
	_ = ProcessTransactionsEscrow(110, nil)
	if p, h := pendingCommit(owner.addr); p != c.ByteValue || h != 110 {
		t.Fatalf("after the delay: pending %x at %d, want the commitment maturing from 110", p, h)
	}
	if _, exists := account.GetAccountByAddressBytes(c.GetBytes()); exists {
		t.Fatal("settlement created an account for the commitment address")
	}
}

// Cancelling the escrow entry (what validateEscrowCancellation authorises
// removes it from the pool) must leave the commitment unchanged.
func TestCancelledEscrowCommitmentNeverApplies(t *testing.T) {
	owner := registeredStageBKey(t)
	fund(owner.addr)
	freshPolicyPools(t)
	withAccountPolicy(t, owner.addr, 10)
	c, _ := common.RecoveryCommitment(recoverySecret(6))
	reg := commitmentRegistration(t, owner, c, 22)
	if err := ProcessTransaction(reg, 100, 0); err != nil {
		t.Fatal(err)
	}
	transactionsPool.RemoveEscrowTransaction(reg.Hash.GetBytes())
	_ = ProcessTransactionsEscrow(200, nil)
	if p, _ := pendingCommit(owner.addr); p != ([common.AddressLength]byte{}) {
		t.Fatal("a cancelled commitment change applied")
	}
}

func TestMultiSignCommitmentNeedsItsApprovals(t *testing.T) {
	owner := registeredStageBKey(t)
	signer := testAddress(0x61)
	fund(owner.addr, signer)
	freshPolicyPools(t)
	withAccountPolicy(t, owner.addr, 0, signer)
	c, _ := common.RecoveryCommitment(recoverySecret(7))
	reg := commitmentRegistration(t, owner, c, 23)

	if err := ProcessTransaction(reg, 100, 0); err != nil {
		t.Fatal(err)
	}
	if p, _ := pendingCommit(owner.addr); p != ([common.AddressLength]byte{}) {
		t.Fatal("a multisig account's commitment was set without approvals")
	}
	approval := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: signer, SendingTime: 1, Nonce: 24, MultiSignTx: reg.Hash},
		TxData:  transactionsDefinition.TxData{Recipient: c},
		Height:  101, GasPrice: 1, GasUsage: 1,
	}
	if err := approval.CalcHashAndSet(); err != nil {
		t.Fatal(err)
	}
	if err := ProcessTransaction(approval, 101, 0); err != nil {
		t.Fatal(err)
	}
	if err := ProcessTransactionsMultiSign(approval, 101, nil); err != nil {
		t.Fatal(err)
	}
	if p, h := pendingCommit(owner.addr); p != c.ByteValue || h != 101 {
		t.Fatalf("after the approval: pending %x at %d, want the commitment maturing from 101", p, h)
	}
}
