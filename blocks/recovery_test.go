package blocks

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/pubkeys"
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

	acc = account.Accounts.AllAccounts[a.ByteValue]
	acc.SparePendingCommit[0] = 1
	account.Accounts.AllAccounts[a.ByteValue] = acc
	r2 := rootNow(t)
	if r2 == r1 {
		t.Fatal("pending spare commitment not in the state root")
	}

	account.AddRecoveryBind([32]byte{9}, account.RecoveryBind{Identity: a.ByteValue, Height: 5})
	if rootNow(t) == r2 {
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
	return account.AddRecoveryBind(common.RecoveryBindKey(f.owner.addr, tag, payload), account.RecoveryBind{
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

// The attacker sees S in the owner's reveal in the mempool and binds its own
// key. That bind is valid - it was made with S - but it is new: it cannot be
// revealed for RecoveryBindDelayBlocks, and the owner's reveal, whose bind
// already matured, consumes the commitment first.
func TestMempoolCopyOfSecretCannotRedirectTheReveal(t *testing.T) {
	f := newRecoveryFixture(t)
	f.bindFor(t, f.secret, f.newKey.addr, common.RecoveryBindDelayBlocks)
	attacker := freshPrimaryKey(t)
	if !f.bindFor(t, f.secret, attacker.addr, 0) {
		t.Fatal("setup: the attacker's bind was not stored")
	}
	theft := f.reveal(t, f.secret, attacker, attacker)
	if verifyNow(theft) {
		t.Fatal("a bind made after the secret became public was revealed at once")
	}
	if err := ProcessTransaction(f.reveal(t, f.secret, f.newKey, f.newKey), common.GetHeight()+1, 0); err != nil {
		t.Fatal(err)
	}
	// However long the attacker waits now, the secret opens nothing.
	acc := account.Accounts.AllAccounts[f.owner.addr.ByteValue]
	if c, _ := common.RecoveryCommitment(f.secret); acc.EffectiveRecoveryCommit(1<<40) == c.ByteValue {
		t.Fatal("the owner's reveal left the revealed commitment in force")
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

// The registration that opens an account points at its spare key's address
// (Recipient) and carries the recovery commitment (OptData). Both apply at
// once - there is nothing earlier to protect - and neither address gets an
// account of its own.
func TestOpeningCommitmentsApplyWithoutCreatingAccounts(t *testing.T) {
	owner := registeredStageBKey(t)
	fund(owner.addr)
	spare := secondaryKey(t)
	c, _ := common.RecoveryCommitment(recoverySecret(5))
	reg := commitmentRegistration(t, owner, spare.addr, &c, 31)
	// The account is opened by this block: its keys were not public before.
	for _, k := range []common.Address{owner.addr, owner.spare.addr} {
		if err := pubkeys.StoreRegistrationHeight(k, 100); err != nil {
			t.Fatal(err)
		}
	}
	before := balanceOf(t, owner.addr)
	if err := ProcessTransaction(reg, 100, 0); err != nil {
		t.Fatal(err)
	}
	acc, _ := account.GetAccountByAddressBytes(owner.addr.GetBytes())
	if acc.SpareCommit != spare.addr.ByteValue || acc.RecoveryCommit != c.ByteValue {
		t.Fatalf("opening commitments not applied: spare %x recovery %x", acc.SpareCommit, acc.RecoveryCommit)
	}
	for _, a := range []common.Address{spare.addr, c} {
		if _, exists := account.GetAccountByAddressBytes(a.GetBytes()); exists {
			t.Fatalf("an account was created for %s", a.GetHex())
		}
	}
	if balanceOf(t, owner.addr) >= before {
		t.Fatal("no fee charged")
	}
}

// Binds of one tag with different payloads sit side by side (P-03); repeating
// a bind keeps the first, so its age cannot be reset.
func TestBindApplyKeepsEachPayloadsFirst(t *testing.T) {
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
	for i, step := range []struct {
		payload byte
		height  int64
	}{{1, 100}, {2, 101}, {1, 102}} {
		if err := ProcessTransaction(mk(step.payload, int64(i+1)), step.height, 0); err != nil {
			t.Fatal(err)
		}
	}
	for payload, height := range map[byte]int64{1: 100, 2: 101} {
		b, ok := account.GetRecoveryBind(common.RecoveryBindKey(id, [32]byte{1}, [32]byte{payload}))
		if !ok || b.Payload != ([32]byte{payload}) || b.Height != height {
			t.Fatalf("bind with payload %d: %+v (stored %v), want it from height %d", payload, b, ok, height)
		}
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
	payload, _ := common.RecoveryPayload(f.owner.addr, f.newKey.addr, f.next, f.secret)
	if _, ok := account.GetRecoveryBind(common.RecoveryBindKey(f.owner.addr, tag, payload)); ok {
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

// commitmentRegistration re-registers owner's primary key as a commitment
// registration: the spare key's address and, if given, the recovery
// commitment.
func commitmentRegistration(t *testing.T, owner stageBKey, spare common.Address, recovery *common.Address, nonce int64) transactionsDefinition.Transaction {
	t.Helper()
	reg := pureRegistration(t, owner.addr, enclosed(t, owner, owner.addr, true), owner, true)
	reg.TxParam.Nonce = nonce
	var rec []byte
	if recovery != nil {
		rec = recovery.GetBytes()
	}
	reg.TxData.Recipient, reg.TxData.OptData = transactionsDefinition.CommitmentRegistration(spare, rec)
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

// spareCommitAt is the spare commitment in force for a at height h.
func spareCommitAt(a common.Address, h int64) [common.AddressLength]byte {
	acc, _ := account.GetAccountByAddressBytes(a.GetBytes())
	return acc.EffectiveSpareCommit(h)
}

func TestEscrowCommitmentAppliesWhenTheDelayEnds(t *testing.T) {
	owner := registeredStageBKey(t)
	fund(owner.addr)
	freshPolicyPools(t)
	withAccountPolicy(t, owner.addr, 10)
	c, _ := common.RecoveryCommitment(recoverySecret(5))
	reg := commitmentRegistration(t, owner, c, nil, 21)

	if err := ProcessTransaction(reg, 100, 0); err != nil {
		t.Fatal(err)
	}
	if p := spareCommitAt(owner.addr, 1<<40); p != ([common.AddressLength]byte{}) {
		t.Fatal("an escrow account's commitment was set at inclusion, before its delay")
	}
	if !transactionsPool.PoolTxEscrow.HasTransaction(reg.Hash.GetBytes()) {
		t.Fatal("the commitment change is not held in escrow")
	}
	_ = ProcessTransactionsEscrow(109, nil)
	if p := spareCommitAt(owner.addr, 1<<40); p != ([common.AddressLength]byte{}) {
		t.Fatal("the commitment applied before the escrow delay ended")
	}
	_ = ProcessTransactionsEscrow(110, nil)
	if p := spareCommitAt(owner.addr, 110+common.RecoveryCommitMaturityBlocks-1); p != ([common.AddressLength]byte{}) {
		t.Fatal("a settled escrow commitment applied before maturing")
	}
	if p := spareCommitAt(owner.addr, 110+common.RecoveryCommitMaturityBlocks); p != c.ByteValue {
		t.Fatalf("the settled commitment is %x, want it to mature counting from 110", p)
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
	reg := commitmentRegistration(t, owner, c, nil, 22)
	if err := ProcessTransaction(reg, 100, 0); err != nil {
		t.Fatal(err)
	}
	transactionsPool.RemoveEscrowTransaction(reg.Hash.GetBytes())
	_ = ProcessTransactionsEscrow(200, nil)
	if p := spareCommitAt(owner.addr, 1<<40); p != ([common.AddressLength]byte{}) {
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
	reg := commitmentRegistration(t, owner, c, nil, 23)

	if err := ProcessTransaction(reg, 100, 0); err != nil {
		t.Fatal(err)
	}
	if p := spareCommitAt(owner.addr, 1<<40); p != ([common.AddressLength]byte{}) {
		t.Fatal("a multisig account's commitment was set without approvals")
	}
	approval := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: signer, SendingTime: 1, Nonce: 24, MultiSignTx: reg.Hash},
		TxData:  transactionsDefinition.TxData{Recipient: common.RecoveryCommitAddress, OptData: reg.TxData.OptData},
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
	if p := spareCommitAt(owner.addr, 101+common.RecoveryCommitMaturityBlocks-1); p != ([common.AddressLength]byte{}) {
		t.Fatal("an approved commitment applied before maturing")
	}
	if p := spareCommitAt(owner.addr, 101+common.RecoveryCommitMaturityBlocks); p != c.ByteValue {
		t.Fatalf("the approved commitment is %x, want it to mature counting from 101", p)
	}
}

// The second-key rule asks for a way out, not for two published keys: an
// account that committed to its spare key's ADDRESS may send, with the spare's
// public key still unpublished - an attacker who breaks a scheme has nothing
// of it to work on.
func TestSpareCommitmentReplacesTheSecondKey(t *testing.T) {
	owner := primaryOnlyStageBKey(t)
	fund(owner.addr)
	transfer := signedTx(t, owner, testAddress(0x55), 1, common.GetHeight(), 3)
	if verifyNow(transfer) {
		t.Fatal("an account with one key and no spare commitment sent a transfer")
	}
	spare := secondaryKey(t)
	acc := account.Accounts.AllAccounts[owner.addr.ByteValue]
	acc.SpareCommit = spare.addr.ByteValue
	account.Accounts.AllAccounts[owner.addr.ByteValue] = acc
	if !verifyNow(transfer) {
		t.Fatal("an account with a key and a spare commitment could not send")
	}
}

// With the primary paused, the committed spare registers itself: matching the
// committed address is the authority, so no (paused) key has to vouch for it.
// Any other key gets nothing from this path.
func TestCommittedSpareRegistersItselfUnderPause(t *testing.T) {
	owner := primaryOnlyStageBKey(t)
	fund(owner.addr)
	spare := secondaryKey(t)
	acc := account.Accounts.AllAccounts[owner.addr.ByteValue]
	acc.SpareCommit = spare.addr.ByteValue
	account.Accounts.AllAccounts[owner.addr.ByteValue] = acc

	reveal := pureRegistration(t, owner.addr, enclosed(t, spare, owner.addr, false), spare, false)
	if !reveal.Verify(common.SigName(), common.SigName2(), primaryPaused, secondaryLive) {
		t.Fatal("the committed spare could not register itself while the primary is paused")
	}
	other := secondaryKey(t)
	forged := pureRegistration(t, owner.addr, enclosed(t, other, owner.addr, false), other, false)
	if forged.Verify(common.SigName(), common.SigName2(), primaryPaused, secondaryLive) {
		t.Fatal("a key that is not the committed spare registered itself")
	}
}

// Opening an account that never registered a key, by revealing the key its
// address is the hash of - even when the chain no longer uses that key's
// scheme. Bind first, then reveal with a new key of a current scheme; the old
// key also signs, so knowing its public key (published elsewhere) is not
// enough.

type addressOpening struct {
	id     common.Address
	old    stageBKey
	newKey stageBKey
	next   common.Address
	spare  common.Address
}

func newAddressOpening(t *testing.T) addressOpening {
	t.Helper()
	registeredStageBKey(t) // fresh registry; its own key plays no part
	o := addressOpening{old: freshPrimaryKey(t), newKey: secondaryKey(t), spare: secondaryKey(t).addr}
	o.id = o.old.addr
	o.next, _ = common.RecoveryCommitment(recoverySecret(4))
	fund(o.id)
	return o
}

func (o addressOpening) oldSignature(t *testing.T, signer stageBKey) []byte {
	t.Helper()
	msg, err := common.AddressOpenMessage(o.id, o.newKey.addr, o.next, o.spare)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func (o addressOpening) bind(t *testing.T, oldPub []byte, newKey common.Address, age int64) bool {
	t.Helper()
	tag, _ := common.RecoveryTag(oldPub)
	payload, _ := common.AddressOpenPayload(o.id, newKey, o.next, o.spare, oldPub)
	return account.AddRecoveryBind(common.RecoveryBindKey(o.id, tag, payload), account.RecoveryBind{
		Identity: o.id.ByteValue, Payload: payload, Height: common.GetHeight() + 1 - age,
	})
}

func (o addressOpening) reveal(t *testing.T, old stageBKey, oldSig []byte, newKey stageBKey) transactionsDefinition.Transaction {
	t.Helper()
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: o.id, SendingTime: 1, Nonce: 41},
		TxData: transactionsDefinition.TxData{
			Recipient: common.RecoveryRevealAddress,
			OptData: transactionsDefinition.BuildAddressRevealOptData(transactionsDefinition.AddressReveal{
				Next: o.next, Spare: o.spare, OldScheme: common.SigName(), OldPub: old.pub, OldSig: oldSig,
			}),
			Pubkey: enclosed(t, newKey, o.id, false),
		},
		Height: common.GetHeight(), GasPrice: 1, GasUsage: 2_000_000,
	}
	signIn(t, &tx, newKey, false)
	return tx
}

func TestAddressRevealOpensAnUnregisteredAccount(t *testing.T) {
	o := newAddressOpening(t)
	o.bind(t, o.old.pub, o.newKey.addr, common.RecoveryBindDelayBlocks)
	tx := o.reveal(t, o.old, o.oldSignature(t, o.old), o.newKey)
	if !verifyNow(tx) {
		t.Fatal("a valid address opening was refused")
	}
	if err := ProcessTransaction(tx, common.GetHeight()+1, 0); err != nil {
		t.Fatal(err)
	}
	acc, _ := account.GetAccountByAddressBytes(o.id.GetBytes())
	if acc.RecoveryCommit != o.next.ByteValue || acc.SpareCommit != o.spare.ByteValue {
		t.Fatal("the opening did not install the account's commitments")
	}
	tag, _ := common.RecoveryTag(o.old.pub)
	payload, _ := common.AddressOpenPayload(o.id, o.newKey.addr, o.next, o.spare, o.old.pub)
	if _, ok := account.GetRecoveryBind(common.RecoveryBindKey(o.id, tag, payload)); ok {
		t.Fatal("the consumed bind was kept")
	}
}

// Knowing the old public key is not enough: it may have been published (on a
// previous chain, say), so the old key must sign too.
func TestAddressRevealNeedsTheOldKeysSignature(t *testing.T) {
	o := newAddressOpening(t)
	o.bind(t, o.old.pub, o.newKey.addr, common.RecoveryBindDelayBlocks)
	if verifyNow(o.reveal(t, o.old, o.oldSignature(t, freshPrimaryKey(t)), o.newKey)) {
		t.Fatal("an opening without the old key's signature was accepted")
	}
}

func TestAddressRevealNeedsTheKeyBehindTheAddress(t *testing.T) {
	o := newAddressOpening(t)
	other := freshPrimaryKey(t)
	o.bind(t, other.pub, o.newKey.addr, common.RecoveryBindDelayBlocks)
	if verifyNow(o.reveal(t, other, o.oldSignature(t, other), o.newKey)) {
		t.Fatal("a key that does not hash to the address opened the account")
	}
}

// An account that registered a key is opened already: it recovers through its
// commitments, never by revealing its address key again.
func TestAddressRevealOnlyForAccountsWithoutKeys(t *testing.T) {
	o := newAddressOpening(t)
	registerKey(t, enclosed(t, o.old, o.id, true))
	o.bind(t, o.old.pub, o.newKey.addr, common.RecoveryBindDelayBlocks)
	if verifyNow(o.reveal(t, o.old, o.oldSignature(t, o.old), o.newKey)) {
		t.Fatal("an account with a registered key was opened by address")
	}
}

// Someone who sees the old key and its signature in the owner's reveal can
// bind a key of its own, but the signature covers the owner's new key: it
// opens the account for nobody else.
func TestAddressRevealSignatureNamesTheNewKey(t *testing.T) {
	o := newAddressOpening(t)
	o.bind(t, o.old.pub, o.newKey.addr, common.RecoveryBindDelayBlocks)
	ownersSig := o.oldSignature(t, o.old)
	attacker := secondaryKey(t)
	o2 := o
	o2.newKey = attacker
	if !o2.bind(t, o.old.pub, attacker.addr, common.RecoveryBindExpiryBlocks) {
		t.Fatal("setup: the attacker's bind was not stored")
	}
	if verifyNow(o2.reveal(t, o.old, ownersSig, attacker)) {
		t.Fatal("the attacker's key opened the account with the owner's signature")
	}
}

// P-03: the tag of an address opening is the hash of the old public key, which
// may be known to others. A bind made with it ahead of the owner must not keep
// the owner out.
func TestAddressRevealIsNotBlockedByAnEarlierBind(t *testing.T) {
	o := newAddressOpening(t)
	squatter := secondaryKey(t)
	o.bind(t, o.old.pub, squatter.addr, common.RecoveryBindExpiryBlocks)
	o.bind(t, o.old.pub, o.newKey.addr, common.RecoveryBindDelayBlocks)
	if !verifyNow(o.reveal(t, o.old, o.oldSignature(t, o.old), o.newKey)) {
		t.Fatal("an earlier bind with the same old key blocked the owner's opening")
	}
}

// P-02: "first commitments apply at once" is only safe when the account is
// being opened - no key of it was public before this block, so nobody could
// have forged a signature. An identity whose key was already registered (a
// validator holding both keys and no commitments) gets no such shortcut: a
// forger of the not-yet-paused scheme would otherwise plant its own
// commitments in force, where the break's voiding cannot reach them.
func TestFirstCommitmentsOfAPublishedKeyMature(t *testing.T) {
	owner := registeredStageBKey(t) // keys registered at height 0
	fund(owner.addr)
	spare := secondaryKey(t)
	c, _ := common.RecoveryCommitment(recoverySecret(5))
	reg := commitmentRegistration(t, owner, spare.addr, &c, 31)
	if err := ProcessTransaction(reg, 100, 0); err != nil {
		t.Fatal(err)
	}
	acc, _ := account.GetAccountByAddressBytes(owner.addr.GetBytes())
	var zero [common.AddressLength]byte
	if acc.EffectiveSpareCommit(100) != zero || acc.EffectiveRecoveryCommit(100) != zero {
		t.Fatal("commitments of an identity with a published key applied at once")
	}
	at := 100 + common.RecoveryCommitMaturityBlocks
	if acc.EffectiveSpareCommit(at) != spare.addr.ByteValue || acc.EffectiveRecoveryCommit(at) != c.ByteValue {
		t.Fatal("the commitments did not mature")
	}
	if n := account.VoidPendingRecoveryCommits(101); n != 1 {
		t.Fatalf("a scheme break voided %d accounts' commitments, want 1", n)
	}
	acc, _ = account.GetAccountByAddressBytes(owner.addr.GetBytes())
	if acc.HasCommitments() {
		t.Fatal("commitments set before a scheme break survived it")
	}
}

// bindTx is a bind transaction as it travels: anyone funded may send one.
func bindTx(t *testing.T, payer stageBKey, identity common.Address, tag, payload [32]byte, nonce int64) transactionsDefinition.Transaction {
	t.Helper()
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: payer.addr, SendingTime: 1, Nonce: nonce},
		TxData: transactionsDefinition.TxData{Recipient: common.RecoveryBindAddress,
			OptData: transactionsDefinition.BuildRecoveryBindOptData(identity, tag, payload)},
		Height: common.GetHeight(), GasPrice: 1, GasUsage: 1_000_000,
	}
	signIn(t, &tx, payer, true)
	return tx
}

// P-03: the tag of a bind is public the moment the bind is in the mempool, so
// anyone can land a bind with the same identity and tag and a payload of its
// own first. That must not block the owner: the reveal is matched with the
// bind that carries ITS payload, and a payload made without the secret matches
// no reveal at all.
func TestFrontRunBindDoesNotBlockTheReveal(t *testing.T) {
	f := newRecoveryFixture(t)
	acc := account.Accounts.AllAccounts[f.owner.addr.ByteValue]
	payer := registeredStageBKey(t)
	account.Accounts.AllAccounts[payer.addr.ByteValue] = account.Account{Address: payer.addr.ByteValue, Balance: 1_000_000_000}
	account.Accounts.AllAccounts[f.owner.addr.ByteValue] = acc

	tag, _ := common.RecoveryTag(f.secret)
	payload, _ := common.RecoveryPayload(f.owner.addr, f.newKey.addr, f.next, f.secret)
	h := common.GetHeight() + 1 - common.RecoveryBindDelayBlocks
	// The front-runner copied identity and tag from the owner's bind and got
	// into the earlier block.
	if err := ProcessTransaction(bindTx(t, payer, f.owner.addr, tag, [32]byte{0xEE}, 1), h-1, 0); err != nil {
		t.Fatal(err)
	}
	if err := ProcessTransaction(bindTx(t, payer, f.owner.addr, tag, payload, 2), h, 0); err != nil {
		t.Fatal(err)
	}
	if !verifyNow(f.reveal(t, f.secret, f.newKey, f.newKey)) {
		t.Fatal("a front-run bind with the same tag blocked the owner's reveal")
	}
}

// P-04: a commitment change waiting out an escrow delay or multisig approvals
// is pending exactly like one maturing in the account, and may have been
// signed with the scheme a break has just exposed. The break voids it too -
// it used to settle afterwards and mature a week later.
func TestBreakVoidsCommitmentHeldInEscrow(t *testing.T) {
	owner := registeredStageBKey(t)
	fund(owner.addr)
	freshPolicyPools(t)
	withAccountPolicy(t, owner.addr, 10)
	c, _ := common.RecoveryCommitment(recoverySecret(5))
	reg := commitmentRegistration(t, owner, c, nil, 21)
	if err := ProcessTransaction(reg, 100, 0); err != nil {
		t.Fatal(err)
	}
	pausePrimaryAt(t, 101)
	if transactionsPool.PoolTxEscrow.HasTransaction(reg.Hash.GetBytes()) {
		t.Fatal("a commitment change held in escrow outlived the scheme break")
	}
	_ = ProcessTransactionsEscrow(110, nil)
	if p := spareCommitAt(owner.addr, 1<<40); p != ([common.AddressLength]byte{}) {
		t.Fatal("a commitment change held in escrow settled after the scheme break")
	}
}

// Rewinding the break puts the held change back: the pools are consensus
// state and return to the rewind target with everything else (F3-07).
func TestRewindRestoresCommitmentVoidedInEscrow(t *testing.T) {
	owner := registeredStageBKey(t)
	fund(owner.addr)
	freshPolicyPools(t)
	withAccountPolicy(t, owner.addr, 10)
	c, _ := common.RecoveryCommitment(recoverySecret(5))
	reg := commitmentRegistration(t, owner, c, nil, 21)
	if err := ProcessTransaction(reg, 100, 0); err != nil {
		t.Fatal(err)
	}
	pausePrimaryAt(t, 101)
	transactionsPool.UndoPendingPoolsAbove(100)
	if !transactionsPool.PoolTxEscrow.HasTransaction(reg.Hash.GetBytes()) {
		t.Fatal("rewinding the break did not return the held commitment change to escrow")
	}
}

func TestBreakVoidsCommitmentAwaitingApprovals(t *testing.T) {
	owner := registeredStageBKey(t)
	signer := testAddress(0x61)
	fund(owner.addr, signer)
	freshPolicyPools(t)
	withAccountPolicy(t, owner.addr, 0, signer)
	c, _ := common.RecoveryCommitment(recoverySecret(7))
	reg := commitmentRegistration(t, owner, c, nil, 23)
	if err := ProcessTransaction(reg, 100, 0); err != nil {
		t.Fatal(err)
	}
	pausePrimaryAt(t, 101)
	if transactionsPool.PoolTxMultiSign.HasTransaction(reg.Hash.GetBytes()) {
		t.Fatal("a commitment change awaiting approvals outlived the scheme break")
	}
}

// Held transfers are not commitments: the break leaves them alone.
func TestBreakKeepsHeldTransfers(t *testing.T) {
	owner := registeredStageBKey(t)
	fund(owner.addr)
	freshPolicyPools(t)
	withAccountPolicy(t, owner.addr, 10)
	transfer := signedTx(t, owner, testAddress(0x55), 1, common.GetHeight(), 3)
	if err := ProcessTransaction(transfer, 100, 0); err != nil {
		t.Fatal(err)
	}
	if !transactionsPool.PoolTxEscrow.HasTransaction(transfer.Hash.GetBytes()) {
		t.Fatal("setup: the transfer is not held in escrow")
	}
	pausePrimaryAt(t, 101)
	if !transactionsPool.PoolTxEscrow.HasTransaction(transfer.Hash.GetBytes()) {
		t.Fatal("the scheme break removed a held transfer")
	}
}

// P-06: every reveal of a block is verified against the parent state, where
// two reveals of one identity both open its commitment. The second then
// failed only when applied - after the block's keys had been written. The
// check pass refuses such a block outright.
func TestBlockWithTwoRevealsOfOneIdentityIsRefusedByTheCheck(t *testing.T) {
	a, b := testAddress(0x42), testAddress(0x43)
	reveal := func(id common.Address, opt []byte) transactionsDefinition.Transaction {
		return transactionsDefinition.Transaction{
			TxParam: transactionsDefinition.TxParam{Sender: id},
			TxData:  transactionsDefinition.TxData{Recipient: common.RecoveryRevealAddress, OptData: opt},
		}
	}
	commitment := make([]byte, common.RecoveryRevealOptDataLength)
	opening := make([]byte, common.RecoveryRevealOptDataLength+10)
	transfer := transactionsDefinition.Transaction{TxParam: transactionsDefinition.TxParam{Sender: a}}
	if err := checkOneRevealPerIdentity([]transactionsDefinition.Transaction{reveal(a, commitment), transfer, reveal(b, commitment)}); err != nil {
		t.Fatalf("reveals of different identities were refused: %v", err)
	}
	if checkOneRevealPerIdentity([]transactionsDefinition.Transaction{reveal(a, commitment), reveal(b, commitment), reveal(a, commitment)}) == nil {
		t.Fatal("two reveals of one identity in a block passed the check")
	}
	if checkOneRevealPerIdentity([]transactionsDefinition.Transaction{reveal(a, opening), reveal(a, commitment)}) == nil {
		t.Fatal("an address reveal and a commitment reveal of one identity passed the check")
	}
}

// openingWithScheme is an address opening whose old key belongs to the named
// liboqs scheme, correctly signed and bound.
func openingWithScheme(t *testing.T, scheme string) transactionsDefinition.Transaction {
	t.Helper()
	o := newAddressOpening(t)
	var old stageBKey
	if err := old.s.Init(scheme, nil); err != nil {
		t.Skipf("liboqs has no %s: %v", scheme, err)
	}
	var err error
	if old.pub, err = old.s.GenerateKeyPair(); err != nil {
		t.Fatal(err)
	}
	if old.addr, err = common.PubKeyToAddress(old.pub, true); err != nil {
		t.Fatal(err)
	}
	o.old, o.id = old, old.addr
	fund(o.id)
	o.bind(t, old.pub, o.newKey.addr, common.RecoveryBindDelayBlocks)
	tx := o.reveal(t, old, o.oldSignature(t, old), o.newKey)
	r, err := transactionsDefinition.ParseAddressReveal(tx.TxData.OptData)
	if err != nil {
		t.Fatal(err)
	}
	r.OldScheme = scheme
	tx.TxData.OptData = transactionsDefinition.BuildAddressRevealOptData(r)
	signIn(t, &tx, o.newKey, false)
	return tx
}

// P-08: an address is opened with the key it is the hash of, and that key's
// scheme used to be whatever liboqs scheme the revealer named. Only schemes
// this chain has used count: the two in force and the ones it retired.
func TestAddressRevealOnlyWithASchemeTheChainUsed(t *testing.T) {
	logger.InitLogger()
	const foreign = "ML-DSA-44"
	if verifyNow(openingWithScheme(t, foreign)) {
		t.Fatal("an address was opened with a key of a scheme the chain never used")
	}
	// The chain retires the scheme: a block replaces it in the spare slot.
	tx := openingWithScheme(t, foreign)
	mlDSA44 := encCfg(t, foreign, 1312, 2560, 2420, true)
	applyRecoveryMaintenance(blockWithEnc(50, falcon512(t, false), mayo5(t)), blockWithEnc(49, falcon512(t, false), mlDSA44))
	if !verifyNow(tx) {
		t.Fatal("an address of a retired scheme could not be opened")
	}
	// A rewind below that block takes the record back.
	UnregisterPubKeysAboveHeight(49, 50)
	if verifyNow(tx) {
		t.Fatal("after the rewind the scheme still counts as retired")
	}
}
