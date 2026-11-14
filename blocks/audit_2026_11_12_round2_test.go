package blocks

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	vm "github.com/qwid-org/qwid-node/core/evm"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/params"
	"github.com/qwid-org/qwid-node/pubkeys"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

// Regression tests, audit 2026-11-12 sections 11-12.

// F-EVM-01: block execution keeps no KECCAK256 preimages.
func TestExecutionKeepsNoKeccakPreimages(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initNativeAccountsBlocks()
	InitStateDB()
	var caller, contract common.Address
	caller.ByteValue[0], contract.ByteValue[0] = 0x70, 0x71
	State.CreateAccount(contract)
	// loop: keccak256(mem[0:0x8000]); mem[0] = gas; jump 0
	State.SetCode(contract, common.Hex2Bytes("5b618000600020505a60005260005600"))
	blockCtx := vm.BlockContext{CanTransfer: evmCanTransfer, Transfer: evmTransfer,
		GetHash: func(uint64) common.Hash { return common.Hash{} }, GasLimit: uint64(common.MaxGasUsage),
		BlockNumber: big.NewInt(1), Time: big.NewInt(1), Difficulty: big.NewInt(1), BaseFee: big.NewInt(0)}
	lg := vm.CreateGVMLogger()
	machine := vm.NewEVM(blockCtx, vm.TxContext{Origin: caller, GasPrice: big.NewInt(0)}, &State,
		params.AllEthashProtocolChanges, evmExecutionConfig(&lg))
	State.ResetTransient()
	_, _, _ = machine.Call(vm.AccountRef(caller), contract, nil, 2_000_000, big.NewInt(0))
	if n := len(State.States); n != 0 {
		t.Fatalf("execution left %d keccak preimages in the EVM state", n)
	}
}

func registrationAt(t *testing.T, identity common.Address, pk common.PubKey, signer stageBKey, nonce int64) transactionsDefinition.Transaction {
	t.Helper()
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: identity, SendingTime: 1, Nonce: nonce},
		TxData:  transactionsDefinition.TxData{Recipient: identity, Pubkey: pk},
		Height:  99, GasPrice: 1, GasUsage: 1_000_000,
	}
	signIn(t, &tx, signer, true)
	return tx
}

// F-TX-04 (keys): the per-identity key limit is a rule of verification and of
// the block check, not something found out when the block is applied.
func TestKeyLimitIsEnforcedBeforeApply(t *testing.T) {
	k := registeredStageBKey(t) // primary + spare
	fund(k.addr)
	for i := 2; i < common.MaxKeysPerIdentity-1; i++ {
		registerKey(t, enclosed(t, secondaryKey(t), k.addr, false))
	}
	// one slot left: two registrations in one block do not fit
	a := registrationAt(t, k.addr, enclosed(t, secondaryKey(t), k.addr, false), k, 1)
	b := registrationAt(t, k.addr, enclosed(t, secondaryKey(t), k.addr, false), k, 2)
	if !verifyNow(a) {
		t.Fatal("the registration filling the last slot does not verify")
	}
	last := parentAt(t, 99)
	if _, _, err := CheckBlockTransfers(childOf(last, pooled(t, a)...), last, nil, true); err != nil {
		t.Fatalf("the registration filling the last slot was refused: %v", err)
	}
	if _, _, err := CheckBlockTransfers(childOf(last, pooled(t, a, b)...), last, nil, true); err == nil {
		t.Fatal("two registrations for one free key slot passed the block check")
	}
	registerKey(t, a.TxData.Pubkey)
	if verifyNow(b) {
		t.Fatal("a registration beyond the key limit verifies; it fails only when applied")
	}
}

// F-KEY-01: binding somebody else's key to one's own identity must not keep
// its owner from registering it.
func TestSquattedKeyStillRegistersForItsOwner(t *testing.T) {
	attacker := registeredStageBKey(t)
	fund(attacker.addr)
	victim := unregisteredPrimary(t)
	own := pureRegistration(t, victim.addr, enclosed(t, victim, victim.addr, true), victim, true)

	squat := enclosed(t, victim, attacker.addr, true)
	if err := registerPubKey(squat, 50, true); err != nil { // as applied from the attacker's registration
		t.Fatal(err)
	}
	if !verifyNow(own) {
		t.Fatal("the owner's first registration, signed with the key itself, no longer verifies")
	}
	if err := registerPubKey(own.TxData.Pubkey, 60, false); err != nil {
		t.Fatal(err)
	}
	stored, err := pubkeys.LoadPubKey(victim.addr.GetBytes())
	if err != nil || !bytes.Equal(stored.MainAddress.GetBytes(), victim.addr.GetBytes()) {
		t.Fatalf("the key is not bound to its owner after the owner registered it: %v", err)
	}
	if !pubkeys.IsRegisteredUnder(victim.addr, victim.addr) {
		t.Fatal("the key is missing from its owner's key list")
	}
	// the owner's key can now sign for the owner
	fund(attacker.addr, victim.addr)
	registerKey(t, enclosed(t, secondaryKey(t), victim.addr, false))
	if tx := signedTx(t, victim, testAddress(0x55), 5, 99, 1); !verifyNow(tx) {
		t.Fatal("the owner cannot transact after registering")
	}
	// rewinding the owner's registration restores what was there before
	UnregisterPubKeysAtHeight(60)
	stored, err = pubkeys.LoadPubKey(victim.addr.GetBytes())
	if err != nil || !bytes.Equal(stored.MainAddress.GetBytes(), attacker.addr.GetBytes()) {
		t.Fatalf("after the rewind the earlier binding is not restored: %v", err)
	}
	if pubkeys.IsRegisteredUnder(victim.addr, victim.addr) {
		t.Fatal("after the rewind the key is still in the owner's list")
	}
}

// A registration made WITHOUT a signature of the key it registers cannot take
// a key that is already bound to another identity - not even inside the block
// that bound it.
func TestKeyBoundToItsOwnerCannotBeRebound(t *testing.T) {
	attacker := registeredStageBKey(t)
	fund(attacker.addr)
	victim := unregisteredPrimary(t)
	if err := registerPubKey(enclosed(t, victim, victim.addr, true), 60, false); err != nil {
		t.Fatal(err)
	}
	squat := pureRegistration(t, attacker.addr, enclosed(t, victim, attacker.addr, true), attacker, true)
	if verifyNow(squat) {
		t.Fatal("rebinding a registered key to another identity verifies")
	}
	// same block: verified against the parent, applied after the owner's
	if err := registerPubKey(squat.TxData.Pubkey, 60, true); err != nil {
		t.Fatalf("the late rebinding must be ignored, not fail the block: %v", err)
	}
	stored, _ := pubkeys.LoadPubKey(victim.addr.GetBytes())
	if !bytes.Equal(stored.MainAddress.GetBytes(), victim.addr.GetBytes()) {
		t.Fatal("the key was rebound to the attacker")
	}
	if pubkeys.VoidedAsOf(victim.addr.GetBytes(), 60) || len(pubkeys.RegistrationRecord(victim.addr)) == 9 {
		t.Fatal("the owner's key was marked voidable by the attacker's registration")
	}
	if pubkeys.IsRegisteredUnder(attacker.addr, victim.addr) {
		t.Fatal("the key entered the attacker's key list")
	}
}

func unregisteredPrimary(t *testing.T) stageBKey {
	t.Helper()
	var k stageBKey
	if err := k.s.Init(common.SigName(), nil); err != nil {
		t.Skip(err)
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

// F-POOL-01: a transfer that a block would hold in a full escrow pool is
// refused by the block check; it used to be charged and then silently lost.
func TestHeldTransferIntoAFullPoolIsRefusedByTheCheck(t *testing.T) {
	k := registeredStageBKey(t)
	fund(k.addr)
	acc := account.Accounts.AllAccounts[k.addr.ByteValue]
	acc.TransactionDelay = 20
	account.Accounts.AllAccounts[k.addr.ByteValue] = acc
	saved := transactionsPool.PoolTxEscrow
	t.Cleanup(func() { transactionsPool.PoolTxEscrow = saved })
	transactionsPool.PoolTxEscrow = transactionsPool.NewTransactionPool(1, 1)
	last := parentAt(t, 99)

	a := signedTx(t, k, testAddress(0x61), 5, 99, 1)
	b := signedTx(t, k, testAddress(0x62), 5, 99, 2)
	if _, _, err := CheckBlockTransfers(childOf(last, pooled(t, a)...), last, nil, true); err != nil {
		t.Fatalf("a held transfer that fits was refused: %v", err)
	}
	if _, _, err := CheckBlockTransfers(childOf(last, pooled(t, a, b)...), last, nil, true); err == nil {
		t.Fatal("two held transfers for one free escrow slot passed the block check")
	}
	if err := ProcessTransaction(a, 100, 1); err != nil {
		t.Fatal(err)
	}
	if err := ProcessTransaction(b, 100, 1); err == nil {
		t.Fatal("applying a held transfer into the full pool succeeded silently")
	}
}

// F-CONS-06: once a block pauses the primary scheme - the chain's verdict that
// it may be broken - a primary-signed nonce no longer counts as an oracle
// proof (vote or price) in the blocks built on it.
func signedNonce(t *testing.T, k stageBKey, height int64) []byte {
	t.Helper()
	tx := nonceTxFor(1, height, 0, 0)
	tx.TxParam = transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: k.addr, SendingTime: 1}
	k.sign(t, tx)
	return tx.GetBytes()
}

func parentWithPrimaryPaused(t *testing.T, height int64, paused bool) Block {
	t.Helper()
	b := parentAt(t, height)
	enc1, err := oqs.GenerateBytesFromParams(common.SigName(), common.PubKeyLength(false), common.PrivateKeyLength(), common.SignatureLength(false), paused)
	if err != nil {
		t.Fatal(err)
	}
	b.BaseBlock.BaseHeader.Encryption1 = enc1
	return b
}

func TestPrimarySignedProofDoesNotCountAfterAPause(t *testing.T) {
	k := registeredStageBKey(t)
	fund(k.addr)
	proof := signedNonce(t, k, 100)
	for _, tc := range []struct {
		paused bool
		ok     bool
	}{{false, true}, {true, false}} {
		last := parentWithPrimaryPaused(t, 99, tc.paused)
		blk := childOf(last)
		blk.BaseBlock.BaseHeader.Encryption1 = last.BaseBlock.BaseHeader.Encryption1
		blk.BaseBlock.BaseHeader.Encryption2 = last.BaseBlock.BaseHeader.Encryption2
		blk.BaseBlock.OracleProofs = [][]byte{proof}
		err := AuthenticateOracleProofs(blk, last)
		if tc.ok && err != nil {
			t.Fatalf("a primary-signed proof under a live primary was refused: %v", err)
		}
		if !tc.ok && err == nil {
			t.Fatal("a primary-signed proof counted in a block built on a pause of the primary")
		}
		kept := filterPausedProofs([][]byte{proof}, last)
		if (len(kept) == 1) != tc.ok {
			t.Fatalf("producer filter kept %d proof(s) with the primary paused=%v", len(kept), tc.paused)
		}
	}
}

// The secondary's liveness is derived (live exactly while the primary is
// paused). Proofs signed with it in the era when both schemes were live must
// keep verifying, so the gate applies to a paused PRIMARY only.
func TestProofPauseGateConcernsThePrimaryOnly(t *testing.T) {
	p, s := proofPauseFlags(parentWithPrimaryPaused(t, 10, false))
	if p || s {
		t.Fatalf("flags with a live primary = %v %v, want false false", p, s)
	}
	p, s = proofPauseFlags(parentWithPrimaryPaused(t, 10, true))
	if !p || s {
		t.Fatalf("flags with a paused primary = %v %v, want true false", p, s)
	}
}
