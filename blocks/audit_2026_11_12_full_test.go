package blocks

import (
	"math/big"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	vm "github.com/qwid-org/qwid-node/core/evm"
	"github.com/qwid-org/qwid-node/core/stateDB"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

// Regression tests for the full audit of 2026-11-12
// (audit/2026-11-12/AUDIT_full_2026-11-12.md).

func fundWith(addr common.Address, balance int64) {
	account.Accounts = account.AccountsType{AllAccounts: map[[common.AddressLength]byte]account.Account{
		addr.ByteValue: {Address: addr.ByteValue, Balance: balance},
	}}
}

// F-TX-03: a negative amount is an unstake or a reward withdrawal and nothing
// else. Addressed to the DEX it used to pass Verify and count as a CREDIT in
// the pool's and the block check's balance accounting.
func TestNegativeAmountToDexIsRefused(t *testing.T) {
	k := registeredStageBKey(t)
	fund(k.addr)
	last := parentAt(t, 99)

	dex := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: k.addr, SendingTime: 1, Nonce: 2},
		TxData: transactionsDefinition.TxData{Recipient: common.GetDelegatedAccountAddress(512 + 4),
			Amount: -5_000_000_000, OptData: transactionsDefinition.DexOrderOptData(1, 0)},
		Height: 99, GasPrice: 1,
	}
	dex.ContractAddress = testAddress(0x77)
	dex.GasUsage = dex.MinGasUsage()
	k.sign(t, &dex)
	if verifyNow(dex) {
		t.Fatal("a DEX transaction with a negative amount verifies")
	}
	unpayable := signedTx(t, k, testAddress(0x92), 3_000_000_000, 99, 3)
	if _, _, err := CheckBlockTransfers(childOf(last, pooled(t, dex, unpayable)...), last, nil, true); err == nil {
		t.Fatal("the block check accepted a transfer of 3_000_000_000 from a balance of 1_000_000_000")
	}
}

// F-TX-04: staking is paced (MinNumberOfBlocksInStake). The block check must
// refuse what the apply pass refuses.
func TestSecondStakeInOneBlockIsRefusedByTheCheck(t *testing.T) {
	k := registeredStageBKey(t)
	initTestStaking()
	fundWith(k.addr, 5*common.MinStakingUser)
	last := parentAt(t, 99)
	del := common.GetDelegatedAccountAddress(1)
	a := signedTx(t, k, del, common.MinStakingUser, 99, 1)
	b := signedTx(t, k, del, common.MinStakingUser, 99, 2)
	if _, _, err := CheckBlockTransfers(childOf(last, pooled(t, a)...), last, nil, true); err != nil {
		t.Fatalf("a single stake was refused: %v", err)
	}
	if _, _, err := CheckBlockTransfers(childOf(last, pooled(t, a, b)...), last, nil, true); err == nil {
		t.Fatal("two stakes of one sender in one block passed the check; the second fails when applied")
	}
}

func TestUnstakeTooEarlyOrOfLockedCoinsIsRefusedByTheCheck(t *testing.T) {
	k := registeredStageBKey(t)
	initTestStaking()
	fundWith(k.addr, 5*common.MinStakingUser)
	del := common.GetDelegatedAccountAddress(1)
	amount := common.MinStakingUser
	// staked at 90 with everything locked for a long time
	if err := account.Stake(k.addr.GetBytes(), 2*amount, 90, 1, 1, false, 0, 0); err != nil {
		t.Fatal(err)
	}
	early := signedTx(t, k, del, -amount, 99, 1)
	last := parentAt(t, 99)
	if _, _, err := CheckBlockTransfers(childOf(last, pooled(t, early)...), last, nil, true); err == nil {
		t.Fatalf("an unstake %d blocks after the stake passed the check", 100-90)
	}
	if err := account.StakeLockedFor(k.addr.GetBytes(), amount, 91, 1, 1, amount, 0); err != nil {
		t.Fatal(err)
	}
	late := parentAt(t, 90+common.MinNumberOfBlocksInStake+10)
	h := late.GetHeader().Height
	ok := signedTx(t, k, del, -2*amount, h, 2)
	if _, _, err := CheckBlockTransfers(childOf(late, pooled(t, ok)...), late, nil, true); err != nil {
		t.Fatalf("unstaking the free part was refused: %v", err)
	}
	locked := signedTx(t, k, del, -3*amount, h, 3)
	if _, _, err := CheckBlockTransfers(childOf(late, pooled(t, locked)...), late, nil, true); err == nil {
		t.Fatal("unstaking locked coins passed the check")
	}
}

func TestZeroAmountToAStakingAccountIsRefusedByTheCheck(t *testing.T) {
	k := registeredStageBKey(t)
	initTestStaking()
	fundWith(k.addr, 5*common.MinStakingUser)
	if err := account.Stake(k.addr.GetBytes(), common.MinStakingUser, 40, 1, 1, false, 0, 0); err != nil {
		t.Fatal(err)
	}
	last := parentAt(t, 99)
	for _, id := range []int16{1, 257} {
		tx := signedTx(t, k, common.GetDelegatedAccountAddress(id), 0, 99, int64(id))
		if _, _, err := CheckBlockTransfers(childOf(last, pooled(t, tx)...), last, nil, true); err == nil {
			t.Fatalf("a zero-amount transaction to delegated account %d passed the check; ProcessTransaction refuses it", id)
		}
	}
}

// F-TX-04: an approval that approves nothing, and a policy change that cannot
// apply, cost their fee and do nothing - they no longer invalidate the block.
func TestOrphanMultiSignApprovalDoesNotFailTheBlock(t *testing.T) {
	logger.InitLogger()
	withBalanceTestDB(t)
	initTestAccounts()
	transactionsPool.PoolTxMultiSign = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 2)
	approver := testAddress(50)
	account.Accounts.AllAccounts[approver.ByteValue] = account.Account{Address: approver.ByteValue, Balance: 1000}
	var missing common.Hash
	missing[0] = 0xAB
	tx := transferTx(t, approver, testAddress(51), 0, missing, 5)
	if err := ProcessTransaction(tx, 100, 1); err != nil {
		t.Fatal(err)
	}
	if err := ProcessTransactionsMultiSign(tx, 100, nil); err != nil {
		t.Fatalf("an approval of a transaction that does not exist failed the block: %v", err)
	}
	if transactionsPool.PoolTxMultiSign.HasTransaction(tx.Hash.GetBytes()) {
		t.Fatal("the orphan approval stayed in the multisig pool")
	}
}

func TestMultiSignSettlementWithoutFundsVoidsInsteadOfFailingTheBlock(t *testing.T) {
	logger.InitLogger()
	withBalanceTestDB(t)
	initTestAccounts()
	transactionsPool.PoolTxMultiSign = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 2)
	owner, signer, recipient := testAddress(60), testAddress(61), testAddress(62)
	account.Accounts.AllAccounts[owner.ByteValue] = account.Account{Address: owner.ByteValue, Balance: 100,
		MultiSignNumber: 1, MultiSignAddresses: [][common.AddressLength]byte{signer.ByteValue}}
	account.Accounts.AllAccounts[signer.ByteValue] = account.Account{Address: signer.ByteValue, Balance: 1000}
	main := transferTx(t, owner, recipient, 5000, common.EmptyHash(), 1) // more than the owner holds
	if err := ProcessTransaction(main, 100, 1); err != nil {
		t.Fatal(err)
	}
	appr := transferTx(t, signer, recipient, 0, main.Hash, 2)
	if err := ProcessTransaction(appr, 101, 1); err != nil {
		t.Fatal(err)
	}
	if err := ProcessTransactionsMultiSign(appr, 101, nil); err != nil {
		t.Fatalf("an unpayable multisig settlement failed the block: %v", err)
	}
	if got := balanceOf(t, recipient); got != 0 {
		t.Fatalf("recipient received %d", got)
	}
	if transactionsPool.PoolTxMultiSign.HasTransaction(main.Hash.GetBytes()) {
		t.Fatal("the unpayable main transaction stayed in the pool")
	}
}

func TestPolicyChangeThatCannotApplyDoesNotFailTheBlock(t *testing.T) {
	logger.InitLogger()
	withBalanceTestDB(t)
	initTestAccounts()
	a := testAddress(70)
	account.Accounts.AllAccounts[a.ByteValue] = account.Account{Address: a.ByteValue, Balance: 1_000_000}
	first := transferTx(t, a, a, 0, common.EmptyHash(), 1)
	first.TxData.EscrowTransactionsDelay = 10
	_ = first.CalcHashAndSet()
	second := transferTx(t, a, a, 0, common.EmptyHash(), 2)
	second.TxData.EscrowTransactionsDelay = 20
	_ = second.CalcHashAndSet()
	if err := ProcessTransaction(first, 100, 1); err != nil {
		t.Fatal(err)
	}
	if err := ProcessTransaction(second, 100, 1); err != nil {
		t.Fatalf("a second policy change in the block failed it: %v", err)
	}
	acc, _ := account.GetAccountByAddressBytes(a.GetBytes())
	if acc.TransactionDelay != 10 {
		t.Fatalf("delay = %d, want the first change (10)", acc.TransactionDelay)
	}
}

func TestEscrowAndMultisigPolicyTogetherDoNotVerify(t *testing.T) {
	k := registeredStageBKey(t)
	fund(k.addr)
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: k.addr, SendingTime: 1, Nonce: 9},
		TxData: transactionsDefinition.TxData{Recipient: k.addr, EscrowTransactionsDelay: 10, MultiSignNumber: 1,
			MultiSignAddresses: [][common.AddressLength]byte{testAddress(0x33).ByteValue}},
		Height: 99, GasPrice: 1, GasUsage: 100000,
	}
	k.sign(t, &tx)
	if verifyNow(tx) {
		t.Fatal("a transaction making an account both escrow and multisig verifies; it can never apply")
	}
}

// F-TX-04 (DEX): coins a sender's other transactions of the block still owe
// are not available to a DEX order.
func TestDexOrderLeavesTheSendersOtherSpendCovered(t *testing.T) {
	if !dexCoversReserved(100, -60, 40) {
		t.Fatal("an order leaving exactly the reserved coins was refused")
	}
	if dexCoversReserved(100, -61, 40) {
		t.Fatal("an order eating into the reserved coins was accepted")
	}
	if !dexCoversReserved(10, 500, 40) {
		t.Fatal("an order that pays the sender was refused")
	}
}

// F-TX-01: an escrow or multisig account cannot move coins out through a
// locked stake paid into another account.
func TestEscrowAccountCannotLockStakeIntoAnotherAccount(t *testing.T) {
	logger.InitLogger()
	withBalanceTestDB(t)
	initTestAccounts()
	initTestStaking()
	amount := common.MinStakingUser
	for name, acc := range map[string]account.Account{
		"escrow":   {TransactionDelay: 60480},
		"multisig": {MultiSignNumber: 1, MultiSignAddresses: [][common.AddressLength]byte{testAddress(43).ByteValue}},
	} {
		victim, thief := testAddress(40), testAddress(41)
		acc.Address, acc.Balance = victim.ByteValue, amount+1_000_000
		account.Accounts.AllAccounts[victim.ByteValue] = acc
		tx := transferTx(t, victim, thief, amount, common.EmptyHash(), 2)
		tx.TxData.LockedAmount = 1
		tx.TxData.ReleasePerBlock = 1
		tx.TxData.DelegatedAccountForLocking = common.GetDelegatedAccountAddress(1)
		_ = tx.CalcHashAndSet()
		if CheckStakingTransaction(tx, amount, 1, Block{BaseBlock: BaseBlock{BaseHeader: BaseHeader{Height: 100}}}) {
			t.Errorf("%s: the block check accepts a locked stake into another account", name)
		}
		if err := ProcessTransaction(tx, 100, 1000); err == nil {
			t.Errorf("%s: the locked stake into another account was applied", name)
		}
		if st := account.GetStakingAccountByAddressBytes(thief.GetBytes(), 1); st.StakedBalance != 0 {
			t.Errorf("%s: thief staked balance = %d", name, st.StakedBalance)
		}
	}
	// an ordinary account still can (S4-07)
	payer, friend := testAddress(44), testAddress(45)
	account.Accounts.AllAccounts[payer.ByteValue] = account.Account{Address: payer.ByteValue, Balance: 2 * amount}
	tx := transferTx(t, payer, friend, amount, common.EmptyHash(), 3)
	tx.TxData.LockedAmount, tx.TxData.ReleasePerBlock = amount, 1
	tx.TxData.DelegatedAccountForLocking = common.GetDelegatedAccountAddress(1)
	_ = tx.CalcHashAndSet()
	if err := ProcessTransaction(tx, 100, 1000); err != nil {
		t.Fatalf("an ordinary account's third-party lock was refused: %v", err)
	}
}

// F-SC-01: the token contracts refuse a negative amount.
func negativeTransferReverts(t *testing.T, code []byte) {
	t.Helper()
	initNativeAccountsBlocks()
	InitStateDB()
	var minter, victim, attacker common.Address
	minter.ByteValue[0], victim.ByteValue[0], attacker.ByteValue[0] = 0x60, 0x61, 0x62
	account.SetBalance(minter.ByteValue, 1_000_000)
	machine := newTestEVM(minter)
	State.ResetTransient()
	_, contract, _, err := machine.Create(vm.AccountRef(minter), code, uint64(common.MaxGasUsage)*10, big.NewInt(0), 0)
	if err != nil {
		t.Fatal(err)
	}
	neg := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1000)).Bytes()
	mint := append(append(common.Hex2Bytes("6b386df6"), addressArg(victim)...), int64Arg(1000)...)
	if _, _, err := machine.Call(vm.AccountRef(minter), contract, mint, uint64(common.MaxGasUsage), big.NewInt(0)); err != nil {
		t.Fatal(err)
	}
	in := append(append(append([]byte{}, stateDB.TransferFunc...), addressArg(victim)...), neg...)
	if _, _, err := machine.Call(vm.AccountRef(attacker), contract, in, uint64(common.MaxGasUsage), big.NewInt(0)); err == nil {
		t.Fatal("transfer(victim, -1000) from an empty account succeeded: it takes the victim's tokens")
	}
	negMint := append(append(common.Hex2Bytes("6b386df6"), addressArg(victim)...), neg...)
	if _, _, err := machine.Call(vm.AccountRef(minter), contract, negMint, uint64(common.MaxGasUsage), big.NewInt(0)); err == nil {
		t.Fatal("mint(victim, -1000) succeeded")
	}
}

func TestShippedTokenBytecodeRefusesNegativeAmounts(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	negativeTransferReverts(t, loadContractBin(t))
}

func TestTokenSourceRefusesNegativeAmounts(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	if _, err := exec.LookPath("solc"); err != nil {
		t.Skip("solc not installed")
	}
	src := filepath.Join("..", "smartContracts", "contract.sol")
	abs, _ := filepath.Abs(src)
	out, err := exec.Command("solc", "--evm-version", "paris", "--bin", abs).Output()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	code := common.Hex2Bytes(strings.TrimSpace(lines[len(lines)-1]))
	if !IsTokenToRegister(code) {
		t.Fatal("the compiled source no longer qualifies as a token")
	}
	negativeTransferReverts(t, code)
}
