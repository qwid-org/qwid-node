package blocks

import (
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/core/evm"
	"github.com/qwid-org/qwid-node/core/stateDB"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/params"
)

// End-to-end against the real compiled artefact of smartContracts/contract.sol,
// checked into the repository as contract.bin so this runs without solc.
//
// The other EVM tests exercise the plumbing with synthetic inputs. This one
// deploys actual solc output through the actual interpreter and then reads the
// contract's own storage back through its own getters — so a change that breaks
// deployment, dispatch, storage layout or the token-registration gate shows up
// here rather than on a live chain.

func loadContractBin(t *testing.T) []byte {
	t.Helper()
	// Tests run with the package directory as the working directory.
	path := filepath.Join("..", "smartContracts", "contract.bin")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	hex := strings.TrimSpace(string(raw))
	code := common.Hex2Bytes(hex)
	if len(code) == 0 {
		t.Fatalf("%s decoded to no bytes", path)
	}
	return code
}

// newTestEVM mirrors the context EvaluateSC builds, minus the block lookups
// this test does not need.
func newTestEVM(origin common.Address) *vm.EVM {
	blockCtx := vm.BlockContext{
		CanTransfer: evmCanTransfer,
		Transfer:    evmTransfer,
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
		Coinbase:    common.EmptyAddress(),
		GasLimit:    uint64(common.MaxGasUsage) * 10,
		BlockNumber: big.NewInt(1),
		Time:        big.NewInt(1),
		Difficulty:  big.NewInt(1),
		BaseFee:     big.NewInt(0),
	}
	jumpTable := vm.GetGenericJumpTable()
	cfg := vm.Config{JumpTable: &jumpTable, NoBaseFee: true, ExtraEips: []int{}}
	txCtx := vm.TxContext{Origin: origin, GasPrice: big.NewInt(0)}

	machine := vm.NewEVM(blockCtx, txCtx, &State, params.AllEthashProtocolChanges, cfg)
	machine.Origin = origin
	return machine
}

// callWord invokes selector+args and returns the single 32-byte return word.
func callWord(t *testing.T, machine *vm.EVM, origin, contract common.Address, input []byte) []byte {
	t.Helper()
	ret, _, err := machine.Call(vm.AccountRef(origin), contract, input,
		uint64(common.MaxGasUsage), big.NewInt(0))
	if err != nil {
		t.Fatalf("call reverted: %v", err)
	}
	if len(ret) < 32 {
		t.Fatalf("call returned %d bytes, want at least a 32-byte word", len(ret))
	}
	return ret[len(ret)-32:]
}

func wordToInt64(w []byte) int64 {
	return new(big.Int).SetBytes(w).Int64()
}

func addressArg(a common.Address) []byte { return common.LeftPadBytes(a.GetBytes(), 32) }

func int64Arg(v int64) []byte { return common.LeftPadBytes(big.NewInt(v).Bytes(), 32) }

// The compiled artefact must satisfy the registration gate. If solc output ever
// stops carrying one of the five selectors — a compiler upgrade inlining a
// getter, say — the token silently stops being tradeable, and this catches it.
func TestCompiledContractQualifiesAsToken(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	if !IsTokenToRegister(loadContractBin(t)) {
		t.Fatal("the compiled contract is not recognised as a token; check that " +
			"name/symbol/decimals/balanceOf/transfer(address,int64) survive compilation")
	}
}

func TestDeployMintAndTransferOnRealBytecode(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initNativeAccountsBlocks()
	InitStateDB()

	var minter, recipient common.Address
	minter.ByteValue[0] = 0x60
	recipient.ByteValue[0] = 0x61
	account.SetBalance(minter.ByteValue, 1_000_000)

	machine := newTestEVM(minter)
	State.ResetTransient()

	// --- deploy -------------------------------------------------------------
	_, contract, _, err := machine.Create(vm.AccountRef(minter), loadContractBin(t),
		uint64(common.MaxGasUsage)*10, big.NewInt(0), 0)
	if err != nil {
		t.Fatalf("deployment failed: %v", err)
	}
	if contract == common.EmptyAddress() {
		t.Fatal("deployment produced the empty address")
	}
	if len(State.GetCode(contract)) == 0 {
		t.Fatal("no runtime code was stored at the contract address")
	}

	// --- decimals(), a constant the DEX prices against -----------------------
	if got := wordToInt64(callWord(t, machine, minter, contract, stateDB.DecimalsFunc)); got != 2 {
		t.Errorf("decimals() = %d, want 2", got)
	}

	// --- balances start empty ----------------------------------------------
	balOf := func(who common.Address) int64 {
		input := append(append([]byte{}, stateDB.BalanceOfFunc...), addressArg(who)...)
		return wordToInt64(callWord(t, machine, minter, contract, input))
	}
	if got := balOf(minter); got != 0 {
		t.Fatalf("minter starts with %d, want 0", got)
	}

	// --- mint(minter, 1000) -------------------------------------------------
	mintSel := common.Hex2Bytes("6b386df6") // mint(address,int64)
	mintInput := append(append(append([]byte{}, mintSel...), addressArg(minter)...), int64Arg(1_000)...)
	if _, _, err := machine.Call(vm.AccountRef(minter), contract, mintInput,
		uint64(common.MaxGasUsage), big.NewInt(0)); err != nil {
		t.Fatalf("mint reverted: %v", err)
	}
	if got := balOf(minter); got != 1_000 {
		t.Fatalf("after mint the minter holds %d, want 1000", got)
	}

	// --- transfer(recipient, 400) -------------------------------------------
	transferInput := append(append(append([]byte{}, stateDB.TransferFunc...),
		addressArg(recipient)...), int64Arg(400)...)
	if _, _, err := machine.Call(vm.AccountRef(minter), contract, transferInput,
		uint64(common.MaxGasUsage), big.NewInt(0)); err != nil {
		t.Fatalf("transfer reverted: %v", err)
	}

	if got := balOf(minter); got != 600 {
		t.Errorf("sender holds %d after sending 400 of 1000, want 600", got)
	}
	if got := balOf(recipient); got != 400 {
		t.Errorf("recipient holds %d, want 400", got)
	}
	// Nothing may be created or destroyed by a transfer.
	if total := balOf(minter) + balOf(recipient); total != 1_000 {
		t.Errorf("total supply moved to %d during a transfer, want 1000", total)
	}
}

// The contract's own require() must hold end to end: transferring more than the
// balance has to revert and leave both sides untouched.
func TestTransferBeyondBalanceRevertsAndChangesNothing(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initNativeAccountsBlocks()
	InitStateDB()

	var minter, recipient common.Address
	minter.ByteValue[0] = 0x62
	recipient.ByteValue[0] = 0x63
	account.SetBalance(minter.ByteValue, 1_000_000)

	machine := newTestEVM(minter)
	State.ResetTransient()

	_, contract, _, err := machine.Create(vm.AccountRef(minter), loadContractBin(t),
		uint64(common.MaxGasUsage)*10, big.NewInt(0), 0)
	if err != nil {
		t.Fatalf("deployment failed: %v", err)
	}

	mintSel := common.Hex2Bytes("6b386df6")
	mintInput := append(append(append([]byte{}, mintSel...), addressArg(minter)...), int64Arg(100)...)
	if _, _, err := machine.Call(vm.AccountRef(minter), contract, mintInput,
		uint64(common.MaxGasUsage), big.NewInt(0)); err != nil {
		t.Fatalf("mint reverted: %v", err)
	}

	transferInput := append(append(append([]byte{}, stateDB.TransferFunc...),
		addressArg(recipient)...), int64Arg(500)...)
	_, _, err = machine.Call(vm.AccountRef(minter), contract, transferInput,
		uint64(common.MaxGasUsage), big.NewInt(0))
	if err == nil {
		t.Fatal("transferring more than the balance succeeded")
	}

	balOf := func(who common.Address) int64 {
		input := append(append([]byte{}, stateDB.BalanceOfFunc...), addressArg(who)...)
		return wordToInt64(callWord(t, machine, minter, contract, input))
	}
	if got := balOf(minter); got != 100 {
		t.Errorf("sender balance changed to %d despite the revert, want 100", got)
	}
	if got := balOf(recipient); got != 0 {
		t.Errorf("recipient received %d from a reverted transfer, want 0", got)
	}
}

// Only the deployer may mint. A stranger's mint must revert, or anyone could
// print the token the DEX prices.
func TestOnlyMinterCanMint(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initNativeAccountsBlocks()
	InitStateDB()

	var minter, stranger common.Address
	minter.ByteValue[0] = 0x64
	stranger.ByteValue[0] = 0x65
	account.SetBalance(minter.ByteValue, 1_000_000)
	account.SetBalance(stranger.ByteValue, 1_000_000)

	machine := newTestEVM(minter)
	State.ResetTransient()

	_, contract, _, err := machine.Create(vm.AccountRef(minter), loadContractBin(t),
		uint64(common.MaxGasUsage)*10, big.NewInt(0), 0)
	if err != nil {
		t.Fatalf("deployment failed: %v", err)
	}

	mintSel := common.Hex2Bytes("6b386df6")
	mintInput := append(append(append([]byte{}, mintSel...), addressArg(stranger)...), int64Arg(999)...)

	strangerVM := newTestEVM(stranger)
	if _, _, err := strangerVM.Call(vm.AccountRef(stranger), contract, mintInput,
		uint64(common.MaxGasUsage), big.NewInt(0)); err == nil {
		t.Fatal("a non-minter successfully minted tokens")
	}

	balInput := append(append([]byte{}, stateDB.BalanceOfFunc...), addressArg(stranger)...)
	if got := wordToInt64(callWord(t, machine, minter, contract, balInput)); got != 0 {
		t.Errorf("the stranger holds %d after a rejected mint, want 0", got)
	}
}
