package blocks

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	vm "github.com/qwid-org/qwid-node/core/evm"
	"github.com/qwid-org/qwid-node/core/stateDB"
	"github.com/qwid-org/qwid-node/core/types"
	loggerMain "github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
	"math/big"
	"sync"
)

var State stateDB.StateAccount
var StateMutex sync.RWMutex
var VM *vm.EVM

type PasiveFunction struct {
	Address common.Address `json:"address"`
	OptData []byte         `json:"optData"`
	Height  int64          `json:"height"`
}

// evmCanTransfer reports whether addr's native balance covers amount (DB-C2).
func evmCanTransfer(db vm.StateDB, addr common.Address, amount *big.Int) bool {
	return db.GetBalance(addr).Cmp(amount) >= 0
}

// evmTransfer moves amount between native balances via the Phase 2 bridge
// (journaled, so a reverted EVM call restores both sides).
func evmTransfer(db vm.StateDB, from, to common.Address, amount *big.Int) {
	db.SubBalance(from, amount)
	db.AddBalance(to, amount)
}

// isContractCallTx reports whether the EVM (via EvaluateSC) owns this tx's value
// transfer, so the native ProcessTransaction path must NOT also move it. It must
// match EXACTLY the condition under which EvaluateSCForBlock routes a tx to
// EvaluateSC: OptData present, non-delegated recipient, and a sender that is
// neither a multisign account nor escrow-delayed (both skip SC execution).
func isContractCallTx(tx transactionsDefinition.Transaction, senderAcc account.Account, height int64) bool {
	if _, ok := tx.CancellationTarget(); ok {
		return false
	}
	if len(tx.TxData.OptData) == 0 {
		return false
	}
	if common.IsRecoveryAddress(tx.TxData.Recipient) || tx.IsCommitmentRegistration() {
		return false // recovery data or a recovery commitment, not EVM input
	}
	if _, err := account.IntDelegatedAccountFromAddress(tx.TxData.Recipient); err == nil {
		return false // delegated recipient (staking/reward/DEX) — not an SC call
	}
	if senderAcc.MultiSignNumber > 0 {
		return false // multisign accounts skip SC execution
	}
	if senderAcc.TransactionDelay > 0 { // held in escrow at inclusion (S4-02)
		return false // escrow-delayed — SC not executed
	}
	return true
}

// ErrNativeSupplyChanged marks an execution that created or destroyed native
// coins. The EVM may only move coins between accounts; an execution that does
// otherwise - a VM bug like F1-01 (SELFDESTRUCT to itself) - is reverted and
// fails like any other, instead of breaking the block's supply check. A
// supply break used to invalidate every block carrying the transaction, while
// the transaction stayed in the pool to poison the next one.
var ErrNativeSupplyChanged = errors.New("execution changed the native coin supply")

// finishExecution ends a successful top-level execution: one that moved the
// native supply is reverted and reported as ErrNativeSupplyChanged, anything
// else is finalised. The caller holds StateMutex.
func finishExecution() error {
	if delta := State.NativeBalanceDelta(); delta != 0 {
		State.RevertToSnapshot(0)
		return fmt.Errorf("%w by %d", ErrNativeSupplyChanged, delta)
	}
	State.FinaliseTx()
	return nil
}

// dropBadTransaction removes from the pool a transaction whose execution
// makes its block invalid, so that the next block does not carry it again
// (pool hygiene). CheckBlockTransfers does the same for the transactions it
// rejects; without this, a block failing here or in the supply check left
// the transaction in the pool and every next block repeated the failure until
// the transaction aged out of the height window (about a day). Only failures
// caused by the transaction itself come here - a database error says nothing
// about it.
func dropBadTransaction(t transactionsDefinition.Transaction, bl Block, err error) {
	loggerMain.GetLogger().Printf("transaction %x makes block %d invalid (%v) - removing it from the pool",
		t.Hash.GetBytes()[:8], bl.GetHeader().Height, err)
	transactionsPool.RemoveBlockBreakingTransactionByHash(t.Hash.GetBytes(), bl.GetHeader().Height)
}

// isEVMExecutionError reports whether err is an EVM execution failure — a
// contract-caused failure the sender pays for and the block includes — as
// opposed to a node/processing error, which must stay block-fatal. Anything
// not positively matched here is treated as block-fatal (the safe default).
func isEVMExecutionError(err error) bool {
	switch {
	case errors.Is(err, vm.ErrExecutionReverted),
		errors.Is(err, vm.ErrOutOfGas),
		errors.Is(err, vm.ErrCodeStoreOutOfGas),
		errors.Is(err, vm.ErrDepth),
		errors.Is(err, vm.ErrInsufficientBalance),
		errors.Is(err, vm.ErrContractAddressCollision),
		errors.Is(err, vm.ErrMaxCodeSizeExceeded),
		errors.Is(err, vm.ErrInvalidJump),
		errors.Is(err, vm.ErrWriteProtection),
		errors.Is(err, vm.ErrReturnDataOutOfBounds),
		errors.Is(err, vm.ErrGasUintOverflow),
		errors.Is(err, vm.ErrInvalidCode),
		errors.Is(err, vm.ErrNonceUintOverflow),
		errors.Is(err, vm.ErrPrecompileFailed),
		errors.Is(err, ErrNativeSupplyChanged):
		return true
	}
	var opErr *vm.ErrInvalidOpCode
	if errors.As(err, &opErr) {
		return true
	}
	var suErr *vm.ErrStackUnderflow
	if errors.As(err, &suErr) {
		return true
	}
	var soErr *vm.ErrStackOverflow
	if errors.As(err, &soErr) {
		return true
	}
	return false
}

func InitStateDB() {
	StateMutex.Lock()
	defer StateMutex.Unlock()
	State = stateDB.CreateStateDB()
	// Phase 1: restore persisted EVM state so contracts survive restarts.
	if err := State.Load(-1); err != nil {
		loggerMain.GetLogger().Println("could not load persisted EVM state (starting empty):", err)
	}
}

// CommitEVMState persists the current EVM state for a block height
// unconditionally. Genesis uses it to write the floor snapshot every later
// closest-at-or-below lookup bottoms out on; block-apply paths should use
// CommitEVMStateIfChanged instead.
func CommitEVMState(height int64) error {
	StateMutex.Lock()
	defer StateMutex.Unlock()
	return State.Store(height)
}

// CommitEVMStateIfChanged persists the EVM state for a block height only when
// a transaction of that block actually touched it (EvaluateSCForBlock marks
// the state changed on every SC/DEX/token execution). Storing the full state
// under every height made snapshots grow with chain length; skipping unchanged
// heights keeps them proportional to contract activity while preserving the
// rewind invariant — every height at which the state changed has a snapshot,
// so the closest snapshot at-or-below any rewind target is exact.
func CommitEVMStateIfChanged(height int64) error {
	StateMutex.Lock()
	defer StateMutex.Unlock()
	if !State.ChangedSinceStore() {
		return nil
	}
	return State.Store(height)
}

// ErrDexLimitExceeded marks a DEX order whose signed price limit the trade
// would break (S7-07). Such an order is skipped, not a block error.
var ErrDexLimitExceeded = errors.New("dex price limit exceeded")

// checkDexLimit applies an order's coin limit to the coins the trade moves
// for the sender (amountCoin > 0 received, < 0 paid).
func checkDexLimit(operation int, amountCoin, coinLimit int64) error {
	if coinLimit <= 0 {
		return nil
	}
	if operation == 3 && -amountCoin > coinLimit {
		return fmt.Errorf("%w: buy costs %d, limit %d", ErrDexLimitExceeded, -amountCoin, coinLimit)
	}
	if operation == 4 && amountCoin < coinLimit {
		return fmt.Errorf("%w: sell pays %d, limit %d", ErrDexLimitExceeded, amountCoin, coinLimit)
	}
	return nil
}

// GenerateOptDataDEX prices a DEX order against the current pool and returns
// the token transfer to run, who it is from, what the sender receives in
// coins and tokens (negative: pays) and the price to store - coin base units
// per whole token (dexTokenPrice). All arithmetic is in base units
// (dexOrderAmounts).
func GenerateOptDataDEX(tx transactionsDefinition.Transaction, operation int) ([]byte, common.Address, int64, int64, int64, error) {
	// 2 - adding liquidity, 3 - buy trade, 4 -sell trade, 5 - withdraw token, 6 - withdraw KURA (5,6 inactive, just withdraw is selling opposite)

	// OptData is sender-controlled and no earlier layer enforces a DEX shape:
	// Transaction.Verify accepts any byte slice here, and the producer's
	// preflight does not run this parser. GetInt64FromByte panics below eight
	// bytes, so without this check one validly signed transaction addressed to
	// a DEX delegated account was a deterministic panic inside block
	// application on every validator (QWID-2026-13). An error, by contrast,
	// takes the ordinary invalid-transaction branch.
	amountToken, coinLimit, err := transactionsDefinition.ParseDexOptData(tx.TxData.OptData, operation)
	if err != nil {
		return nil, common.Address{}, 0, 0, 0, err
	}
	sender := tx.TxParam.Sender
	tokenAddress := tx.ContractAddress
	if operation == 2 && (tx.TxData.Amount < 0 || amountToken < 0) || (operation == 3 || operation == 4) && (amountToken == 0) || operation == 5 && amountToken == 0 || operation == 6 && tx.TxData.Amount == 0 {
		return nil, common.Address{}, 0, 0, 0, fmt.Errorf("withdraw one can perform on one currency the second should be 0")
	}

	accDex := account.GetDexAccountByAddressBytes(tokenAddress.GetBytes())
	balanceToken, err := GetBalance(tx.ContractAddress, sender)
	if err != nil {
		return nil, common.Address{}, 0, 0, 0, err
	}
	ba := [common.AddressLength]byte{}
	copy(ba[:], tx.ContractAddress.GetBytes())
	StateMutex.RLock()
	ti, ok := State.Tokens[ba]
	StateMutex.RUnlock()
	if !ok {
		return nil, common.Address{}, 0, 0, 0, fmt.Errorf("no token with a given address")
	}

	// dex account where all tokens liquidity are stored
	dex := common.GetDexAccountAddress()

	amountCoinInt64, amountTokenInt64, price, err := dexOrderAmounts(operation, tx.TxData.Amount, amountToken,
		accDex.CoinPool, accDex.TokenPool, ti.Decimals)
	if err != nil {
		return nil, common.Address{}, 0, 0, 0, err
	}

	// S7-07: the sender's price limit, signed with the order. amountCoinInt64
	// is what the sender receives (negative: pays). A violated limit is not
	// an invalid block - the order is skipped and its fee stays paid - so a
	// price move can neither fill it at a worse price (no sandwich) nor
	// poison every block that carries it.
	if err := checkDexLimit(operation, amountCoinInt64, coinLimit); err != nil {
		return nil, common.Address{}, 0, 0, 0, err
	}

	senderAccount, exist := account.GetAccountByAddressBytes(tx.TxParam.Sender.GetBytes())
	if !exist || !bytes.Equal(senderAccount.Address[:], tx.TxParam.Sender.GetBytes()) {
		return nil, common.Address{}, 0, 0, 0, fmt.Errorf("no account found in dex transfer")
	}

	dexAccount := account.SetAccountByAddressBytes(dex.GetBytes())

	if dexAccount.Balance-amountCoinInt64 < 0 {
		return nil, common.Address{}, 0, 0, 0, fmt.Errorf("not enough coins in dex account")
	}
	balanceDexToken, err := GetBalance(tx.ContractAddress, dex)
	if err != nil {
		return nil, common.Address{}, 0, 0, 0, err
	}

	if balanceDexToken-amountTokenInt64 < 0 {
		return nil, common.Address{}, 0, 0, 0, fmt.Errorf("not enough tokens in dex account")
	}

	if senderAccount.Balance+amountCoinInt64 < 0 {
		return nil, common.Address{}, 0, 0, 0, fmt.Errorf("not enough coins in account")
	}
	if balanceToken+amountTokenInt64 < 0 {
		return nil, common.Address{}, 0, 0, 0, fmt.Errorf("not enough tokens in account")
	}

	// The trade must not drive either side of THIS pool negative. The checks
	// above bound only the SHARED dex native account, which holds every pool's
	// coins together, so a rounded-average-price payout larger than this pool's
	// own reserve drained other pools' liquidity from the shared account
	// (QWID-2026-25). accDex holds the pre-trade pool state; applying the trade
	// does CoinPool -= amountCoinInt64 / TokenPool -= amountTokenInt64, so a
	// payout (positive amount) above the reserve is refused here.
	if amountCoinInt64 > accDex.CoinPool {
		return nil, common.Address{}, 0, 0, 0, fmt.Errorf("dex trade would overdraw the pool coin reserve: %d > %d", amountCoinInt64, accDex.CoinPool)
	}
	if amountTokenInt64 > accDex.TokenPool {
		return nil, common.Address{}, 0, 0, 0, fmt.Errorf("dex trade would overdraw the pool token reserve: %d > %d", amountTokenInt64, accDex.TokenPool)
	}

	if accDex.Balances[senderAccount.Address].CoinBalance-amountCoinInt64 < 0 && (operation == 6 || operation == 5) {
		return nil, common.Address{}, 0, 0, 0, fmt.Errorf("not enough coins in dex account")
	}
	if accDex.Balances[senderAccount.Address].TokenBalance-amountTokenInt64 < 0 && (operation == 6 || operation == 5) {
		return nil, common.Address{}, 0, 0, 0, fmt.Errorf("not enough tokens in dex account")
	}

	var fromAccountAddress common.Address
	var optData string

	if amountTokenInt64 > 0 {
		dexByte := common.LeftPadBytes(senderAccount.Address[:], 32)
		amountByte := common.LeftPadBytes(common.GetInt64ToBytesSC(amountTokenInt64), 32)
		optData += common.Bytes2Hex(stateDB.TransferFunc)
		optData += common.Bytes2Hex(dexByte)
		optData += common.Bytes2Hex(amountByte)
		fromAccountAddress = dex
	} else if amountTokenInt64 < 0 {
		dexByte := common.LeftPadBytes(dex.GetBytes(), 32)
		amountByte := common.LeftPadBytes(common.GetInt64ToBytesSC(-amountTokenInt64), 32)
		optData += common.Bytes2Hex(stateDB.TransferFunc)
		optData += common.Bytes2Hex(dexByte)
		optData += common.Bytes2Hex(amountByte)
		fromAccountAddress = sender
	}

	loggerMain.GetLogger().Println(optData)
	return common.Hex2Bytes(optData), fromAccountAddress, amountCoinInt64, amountTokenInt64, price, nil
}

func EvaluateSCForBlock(bl Block) (bool, map[[common.HashLength]byte]string, map[[common.HashLength]byte]common.Address, map[[common.AddressLength]byte][]byte, map[[common.HashLength]byte][]byte) {
	addresses := map[[common.HashLength]byte]common.Address{}
	logs := map[[common.HashLength]byte]string{}
	rets := map[[common.HashLength]byte][]byte{}
	optDatas := map[[common.AddressLength]byte][]byte{}
	for _, th := range bl.GetBlockTransactionsHashes() {
		poolprefix := common.TransactionPoolHashesDBPrefix[:]
		t, err := transactionsDefinition.LoadFromDBPoolTx(poolprefix, th.GetBytes())
		if err != nil {
			poolprefix = common.TransactionDBPrefix[:]
			t, err = transactionsDefinition.LoadFromDBPoolTx(poolprefix, th.GetBytes())
			if err != nil {
				loggerMain.GetLogger().Println(err)
				return false, logs, map[[common.HashLength]byte]common.Address{}, map[[common.AddressLength]byte][]byte{}, map[[common.HashLength]byte][]byte{}
			}
		}

		senderAcc, exist := account.GetAccountByAddressBytes(t.TxParam.Sender.GetBytes())
		if !exist {
			loggerMain.GetLogger().Println("no account exist with this address")
			continue
		}
		if senderAcc.TransactionDelay > 0 { // held in escrow at inclusion (S4-02)
			//TODO escrow does not execute SC
			continue

		} else if senderAcc.MultiSignNumber > 0 {
			//TODO MultiSignNumber does not execute SC
			continue
		}

		addressRecipient := t.TxData.Recipient
		if common.IsRecoveryAddress(addressRecipient) || t.IsCommitmentRegistration() {
			continue
		}
		n, err := account.IntDelegatedAccountFromAddress(addressRecipient)
		if err == nil && n > 512 { // 514 == operation 2 etc...
			operation := n - 512
			//DEX checking transaction
			dexOptData, fromAddress, coinAmount, tokenAmount, price, err := GenerateOptDataDEX(t, operation)
			loggerMain.GetLogger().Printf("Token Price: %v\n", price)
			if err != nil {
				// An order that cannot execute against the current state -
				// unknown token, balances or pool too small, its price limit
				// broken - is skipped: its fee was charged in
				// ProcessTransaction and nothing else has moved yet. Making it
				// a block error let one such order (any user's mistake)
				// invalidate every block that carried it, while it stayed in
				// the pool to poison the next one.
				loggerMain.GetLogger().Println("DEX order skipped:", err)
				continue
			}
			// The DEX execution below runs token transfers through the EVM and
			// mutates State (token balances, prices). Mark before executing:
			// conservative marking costs at most one redundant snapshot, while a
			// missed mark would silently corrupt every later rewind.
			StateMutex.Lock()
			State.MarkChanged()
			StateMutex.Unlock()
			// transfering tokens
			l, _, _, _, err := EvaluateSCDex(t.ContractAddress, fromAddress, dexOptData, t, bl)
			if err != nil {
				loggerMain.GetLogger().Println(err)
				if isEVMExecutionError(err) {
					// The token's transfer failed and the EVM reverted it;
					// no coins have moved. Skip the order like above.
					continue
				}
				dropBadTransaction(t, bl, err)
				return false, logs, map[[common.HashLength]byte]common.Address{}, map[[common.AddressLength]byte][]byte{}, map[[common.HashLength]byte][]byte{}
			}
			t.OutputLogs = []byte(l)
			err = t.StoreToDBPoolTx(poolprefix)
			if err != nil {
				loggerMain.GetLogger().Println(err)
				return false, logs, map[[common.HashLength]byte]common.Address{}, map[[common.AddressLength]byte][]byte{}, map[[common.HashLength]byte][]byte{}
			}
			aa := [common.AddressLength]byte{}
			da := [common.AddressLength]byte{}
			copy(aa[:], t.TxParam.Sender.GetBytes())
			dex := common.GetDexAccountAddress()
			copy(da[:], dex.GetBytes())
			// transfering coins KURA

			err = AddBalance(aa, coinAmount)
			if err != nil {
				loggerMain.GetLogger().Println(err)
				dropBadTransaction(t, bl, err)
				return false, nil, nil, nil, nil
			}
			err = AddBalance(da, -coinAmount)
			if err != nil {
				loggerMain.GetLogger().Println(err)
				dropBadTransaction(t, bl, err)
				return false, nil, nil, nil, nil
			}

			ba := [common.AddressLength]byte{}
			copy(ba[:], t.ContractAddress.GetBytes())
			StateMutex.RLock()
			_, ok := State.Tokens[ba]
			StateMutex.RUnlock()
			if !ok {
				loggerMain.GetLogger().Println("no token with a given address")
				dropBadTransaction(t, bl, fmt.Errorf("no token with address %x", ba[:]))
				return false, nil, nil, nil, nil
			}

			accDex := account.GetDexAccountByAddressBytes(t.ContractAddress.GetBytes())

			// Coin base units per whole token (dexTokenPrice): always fits.
			accDex.TokenPrice = price

			if operation == 2 || operation > 4 { // no sell or buy
				balances := accDex.Balances
				if balances == nil {
					balances = make(map[[common.AddressLength]byte]account.CoinTokenDetails)
				}
				coinAmountTmp := accDex.Balances[aa].CoinBalance - coinAmount
				tokenAmountTmp := accDex.Balances[aa].TokenBalance - tokenAmount
				balances[aa] = account.CoinTokenDetails{
					CoinBalance:  coinAmountTmp,
					TokenBalance: tokenAmountTmp,
				}
				accDex.Balances = balances
			} else {
				// Every provider's share moves with the pool, in whole base
				// units (dexShareDelta); an empty pool side moves nothing and
				// a share that cannot be represented is left alone
				// (QWID-2026-24).
				for addr, acc := range accDex.Balances {
					balances := accDex.Balances[addr]
					if tv, ok := dexShareDelta(acc.TokenBalance, -tokenAmount, accDex.TokenPool); ok {
						balances.TokenBalance += tv
					}
					if cv, ok := dexShareDelta(acc.CoinBalance, -coinAmount, accDex.CoinPool); ok {
						balances.CoinBalance += cv
					}
					accDex.Balances[addr] = balances
				}
			}
			accDex.TokenPool += -tokenAmount
			accDex.CoinPool += -coinAmount
			account.SetDexAccountByAddressBytes(t.ContractAddress.GetBytes(), accDex)

			continue
		}
		if err == nil {
			continue
		}
		if len(t.TxData.OptData) == 0 {
			continue
		}
		if _, ok := t.CancellationTarget(); ok {
			continue
		}

		// EvaluateSC deploys or calls a contract on the shared State. Marked
		// before the call for the same reason as the DEX branch above — even a
		// reverted execution may leave persistable traces, and an extra snapshot
		// is cheaper than a rewind on a stale one.
		StateMutex.Lock()
		State.MarkChanged()
		StateMutex.Unlock()
		l, ret, address, _, err := EvaluateSC(t, bl)
		if t.TxData.Recipient == common.EmptyAddress() {
			code := t.TxData.OptData
			if ok := IsTokenToRegister(code); ok && err == nil {
				input := stateDB.NameFunc
				output, _, _, _, _, err := GetViewFunctionReturns(address, input, bl)
				var name string
				if err == nil {
					name = common.GetStringFromSCBytes(common.Hex2Bytes(output), 0)
				}
				input = stateDB.SymbolFunc
				output, _, _, _, _, err = GetViewFunctionReturns(address, input, bl)
				var symbol string
				if err == nil {
					symbol = common.GetStringFromSCBytes(common.Hex2Bytes(output), 0)
				}
				input = stateDB.DecimalsFunc
				output, _, _, _, _, err = GetViewFunctionReturns(address, input, bl)
				// A token that declares more decimals than an int64 amount
				// can carry (or a value that is no number of decimals at
				// all) is not registered: the DEX could not account for it.
				// The low byte of the word used to be taken as it came.
				var decimals uint8
				decimalsOK := true
				if err == nil {
					decimals, decimalsOK = tokenDecimalsFromWord(common.Hex2Bytes(output))
				}
				if decimalsOK {
					StateMutex.Lock()
					State.RegisterNewToken(address, name, symbol, decimals)
					StateMutex.Unlock()
				} else {
					loggerMain.GetLogger().Printf("token %s not registered for the DEX: its decimals() is not a number up to %d",
						address.GetHex(), MaxTokenDecimals)
				}
			}
		}
		if err != nil {
			loggerMain.GetLogger().Println(err)
			if isEVMExecutionError(err) {
				// Phase 3b (CONSENSUS): per-tx contract failure. The EVM's internal
				// snapshot (evm.go Call/create) already reverted this call's value
				// transfer and storage writes. Include the tx (ProcessTransaction
				// charges its size-based fee; value stays with the sender), record
				// it as failed, register NO contract, and do NOT reject the block.
				t.OutputLogs = []byte(l)
				if serr := t.StoreToDBPoolTx(poolprefix); serr != nil {
					loggerMain.GetLogger().Println(serr)
					return false, logs, map[[common.HashLength]byte]common.Address{}, map[[common.AddressLength]byte][]byte{}, map[[common.HashLength]byte][]byte{}
				}
				continue
			}
			// Non-execution (node/processing) error: block-fatal, as before,
			// and the transaction leaves the pool so the next block does not
			// carry it again.
			dropBadTransaction(t, bl, err)
			return false, logs, map[[common.HashLength]byte]common.Address{}, map[[common.AddressLength]byte][]byte{}, map[[common.HashLength]byte][]byte{}
		}
		//TODO we should refund left gas
		//t.GasUsage -= int64(leftOverGas)
		t.ContractAddress = address
		outputLogs := []byte(l)

		t.OutputLogs = outputLogs[:]
		err = t.StoreToDBPoolTx(poolprefix)
		if err != nil {
			loggerMain.GetLogger().Println(err)
			return false, logs, map[[common.HashLength]byte]common.Address{}, map[[common.AddressLength]byte][]byte{}, map[[common.HashLength]byte][]byte{}
		}
		hh := [common.HashLength]byte{}
		copy(hh[:], t.Hash.GetBytes()[:])
		rets[hh] = ret
		addresses[hh] = address
		logs[hh] = l
		aa := [common.AddressLength]byte{}
		copy(aa[:], address.GetBytes()[:])
		optDatas[aa] = t.TxData.OptData
	}
	return true, logs, addresses, optDatas, rets
}

// evmGasBudget converts a transaction's declared gas into the budget handed to
// the VM. It is the LAST line of defence for QWID-2026-11: admission and block
// verification enforce GasUsage <= MaxGasUsage, but this executor must not
// trust that they did — old pools, sync replays and future rule drift all
// deliver transactions that never passed the current Verify. The clamp keeps
// the historic x10 headroom multiplier while making the product incapable of
// exceeding ten block limits or wrapping (both factors are bounded first).
// randaoFromParent supplies the EVM's PREVRANDAO value from the committed
// parent-block hash. See the comment at its use sites; the nil-guard in
// opRandom remains as defence in depth.
func randaoFromParent(bl Block) *common.Hash {
	h := common.BytesToHash(bl.GetHeader().PreviousHash.GetBytes())
	return &h
}

func evmGasBudget(declared int64) uint64 {
	if declared < 0 {
		return 0
	}
	if declared > common.MaxGasUsage {
		declared = common.MaxGasUsage
	}
	// Exactly the declared gas (S6-03): fee, per-transaction and per-block
	// limits all count the declaration, so the EVM may not burn more.
	return uint64(declared)
}

func EvaluateSC(tx transactionsDefinition.Transaction, bl Block) (logs string, ret []byte, address common.Address, leftOverGas uint64, err error) {
	if len(tx.TxData.OptData) == 0 {
		loggerMain.GetLogger().Println("no smart contract in transaction")
		return logs, ret, address, leftOverGas, nil
	}

	origin := tx.TxParam.Sender
	code := tx.TxData.OptData
	// Publish this block's consensus oracle values for the oracle precompiles
	// (0x100 price, 0x101 rand) before any EVM execution (deterministic:
	// the values are sealed in the block being evaluated).
	blockCtx := vm.BlockContext{
		CanTransfer: evmCanTransfer,
		Transfer:    evmTransfer,
		GetHash: func(height uint64) common.Hash {
			hashBytes, _ := LoadHashOfBlock(int64(height))
			return common.BytesToHash(hashBytes)
		},
		Coinbase:    common.EmptyAddress(),
		GasLimit:    uint64(common.MaxGasUsage),
		BlockNumber: new(big.Int).SetInt64(bl.GetHeader().Height),
		// The COMMITTED block timestamp, never the wall clock. Every validator
		// replays this block at a different moment; TIMESTAMP fed from the
		// local clock gave the same transaction different environmental input
		// on each node, so a contract branching on it could split state
		// silently — the header commits no post-state root, so nothing would
		// ever flag the divergence (QWID-2026-10). Replaying old blocks would
		// also be unable to reconstruct the original state.
		Time:       new(big.Int).SetInt64(bl.GetBlockTimeStamp()),
		Difficulty: new(big.Int).SetInt64(int64(bl.GetHeader().Difficulty)),
		BaseFee:    new(big.Int).SetInt64(int64(0)),
		// Consensus-committed and replay-stable: the parent block hash from
		// the header every validator already agreed on. Deterministic across
		// nodes and across time, which is the property QWID-2026-10 demands of
		// every environmental input; deliberately NOT node-local. It is of
		// course miner-known — PREVRANDAO here is an anti-panic determinism
		// value, not a randomness source; contracts needing randomness must
		// use the RAND oracle.
		Random: randaoFromParent(bl),
	}
	logger := vm.CreateGVMLogger()
	jumpTable := vm.GetGenericJumpTable()

	configCtx := vm.Config{
		Debug:                   false, // S6-01: per-opcode tracing slowed every execution ~170x
		Tracer:                  &logger,
		NoBaseFee:               true,
		EnablePreimageRecording: true,
		JumpTable:               &jumpTable,
		ExtraEips:               []int{},
	}
	txCtx := vm.TxContext{
		Origin:   tx.TxParam.Sender,
		GasPrice: new(big.Int).SetInt64(0),
	}
	StateMutex.Lock()
	defer StateMutex.Unlock()
	// Inside the lock (S6-02): the precompiles read package-level values, and
	// every EVM run - block execution and RPC views alike - holds StateMutex,
	// so no concurrent run can replace them before this one reads them.
	vm.SetQwidOracles(bl.BaseBlock.PriceOracle, bl.BaseBlock.RandOracle)

	VM = vm.NewEVM(blockCtx, txCtx, &State, evmChainConfig(), configCtx)
	defer VM.Cancel()

	VM.Origin = origin
	VM.GasPrice = new(big.Int).SetInt64(0)
	nonce := uint64(tx.TxParam.Nonce)

	// Reset all per-transaction transient execution state (journal, snapshot
	// counter, logs, suicides, EIP-2929 access list) so nothing captured
	// during a previous tx (LOG-opcode events, SELFDESTRUCT marks, warm
	// addresses/slots, or an unbounded journal) leaks into this one.
	State.ResetTransient()

	// EIP-2929: warm the tx sender, recipient, and precompiles at tx start.
	var accessDest *common.Address
	if tx.TxData.Recipient != common.EmptyAddress() {
		r := tx.TxData.Recipient
		accessDest = &r
	}
	rules := VM.ChainConfig().Rules(blockCtx.BlockNumber, blockCtx.Random != nil)
	State.PrepareAccessList(tx.TxParam.Sender, accessDest, vm.ActivePrecompiles(rules), nil)

	if tx.TxData.Recipient == common.EmptyAddress() {
		ret, address, leftOverGas, err = VM.Create(vm.AccountRef(origin), code, evmGasBudget(tx.GasUsage), big.NewInt(tx.TxData.Amount), nonce)

		if err != nil {
			loggerMain.GetLogger().Println(err)
			return logger.ToString() + formatEVMLogs(State.GetLogs()), ret, address, leftOverGas, err
		}
	} else {
		address = tx.TxData.Recipient
		ret, leftOverGas, err = VM.Call(vm.AccountRef(origin), address, code, evmGasBudget(tx.GasUsage), big.NewInt(tx.TxData.Amount))
		if err != nil {
			loggerMain.GetLogger().Println(err)
			return logger.ToString() + formatEVMLogs(State.GetLogs()), ret, address, leftOverGas, err
		}
	}
	if err = finishExecution(); err != nil {
		loggerMain.GetLogger().Println(err)
		return logger.ToString(), nil, address, 0, err
	}

	return logger.ToString() + formatEVMLogs(State.GetLogs()), ret, address, leftOverGas, nil
}

// formatEVMLogs renders the LOG-opcode events collected via StateDB.AddLog
// during this execution as a JSON block appended to the tracer output. This
// is additive: it does not replace the existing tracer-based OutputLogs
// content, it feeds the same persistence path (t.OutputLogs) with the
// consensus-relevant contract event logs that were previously discarded
// because AddLog was a no-op.
func formatEVMLogs(evmLogs []*types.Log) string {
	if len(evmLogs) == 0 {
		return ""
	}
	b, err := json.Marshal(evmLogs)
	if err != nil {
		loggerMain.GetLogger().Println(err)
		return ""
	}
	return "\nEVM Logs:\n" + string(b)
}

func EvaluateSCDex(tokenAddress common.Address, sender common.Address, optData []byte, tx transactionsDefinition.Transaction, bl Block) (logs string, ret []byte, address common.Address, leftOverGas uint64, err error) {


	// Publish this block's consensus oracle values for the oracle precompiles
	// (0x100 price, 0x101 rand) before any EVM execution (deterministic:
	// the values are sealed in the block being evaluated).
	blockCtx := vm.BlockContext{
		CanTransfer: evmCanTransfer,
		Transfer:    evmTransfer,
		GetHash: func(height uint64) common.Hash {
			hashBytes, _ := LoadHashOfBlock(int64(height))
			return common.BytesToHash(hashBytes)
		},
		Coinbase:    common.EmptyAddress(),
		GasLimit:    uint64(common.MaxGasUsage),
		BlockNumber: new(big.Int).SetInt64(bl.GetHeader().Height),
		// The COMMITTED block timestamp, never the wall clock. Every validator
		// replays this block at a different moment; TIMESTAMP fed from the
		// local clock gave the same transaction different environmental input
		// on each node, so a contract branching on it could split state
		// silently — the header commits no post-state root, so nothing would
		// ever flag the divergence (QWID-2026-10). Replaying old blocks would
		// also be unable to reconstruct the original state.
		Time:       new(big.Int).SetInt64(bl.GetBlockTimeStamp()),
		Difficulty: new(big.Int).SetInt64(int64(bl.GetHeader().Difficulty)),
		BaseFee:    new(big.Int).SetInt64(int64(0)),
		// Consensus-committed and replay-stable: the parent block hash from
		// the header every validator already agreed on. Deterministic across
		// nodes and across time, which is the property QWID-2026-10 demands of
		// every environmental input; deliberately NOT node-local. It is of
		// course miner-known — PREVRANDAO here is an anti-panic determinism
		// value, not a randomness source; contracts needing randomness must
		// use the RAND oracle.
		Random: randaoFromParent(bl),
	}
	logger := vm.CreateGVMLogger()
	jumpTable := vm.GetGenericJumpTable()

	configCtx := vm.Config{
		Debug:                   false, // S6-01: per-opcode tracing slowed every execution ~170x
		Tracer:                  &logger,
		NoBaseFee:               true,
		EnablePreimageRecording: true,
		JumpTable:               &jumpTable,
		ExtraEips:               []int{},
	}
	txCtx := vm.TxContext{
		Origin:   tx.TxParam.Sender,
		GasPrice: new(big.Int).SetInt64(0),
	}
	StateMutex.Lock()
	defer StateMutex.Unlock()
	// Inside the lock (S6-02): the precompiles read package-level values, and
	// every EVM run - block execution and RPC views alike - holds StateMutex,
	// so no concurrent run can replace them before this one reads them.
	vm.SetQwidOracles(bl.BaseBlock.PriceOracle, bl.BaseBlock.RandOracle)

	//nonce := new(big.Int).SetInt64(int64(tx.TxParam.Nonce))

	VM = vm.NewEVM(blockCtx, txCtx, &State, evmChainConfig(), configCtx)
	defer VM.Cancel()

	VM.Origin = sender
	VM.GasPrice = new(big.Int).SetInt64(0)

	// Reset all per-transaction transient execution state before invoking the
	// VM so warm access-list entries / suicide marks / journal from a prior
	// EvaluateSC or EvaluateSCDex call don't bleed into this DEX execution.
	State.ResetTransient()

	ret, leftOverGas, err = VM.Call(vm.AccountRef(sender), tokenAddress, optData, uint64(common.DexTokenCallGas), new(big.Int).SetInt64(0))
	if err != nil {
		return logger.ToString(), ret, tokenAddress, leftOverGas, err
	}
	if err = finishExecution(); err != nil {
		return logger.ToString(), nil, tokenAddress, 0, err
	}

	return logger.ToString(), ret, tokenAddress, leftOverGas, nil
}

func GetViewFunctionReturns(contractAddr common.Address, OptData []byte, bl Block) (outputs string, logs string, ret []byte, address common.Address, leftOverGas uint64, err error) {

	origin := common.EmptyAddress()
	input := OptData
	// Publish this block's consensus oracle values for the oracle precompiles
	// (0x100 price, 0x101 rand) before any EVM execution (deterministic:
	// the values are sealed in the block being evaluated).
	blockCtx := vm.BlockContext{
		CanTransfer: evmCanTransfer,
		Transfer:    evmTransfer,
		GetHash: func(height uint64) common.Hash {
			hashBytes, _ := LoadHashOfBlock(int64(height))
			return common.BytesToHash(hashBytes)
		},
		Coinbase:    common.EmptyAddress(),
		GasLimit:    uint64(common.MaxGasUsage),
		BlockNumber: new(big.Int).SetInt64(bl.GetHeader().Height),
		// The COMMITTED block timestamp, never the wall clock. Every validator
		// replays this block at a different moment; TIMESTAMP fed from the
		// local clock gave the same transaction different environmental input
		// on each node, so a contract branching on it could split state
		// silently — the header commits no post-state root, so nothing would
		// ever flag the divergence (QWID-2026-10). Replaying old blocks would
		// also be unable to reconstruct the original state.
		Time:       new(big.Int).SetInt64(bl.GetBlockTimeStamp()),
		Difficulty: new(big.Int).SetInt64(int64(bl.GetHeader().Difficulty)),
		BaseFee:    new(big.Int).SetInt64(int64(0)),
		// Consensus-committed and replay-stable: the parent block hash from
		// the header every validator already agreed on. Deterministic across
		// nodes and across time, which is the property QWID-2026-10 demands of
		// every environmental input; deliberately NOT node-local. It is of
		// course miner-known — PREVRANDAO here is an anti-panic determinism
		// value, not a randomness source; contracts needing randomness must
		// use the RAND oracle.
		Random: randaoFromParent(bl),
	}
	logger := vm.CreateGVMLogger()
	jumpTable := vm.GetGenericJumpTable()

	configCtx := vm.Config{
		Debug:                   false, // S6-01: per-opcode tracing slowed every execution ~170x
		Tracer:                  &logger,
		NoBaseFee:               true,
		EnablePreimageRecording: true,
		JumpTable:               &jumpTable,
		ExtraEips:               []int{},
	}
	txCtx := vm.TxContext{
		Origin:   origin,
		GasPrice: new(big.Int).SetInt64(0),
	}
	StateMutex.Lock()
	defer StateMutex.Unlock()
	// Inside the lock (S6-02): the precompiles read package-level values, and
	// every EVM run - block execution and RPC views alike - holds StateMutex,
	// so no concurrent run can replace them before this one reads them.
	vm.SetQwidOracles(bl.BaseBlock.PriceOracle, bl.BaseBlock.RandOracle)
	VM = vm.NewEVM(blockCtx, txCtx, &State, evmChainConfig(), configCtx)
	defer VM.Cancel()

	VM.Origin = origin
	VM.GasPrice = new(big.Int).SetInt64(0)

	// Reset all per-transaction transient execution state before invoking the
	// VM so warm access-list entries / suicide marks / journal from a prior
	// EvaluateSC or EvaluateSCDex call don't bleed into this view execution.
	State.ResetTransient()

	ret, leftOverGas, err = VM.StaticCall(vm.AccountRef(origin), contractAddr, input, uint64(common.MaxGasUsage))
	// The output is the call's return data, hex-encoded - what the tracer's
	// CaptureExit used to record for the top frame before tracing was turned
	// off (S6-01). A revert or out-of-gas is an error (S6-05): read as empty
	// output it made a DEX token balance look like 0.
	output := hex.EncodeToString(ret)
	if err != nil {
		return output, string(ret), ret, address, leftOverGas, err
	}
	return output, string(ret), ret, address, leftOverGas, nil
}

func IsTokenToRegister(code []byte) bool {
	toRegister := true
	if bytes.Index(code, stateDB.NameFunc) < 0 {
		toRegister = false
	}
	if bytes.Index(code, stateDB.BalanceOfFunc) < 0 {
		toRegister = false
	}
	if bytes.Index(code, stateDB.TransferFunc) < 0 {
		toRegister = false
	}
	if bytes.Index(code, stateDB.SymbolFunc) < 0 {
		toRegister = false
	}
	if bytes.Index(code, stateDB.DecimalsFunc) < 0 {
		toRegister = false
	}
	return toRegister
}

func GetBalance(coin common.Address, owner common.Address) (int64, error) {

	inputs := stateDB.BalanceOfFunc
	ba := common.LeftPadBytes(owner.GetBytes(), 32)
	inputs = append(inputs, ba...)

	h := common.GetHeight()

	var bl Block
	var err error

	bl, err = LoadBlock(h - 1)
	if err != nil {
		loggerMain.GetLogger().Println(err)
		return 0, err
	}

	output, _, _, _, _, err := GetViewFunctionReturns(coin, inputs, bl)
	if err != nil {
		loggerMain.GetLogger().Println("Some error in SC query Get Balance", err)
		return 0, err
	}
	if output != "" {
		// The whole 256-bit word: a balance beyond int64 is refused, not
		// wrapped into a negative or truncated number.
		bal, ok := common.Int64FromSCWord(common.Hex2Bytes(output))
		if !ok {
			return 0, fmt.Errorf("token %s: balance of %s does not fit in int64", coin.GetHex(), owner.GetHex())
		}
		return bal, nil
	} else {
		return 0, nil
	}
}
