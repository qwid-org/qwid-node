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
	"github.com/qwid-org/qwid-node/params"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"math"
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
	if _, err := account.IntDelegatedAccountFromAddress(tx.TxData.Recipient); err == nil {
		return false // delegated recipient (staking/reward/DEX) — not an SC call
	}
	if senderAcc.MultiSignNumber > 0 {
		return false // multisign accounts skip SC execution
	}
	if senderAcc.TransactionDelay > 0 && tx.GetHeight()+senderAcc.TransactionDelay > height {
		return false // escrow-delayed — SC not executed
	}
	return true
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
		errors.Is(err, vm.ErrNonceUintOverflow):
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

// constantProductPrice returns the exact constant-product (x*y=k) average
// execution price coinPool/(tokenPool - amountToken), rounded to roundDecimals,
// or 0 when the pools/denominator are non-positive (e.g. a buy of the whole
// token pool, which is not allowed). amountToken is SIGNED: >0 for a buy (tokens
// leave the pool), <0 for a sell (tokens enter the pool). Using amountToken
// (not the old 2*amountToken) makes swaps exact x*y=k (AC-H6): the price
// diverges only as a trade approaches the full pool, never at half the pool.
func constantProductPrice(coinPool, tokenPool, amountToken float64, roundDecimals int) float64 {
	denom := tokenPool - amountToken
	if coinPool > 0 && denom > 0 {
		return common.RoundToken(coinPool/denom, roundDecimals)
	}
	return 0
}

// scaleToInt64 converts a whole-unit float amount to base units (amount * 10^decimals),
// returning ok=false when the result would not fit in an int64. This avoids the
// non-portable `int64(hugeFloat)` conversion (implementation-defined in Go when the
// value overflows), which would otherwise make DEX pricing non-deterministic across
// architectures near the full-pool boundary (AC-H6).
func scaleToInt64(amount float64, decimals int) (int64, bool) {
	scaled := amount * math.Pow10(decimals)
	if math.IsNaN(scaled) || math.IsInf(scaled, 0) || math.Abs(scaled) >= float64(math.MaxInt64) {
		return 0, false
	}
	return int64(scaled), true
}

// scaleTokenPrice converts a whole-unit price into the int64 the DEX account
// stores, scaling by 10^(coinDecimals+tokenDecimals).
//
// This value is serialised into consensus state (account/dexAccount.go), so an
// implementation-defined `int64(hugeFloat)` here is not merely a wrong number:
// amd64 yields the minimum int64 and arm64 saturates to the maximum, so two
// nodes on different architectures would write different state for the same
// block and fork. The multiplier is the SUM of the decimals, which leaves very
// little headroom — 10^16 for an 8-decimal token, so any price at or above
// ~922 overflows.
//
// The two decimal counts are widened to int before being added. The callers'
// original expression added them as uint8, which wraps above 247.
func scaleTokenPrice(price float64, coinDecimals, tokenDecimals uint8) (int64, bool) {
	return scaleToInt64(price, int(coinDecimals)+int(tokenDecimals))
}

func GenerateOptDataDEX(tx transactionsDefinition.Transaction, operation int) ([]byte, common.Address, int64, int64, float64, error) {
	// 2 - adding liquidity, 3 - buy trade, 4 -sell trade, 5 - withdraw token, 6 - withdraw KURA (5,6 inactive, just withdraw is selling opposite)
	amountToken := common.GetInt64FromByte(tx.TxData.OptData)
	sender := tx.TxParam.Sender
	tokenAddress := tx.ContractAddress
	if operation == 2 && (tx.TxData.Amount < 0 || amountToken < 0) || (operation == 3 || operation == 4) && (amountToken == 0) || operation == 5 && amountToken == 0 || operation == 6 && tx.TxData.Amount == 0 {
		return nil, common.Address{}, 0, 0, 0, fmt.Errorf("withdraw one can perform on one currency the second should be 0")
	}

	accDex := account.GetDexAccountByAddressBytes(tokenAddress.GetBytes())
	poolPrice := float64(0)
	price := 0.0
	var amountCoinInt64, amountTokenInt64 int64
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

	tokenPoolAmount := account.Int64toFloat64ByDecimals(accDex.TokenPool, ti.Decimals)
	coinPoolAmount := account.Int64toFloat64(accDex.CoinPool)
	amountTokenFloat := account.Int64toFloat64ByDecimals(amountToken, ti.Decimals)
	amountCoinFloat := account.Int64toFloat64ByDecimals(tx.TxData.Amount, common.Decimals)

	if coinPoolAmount > 0 && tokenPoolAmount > 0 {
		poolPrice = common.RoundToken(coinPoolAmount/tokenPoolAmount, int(common.Decimals+ti.Decimals))
	}

	// dex account where all tokens liquidity are stored
	dex := common.GetDexAccountAddress()

	switch operation {
	case 2: // add liquidity
		c, okC := scaleToInt64(-amountCoinFloat, int(common.Decimals))
		tkn, okT := scaleToInt64(-amountTokenFloat, int(ti.Decimals))
		if !okC || !okT {
			return nil, common.Address{}, 0, 0, 0, fmt.Errorf("dex add liquidity: amount does not fit in int64")
		}
		amountCoinInt64, amountTokenInt64 = c, tkn
		price = common.RoundToken(amountCoinFloat/amountTokenFloat, int(common.Decimals+ti.Decimals))
	case 5: // withdraw token
		if poolPrice > 0 {
			price = poolPrice
			amount := common.RoundCoin(poolPrice * amountTokenFloat)
			c, okC := scaleToInt64(amount, int(common.Decimals))
			tkn, okT := scaleToInt64(amountTokenFloat, int(ti.Decimals))
			if !okC || !okT {
				return nil, common.Address{}, 0, 0, 0, fmt.Errorf("dex withdraw token: amount does not fit in int64")
			}
			amountCoinInt64, amountTokenInt64 = c, tkn
		}
	case 6: // withdraw Coin
		if poolPrice > 0 {
			price = poolPrice
			amount := common.RoundToken(1.0/poolPrice*amountCoinFloat, int(ti.Decimals))
			tkn, okT := scaleToInt64(amount, int(ti.Decimals))
			c, okC := scaleToInt64(amountCoinFloat, int(common.Decimals))
			if !okC || !okT {
				return nil, common.Address{}, 0, 0, 0, fmt.Errorf("dex withdraw coin: amount does not fit in int64")
			}
			amountTokenInt64, amountCoinInt64 = tkn, c
		}
	case 3: //buy
		price = constantProductPrice(coinPoolAmount, tokenPoolAmount, amountTokenFloat, int(common.Decimals+ti.Decimals))
		if price > 0 {
			amount := common.RoundCoin(-price * amountTokenFloat)
			c, okC := scaleToInt64(amount, int(common.Decimals))
			tkn, okT := scaleToInt64(amountTokenFloat, int(ti.Decimals))
			if !okC || !okT {
				return nil, common.Address{}, 0, 0, 0, fmt.Errorf("dex trade: amount does not fit in int64")
			}
			amountCoinInt64 = c
			amountTokenInt64 = tkn
		}
	case 4: //sell
		amountTokenFloat *= -1
		price = constantProductPrice(coinPoolAmount, tokenPoolAmount, amountTokenFloat, int(common.Decimals+ti.Decimals))
		if price > 0 {
			amount := common.RoundCoin(-price * amountTokenFloat)
			c, okC := scaleToInt64(amount, int(common.Decimals))
			tkn, okT := scaleToInt64(amountTokenFloat, int(ti.Decimals))
			if !okC || !okT {
				return nil, common.Address{}, 0, 0, 0, fmt.Errorf("dex trade: amount does not fit in int64")
			}
			amountCoinInt64 = c
			amountTokenInt64 = tkn
		}
	default:
		return nil, common.Address{}, 0, 0, 0, fmt.Errorf("wrong operation on dex")
	}

	// Reject here, while we can still refuse the transaction. EvaluateSCForBlock
	// scales this same price into accDex.TokenPrice when the block is applied,
	// and its only failure mode is rejecting the whole block — which would let
	// one crafted transaction kill every block carrying it. Validating at
	// transaction level means the value provably fits by the time it is stored.
	if _, ok := scaleTokenPrice(price, common.Decimals, ti.Decimals); !ok {
		return nil, common.Address{}, 0, 0, 0, fmt.Errorf("dex: token price %v does not fit in int64 at %d decimals", price, int(common.Decimals)+int(ti.Decimals))
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
	height := bl.GetHeader().Height
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
		if senderAcc.TransactionDelay > 0 && t.GetHeight()+senderAcc.TransactionDelay > height {
			//TODO escrow does not execute SC
			continue

		} else if senderAcc.MultiSignNumber > 0 {
			//TODO MultiSignNumber does not execute SC
			continue
		}

		addressRecipient := t.TxData.Recipient
		n, err := account.IntDelegatedAccountFromAddress(addressRecipient)
		if err == nil && n > 512 { // 514 == operation 2 etc...
			operation := n - 512
			//DEX checking transaction
			dexOptData, fromAddress, coinAmount, tokenAmount, price, err := GenerateOptDataDEX(t, operation)
			loggerMain.GetLogger().Printf("Token Price: %v\n", price)
			if err != nil {
				loggerMain.GetLogger().Println(err)
				return false, nil, nil, nil, nil
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
				return false, nil, nil, nil, nil
			}
			err = AddBalance(da, -coinAmount)
			if err != nil {
				loggerMain.GetLogger().Println(err)
				return false, nil, nil, nil, nil
			}

			ba := [common.AddressLength]byte{}
			copy(ba[:], t.ContractAddress.GetBytes())
			StateMutex.RLock()
			ti, ok := State.Tokens[ba]
			StateMutex.RUnlock()
			if !ok {
				loggerMain.GetLogger().Println("no token with a given address")
				return false, nil, nil, nil, nil
			}

			accDex := account.GetDexAccountByAddressBytes(t.ContractAddress.GetBytes())

			// GenerateOptDataDEX above already refused any price that does not
			// fit, so this cannot fail. Guarded anyway, and on failure the stored
			// price is left untouched rather than rejecting the block: a
			// deterministic skip cannot fork the chain, whereas returning false
			// here would make one transaction invalidate the entire block.
			if scaledPrice, ok := scaleTokenPrice(price, common.Decimals, ti.Decimals); ok {
				accDex.TokenPrice = scaledPrice
			} else {
				loggerMain.GetLogger().Printf("WARNING: dex token price %v does not fit in int64; keeping the previous stored price", price)
			}

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
				coinPercentTmp := float64(-coinAmount) / float64(accDex.CoinPool)
				tokenPercentTmp := float64(-tokenAmount) / float64(accDex.TokenPool)

				for addr, acc := range accDex.Balances {
					balances := accDex.Balances[addr]
					balances.TokenBalance += int64(common.RoundToken(tokenPercentTmp*float64(acc.TokenBalance), int(ti.Decimals)))
					balances.CoinBalance += int64(common.RoundToken(coinPercentTmp*float64(acc.CoinBalance), int(common.Decimals)))
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
				var decimals uint8
				if err == nil {
					decimals = uint8(common.GetUintFromSCByte(common.Hex2Bytes(output)))
				}
				StateMutex.Lock()
				State.RegisterNewToken(address, name, symbol, decimals)
				StateMutex.Unlock()
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
			// Non-execution (node/processing) error: block-fatal, as before.
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

func EvaluateSC(tx transactionsDefinition.Transaction, bl Block) (logs string, ret []byte, address common.Address, leftOverGas uint64, err error) {
	if len(tx.TxData.OptData) == 0 {
		loggerMain.GetLogger().Println("no smart contract in transaction")
		return logs, ret, address, leftOverGas, nil
	}
	gasMult := 10.0

	origin := tx.TxParam.Sender
	code := tx.TxData.OptData
	blockCtx := vm.BlockContext{
		CanTransfer: evmCanTransfer,
		Transfer:    evmTransfer,
		GetHash: func(height uint64) common.Hash {
			hashBytes, _ := LoadHashOfBlock(int64(height))
			return common.BytesToHash(hashBytes)
		},
		Coinbase:    common.EmptyAddress(),
		GasLimit:    uint64(common.MaxGasUsage) * uint64(gasMult),
		BlockNumber: new(big.Int).SetInt64(bl.GetHeader().Height),
		Time:        new(big.Int).SetInt64(common.GetCurrentTimeStampInSecond()),
		Difficulty:  new(big.Int).SetInt64(int64(bl.GetHeader().Difficulty)),
		BaseFee:     new(big.Int).SetInt64(int64(0)),
		Random:      nil,
	}
	logger := vm.CreateGVMLogger()
	jumpTable := vm.GetGenericJumpTable()

	configCtx := vm.Config{
		Debug:                   true,
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

	VM = vm.NewEVM(blockCtx, txCtx, &State, params.AllEthashProtocolChanges, configCtx)
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
		ret, address, leftOverGas, err = VM.Create(vm.AccountRef(origin), code, uint64(tx.GasUsage)*uint64(gasMult), big.NewInt(tx.TxData.Amount), nonce)

		if err != nil {
			loggerMain.GetLogger().Println(err)
			return logger.ToString() + formatEVMLogs(State.GetLogs()), ret, address, leftOverGas, err
		}
	} else {
		address = tx.TxData.Recipient
		ret, leftOverGas, err = VM.Call(vm.AccountRef(origin), address, code, uint64(tx.GasUsage)*uint64(gasMult), big.NewInt(tx.TxData.Amount))
		if err != nil {
			loggerMain.GetLogger().Println(err)
			return logger.ToString() + formatEVMLogs(State.GetLogs()), ret, address, leftOverGas, err
		}
	}

	return logger.ToString() + formatEVMLogs(State.GetLogs()), ret, address, uint64(float64(leftOverGas) / gasMult), nil
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

	gasMult := 10.0

	blockCtx := vm.BlockContext{
		CanTransfer: evmCanTransfer,
		Transfer:    evmTransfer,
		GetHash: func(height uint64) common.Hash {
			hashBytes, _ := LoadHashOfBlock(int64(height))
			return common.BytesToHash(hashBytes)
		},
		Coinbase:    common.EmptyAddress(),
		GasLimit:    uint64(common.MaxGasUsage) * uint64(gasMult),
		BlockNumber: new(big.Int).SetInt64(bl.GetHeader().Height),
		Time:        new(big.Int).SetInt64(common.GetCurrentTimeStampInSecond()),
		Difficulty:  new(big.Int).SetInt64(int64(bl.GetHeader().Difficulty)),
		BaseFee:     new(big.Int).SetInt64(int64(0)),
		Random:      nil,
	}
	logger := vm.CreateGVMLogger()
	jumpTable := vm.GetGenericJumpTable()

	configCtx := vm.Config{
		Debug:                   true,
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

	//nonce := new(big.Int).SetInt64(int64(tx.TxParam.Nonce))

	VM = vm.NewEVM(blockCtx, txCtx, &State, params.AllEthashProtocolChanges, configCtx)
	defer VM.Cancel()

	VM.Origin = sender
	VM.GasPrice = new(big.Int).SetInt64(0)

	// Reset all per-transaction transient execution state before invoking the
	// VM so warm access-list entries / suicide marks / journal from a prior
	// EvaluateSC or EvaluateSCDex call don't bleed into this DEX execution.
	State.ResetTransient()

	ret, leftOverGas, err = VM.Call(vm.AccountRef(sender), tokenAddress, optData, uint64(210000), new(big.Int).SetInt64(0))
	if err != nil {
		return logger.ToString(), ret, tokenAddress, leftOverGas, err
	}

	return logger.ToString(), ret, tokenAddress, uint64(float64(leftOverGas) / gasMult), nil
}

func GetViewFunctionReturns(contractAddr common.Address, OptData []byte, bl Block) (outputs string, logs string, ret []byte, address common.Address, leftOverGas uint64, err error) {

	origin := common.EmptyAddress()
	input := OptData
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
		Time:        new(big.Int).SetInt64(common.GetCurrentTimeStampInSecond()),
		Difficulty:  new(big.Int).SetInt64(int64(bl.GetHeader().Difficulty)),
		BaseFee:     new(big.Int).SetInt64(int64(0)),
		Random:      nil,
	}
	logger := vm.CreateGVMLogger()
	jumpTable := vm.GetGenericJumpTable()

	configCtx := vm.Config{
		Debug:                   true,
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
	VM = vm.NewEVM(blockCtx, txCtx, &State, params.AllEthashProtocolChanges, configCtx)
	defer VM.Cancel()

	VM.Origin = origin
	VM.GasPrice = new(big.Int).SetInt64(0)

	// Reset all per-transaction transient execution state before invoking the
	// VM so warm access-list entries / suicide marks / journal from a prior
	// EvaluateSC or EvaluateSCDex call don't bleed into this view execution.
	State.ResetTransient()

	ret, leftOverGas, err = VM.StaticCall(vm.AccountRef(origin), contractAddr, input, uint64(common.MaxGasUsage))
	// Convert hex to bytes
	dataBytes, err := hex.DecodeString(logger.Output)
	if err != nil {
		loggerMain.GetLogger().Fatal(err)
	}

	// Convert bytes to UTF-8
	decodedString := string(dataBytes)
	if err != nil {
		return logger.Output, decodedString, ret, address, leftOverGas, err
	}

	return logger.Output, decodedString, ret, address, leftOverGas, nil
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
		bal := common.GetInt64FromSCByte(common.Hex2Bytes(output))
		return bal, nil
	} else {
		return 0, nil
	}
}
