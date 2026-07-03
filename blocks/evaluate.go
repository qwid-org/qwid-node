package blocks

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/common"
	vm "github.com/wonabru/qwid-node/core/evm"
	"github.com/wonabru/qwid-node/core/stateDB"
	"github.com/wonabru/qwid-node/core/types"
	loggerMain "github.com/wonabru/qwid-node/logger"
	"github.com/wonabru/qwid-node/params"
	"github.com/wonabru/qwid-node/transactionsDefinition"
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

func InitStateDB() {
	StateMutex.Lock()
	defer StateMutex.Unlock()
	State = stateDB.CreateStateDB()
	// Phase 1: restore persisted EVM state so contracts survive restarts.
	if err := State.Load(-1); err != nil {
		loggerMain.GetLogger().Println("could not load persisted EVM state (starting empty):", err)
	}
}

// CommitEVMState persists the current EVM state for a block height. Call it
// wherever native accounts are stored on block finalize.
func CommitEVMState(height int64) error {
	StateMutex.Lock()
	defer StateMutex.Unlock()
	return State.Store(height)
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
		amountCoinInt64 = int64(-amountCoinFloat * math.Pow10(int(common.Decimals)))
		amountTokenInt64 = int64(-amountTokenFloat * math.Pow10(int(ti.Decimals)))
		price = common.RoundToken(amountCoinFloat/amountTokenFloat, int(common.Decimals+ti.Decimals))
	case 5: // withdraw token
		if poolPrice > 0 {
			price = poolPrice
			amount := common.RoundCoin(poolPrice * amountTokenFloat)
			amountCoinInt64 = int64(amount * math.Pow10(int(common.Decimals)))
			amountTokenInt64 = int64(amountTokenFloat * math.Pow10(int(ti.Decimals)))
		}
	case 6: // withdraw Coin
		if poolPrice > 0 {
			price = poolPrice
			amount := common.RoundToken(1.0/poolPrice*amountCoinFloat, int(ti.Decimals))
			amountTokenInt64 = int64(amount * math.Pow10(int(ti.Decimals)))
			amountCoinInt64 = int64(amountCoinFloat * math.Pow10(int(common.Decimals)))
		}
	case 3: //buy
		if coinPoolAmount > 0 && tokenPoolAmount-2*amountTokenFloat > 0 {
			price = common.RoundToken(coinPoolAmount/(tokenPoolAmount-2*amountTokenFloat), int(common.Decimals+ti.Decimals))
		}
		if price > 0 {
			amount := common.RoundCoin(-price * amountTokenFloat)
			amountCoinInt64 = int64(amount * math.Pow10(int(common.Decimals)))
			amountTokenInt64 = int64(amountTokenFloat * math.Pow10(int(ti.Decimals)))
		}
	case 4: //sell
		amountTokenFloat *= -1
		if coinPoolAmount > 0 && tokenPoolAmount-2*amountTokenFloat > 0 {
			price = common.RoundToken(coinPoolAmount/(tokenPoolAmount-2*amountTokenFloat), int(common.Decimals+ti.Decimals))
		}
		if price > 0 {
			amount := common.RoundCoin(-price * amountTokenFloat)
			amountCoinInt64 = int64(amount * math.Pow10(int(common.Decimals)))
			amountTokenInt64 = int64(amountTokenFloat * math.Pow10(int(ti.Decimals)))
		}
	default:
		return nil, common.Address{}, 0, 0, 0, fmt.Errorf("wrong operation on dex")
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

			accDex.TokenPrice = int64(price * math.Pow10(int(common.Decimals+ti.Decimals)))

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
		CanTransfer: nil,
		Transfer:    nil,
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

	// Reset the per-execution log buffer so LOG-opcode events (StateDB.AddLog,
	// invoked by the interpreter for LOG0-LOG4) captured during this tx don't
	// leak into the next one.
	State.ClearLogs()

	if tx.TxData.Recipient == common.EmptyAddress() {
		ret, address, leftOverGas, err = VM.Create(vm.AccountRef(origin), code, uint64(tx.GasUsage)*uint64(gasMult), new(big.Int).SetInt64(0), nonce)

		if err != nil {
			loggerMain.GetLogger().Println(err)
			return logger.ToString() + formatEVMLogs(State.GetLogs()), ret, address, leftOverGas, err
		}
	} else {
		address = tx.TxData.Recipient
		ret, leftOverGas, err = VM.Call(vm.AccountRef(origin), address, code, uint64(tx.GasUsage)*uint64(gasMult), new(big.Int).SetInt64(0))
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
		CanTransfer: nil,
		Transfer:    nil,
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
		CanTransfer: nil,
		Transfer:    nil,
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
	ret, leftOverGas, err = VM.StaticCall(vm.AccountRef(origin), contractAddr, input, uint64(common.MaxGasUsage))
	// Konwersja hex do bajtów
	dataBytes, err := hex.DecodeString(logger.Output)
	if err != nil {
		loggerMain.GetLogger().Fatal(err)
	}

	// Konwersja bajtów do UTF-8
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
