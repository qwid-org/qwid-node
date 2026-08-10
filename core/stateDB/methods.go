package stateDB

import (
	"math"
	"math/big"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/core/types"
	"github.com/qwid-org/qwid-node/crypto"
	"github.com/qwid-org/qwid-node/logger"
)

type TokenInfo struct {
	Name     string `json:"name"`
	Symbols  string `json:"symbols"`
	Decimals uint8  `json:"decimals"`
}

type StateAccount struct {
	Accounts            map[[common.AddressLength]byte]account.Account                      `json:"accounts"`
	Codes               map[[common.AddressLength]byte][]byte                               `json:"codes"`
	CodeHashes          map[[common.AddressLength]byte]common.Hash                          `json:"codeHashes"`
	StatesHashes        map[[common.AddressLength]byte]map[common.Hash]common.Hash          `json:"statesHashes"`
	Nonces              map[[common.AddressLength]byte]uint64                               `json:"nonces"`
	States              map[common.Hash][]byte                                              `json:"states"`
	Balances            map[[common.AddressLength]byte]map[[common.AddressLength]byte]int64 `json:"balances"`
	Tokens              map[[common.AddressLength]byte]TokenInfo                            `json:"tokens"`
	SnapShotNum         int                                                                 `json:"snapShotNum"`
	journal             []changeEntry
	logs                []*types.Log                                        // transient
	suicided            map[[common.AddressLength]byte]bool                 // transient
	accessAddrs         map[[common.AddressLength]byte]bool                 // transient, EIP-2929 warm addresses
	accessSlots         map[[common.AddressLength]byte]map[common.Hash]bool // transient, EIP-2929 warm slots
	refund              uint64                                              // transient
	HeightToSnapShotNum map[int64]int                                       `json:"HeightToSnapShotNum"` // suppose int should be replaced by int64
	ContractsByHeight   map[int64][][common.AddressLength]byte              `json:"contractsByHeight"`
	// changedSinceStore is true when the persistable EVM state may have changed
	// since the last successful Store/Load. It drives the store-on-change
	// persistence model: a full state snapshot is written only for blocks that
	// actually executed a contract/DEX/token transaction, so disk usage grows
	// with contract activity instead of chain length. The invariant that makes
	// the closest-at-or-below snapshot lookup exact is: every height at which
	// the state changed has its own snapshot. Marking is conservative — a mark
	// without a real change costs one redundant snapshot; a change without a
	// mark corrupts every later rewind, so when in doubt, mark.
	changedSinceStore bool // transient, guarded by blocks.StateMutex like the rest
}

func CreateStateDB() StateAccount {
	sa := StateAccount{}
	sa.Accounts = map[[common.AddressLength]byte]account.Account{}
	sa.Codes = map[[common.AddressLength]byte][]byte{}
	sa.CodeHashes = map[[common.AddressLength]byte]common.Hash{}
	sa.Nonces = map[[common.AddressLength]byte]uint64{}
	sa.StatesHashes = map[[common.AddressLength]byte]map[common.Hash]common.Hash{}
	sa.States = map[common.Hash][]byte{}
	sa.Balances = map[[common.AddressLength]byte]map[[common.AddressLength]byte]int64{}
	sa.Tokens = map[[common.AddressLength]byte]TokenInfo{}
	sa.SnapShotNum = 0
	sa.journal = nil
	sa.suicided = map[[common.AddressLength]byte]bool{}
	sa.accessAddrs = map[[common.AddressLength]byte]bool{}
	sa.accessSlots = map[[common.AddressLength]byte]map[common.Hash]bool{}
	sa.HeightToSnapShotNum = map[int64]int{}
	sa.ContractsByHeight = map[int64][][common.AddressLength]byte{}
	return sa
}

// MarkChanged records that the persistable EVM state may differ from the last
// stored snapshot. Store and Load clear it on success.
func (sa *StateAccount) MarkChanged() {
	sa.changedSinceStore = true
}

// ChangedSinceStore reports whether the state may differ from the last
// successful Store/Load.
func (sa *StateAccount) ChangedSinceStore() bool {
	return sa.changedSinceStore
}

func (sa *StateAccount) SetSnapShotNum(height int64, snapNum int) {
	(*sa).HeightToSnapShotNum[height] = snapNum
}

func (sa *StateAccount) GetSnapShotNum(height int64) (int, bool) {
	sn, ok := sa.HeightToSnapShotNum[height]
	return sn, ok
}

func (sa *StateAccount) RecordContractCreation(height int64, addr [common.AddressLength]byte) {
	sa.ContractsByHeight[height] = append(sa.ContractsByHeight[height], addr)
}

func (sa *StateAccount) CleanupContractsAfterHeight(height int64) {
	for h, contracts := range sa.ContractsByHeight {
		if h > height {
			for _, addr := range contracts {
				delete(sa.Nonces, addr)
				delete(sa.Codes, addr)
				delete(sa.CodeHashes, addr)
			}
			delete(sa.ContractsByHeight, h)
		}
	}
}

func (sa *StateAccount) CreateAccount(a common.Address) {
	addrb := [common.AddressLength]byte{}
	copy(addrb[:], a.ByteValue[:])
	acc := account.Account{
		Balance:               0,
		Address:               addrb,
		TransactionDelay:      0,
		MultiSignNumber:       0,
		MultiSignAddresses:    make([][20]byte, 0),
		TransactionsSender:    make([]common.Hash, 0),
		TransactionsRecipient: make([]common.Hash, 0),
	}
	(*sa).Accounts[a.ByteValue] = acc
}

func (sa *StateAccount) GetAllRegisteredTokens() map[[common.AddressLength]byte]TokenInfo {
	return sa.Tokens
}

func (sa *StateAccount) RegisterNewToken(a common.Address, name string, symbol string, decimals uint8) {
	ti := TokenInfo{
		Name:     name,
		Symbols:  symbol,
		Decimals: decimals,
	}
	(*sa).Tokens[a.ByteValue] = ti
}

// bigToBaseUnits converts an EVM *big.Int amount (base units, 1:1 with native
// QWD) to int64. ok is false when the amount is outside int64 range; callers
// saturate rather than wrap (unreachable with valid balances).
func bigToBaseUnits(amount *big.Int) (v int64, ok bool) {
	if amount == nil {
		return 0, true
	}
	if !amount.IsInt64() {
		return 0, false
	}
	return amount.Int64(), true
}

func (sa *StateAccount) AddBalance(a common.Address, amount *big.Int) {
	amt, ok := bigToBaseUnits(amount)
	if !ok {
		logger.GetLogger().Println("EVM AddBalance: amount exceeds int64 range, saturating", a.GetHex())
		amt = math.MaxInt64
	}
	prev := account.GetBalance(a.ByteValue)
	next := prev + amt
	if next < prev { // int64 overflow => saturate
		next = math.MaxInt64
	}
	if next == prev {
		return
	}
	sa.journal = append(sa.journal, balanceChange{addr: a.ByteValue, prev: prev})
	sa.SnapShotNum = len(sa.journal)
	account.SetBalance(a.ByteValue, next)
}

func (sa *StateAccount) SubBalance(a common.Address, amount *big.Int) {
	amt, ok := bigToBaseUnits(amount)
	if !ok {
		logger.GetLogger().Println("EVM SubBalance: amount exceeds int64 range, saturating", a.GetHex())
		amt = math.MaxInt64
	}
	prev := account.GetBalance(a.ByteValue)
	// amt is non-negative (EVM balances are uint256-derived) and both operands
	// are in [0, MaxInt64], so prev-amt cannot int64-underflow; a negative
	// result just means "insufficient balance" => floor at 0 (a native balance
	// must never go negative).
	next := prev - amt
	if next < 0 {
		next = 0
	}
	if next == prev {
		return
	}
	sa.journal = append(sa.journal, balanceChange{addr: a.ByteValue, prev: prev})
	sa.SnapShotNum = len(sa.journal)
	account.SetBalance(a.ByteValue, next)
}
func (sa *StateAccount) GetBalance(a common.Address) *big.Int {
	return new(big.Int).SetInt64(account.GetBalance(a.ByteValue))
}

func (sa *StateAccount) GetNonce(a common.Address) uint64 {
	return sa.Nonces[a.ByteValue]
}
func (sa *StateAccount) SetNonce(a common.Address, n uint64) {
	(*sa).Nonces[a.ByteValue] = n
}

func (sa *StateAccount) GetCodeHash(a common.Address) common.Hash {
	return sa.CodeHashes[a.ByteValue]
}

func (sa *StateAccount) GetCode(a common.Address) []byte {
	return sa.Codes[a.ByteValue]
}

func (sa *StateAccount) SetCode(a common.Address, c []byte) {
	(*sa).Codes[a.ByteValue] = c
	(*sa).CodeHashes[a.ByteValue] = crypto.Keccak256Hash(c)
}

func (sa *StateAccount) GetCodeSize(a common.Address) int {
	return len(sa.Codes[a.ByteValue])
}

func (sa *StateAccount) AddRefund(gas uint64) {
	sa.refund += gas
}
func (sa *StateAccount) SubRefund(gas uint64) {
	if gas > sa.refund {
		sa.refund = 0 // clamp; refund is not applied to the fee this phase (DB-C4 accounting-only)
		return
	}
	sa.refund -= gas
}
func (sa *StateAccount) GetRefund() uint64 {
	return sa.refund
}

func (sa *StateAccount) GetCommittedState(a common.Address, h common.Hash) common.Hash {
	s, ok := sa.StatesHashes[a.ByteValue]
	if ok {
		return s[h]
	}
	return common.Hash{}
}
func (sa *StateAccount) GetState(a common.Address, h common.Hash) common.Hash {
	s, ok := sa.StatesHashes[a.ByteValue]
	if ok {
		return s[h]
	}
	return common.Hash{}
}
func (sa *StateAccount) SetState(a common.Address, h common.Hash, h2 common.Hash) {
	m, ok := sa.StatesHashes[a.ByteValue]
	if !ok {
		m = map[common.Hash]common.Hash{}
		sa.StatesHashes[a.ByteValue] = m
	}
	prev, existed := m[h]
	sa.journal = append(sa.journal, slotChange{addr: a.ByteValue, key: h, prev: prev, existed: existed})
	sa.SnapShotNum = len(sa.journal)
	m[h] = h2
}

func (sa *StateAccount) Suicide(a common.Address) bool {
	if _, ok := sa.Accounts[a.ByteValue]; !ok {
		return false
	}
	if sa.suicided == nil {
		sa.suicided = map[[common.AddressLength]byte]bool{}
	}
	if !sa.suicided[a.ByteValue] {
		sa.journal = append(sa.journal, suicideChange{addr: a.ByteValue})
		sa.SnapShotNum = len(sa.journal)
		sa.suicided[a.ByteValue] = true
	}
	return true
}

func (sa *StateAccount) HasSuicided(a common.Address) bool {
	return sa.suicided[a.ByteValue]
}

// Exist reports whether the given account exists in state.
// Notably this should also return true for suicided accounts.
func (sa *StateAccount) Exist(a common.Address) bool {
	_, ok := sa.Accounts[a.ByteValue]
	return ok
}

// Empty returns whether the given account is empty per EIP-161
// (nonce == 0 && code == 0 && balance == 0).
func (sa *StateAccount) Empty(a common.Address) bool {
	return sa.Nonces[a.ByteValue] == 0 && len(sa.Codes[a.ByteValue]) == 0 &&
		sa.GetBalance(a).Sign() == 0
}

// PrepareAccessList resets the warm address/slot sets for a new transaction
// and pre-warms the sender, destination, precompiles, and the tx's EIP-2930
// access list, per EIP-2929/2930. This bypasses the journal since it only
// happens at the start of a transaction, before any snapshot can be taken.
func (sa *StateAccount) PrepareAccessList(sender common.Address, dest *common.Address, precompiles []common.Address, txAccesses types.AccessList) {
	sa.accessAddrs = map[[common.AddressLength]byte]bool{}
	sa.accessSlots = map[[common.AddressLength]byte]map[common.Hash]bool{}
	sa.addAddrNoJournal(sender)
	if dest != nil {
		sa.addAddrNoJournal(*dest)
	}
	for _, p := range precompiles {
		sa.addAddrNoJournal(p)
	}
	for _, tuple := range txAccesses {
		sa.addAddrNoJournal(tuple.Address)
		for _, h := range tuple.StorageKeys {
			sa.addSlotNoJournal(tuple.Address, h)
		}
	}
}

func (sa *StateAccount) addAddrNoJournal(a common.Address) {
	sa.accessAddrs[a.ByteValue] = true
}

func (sa *StateAccount) addSlotNoJournal(a common.Address, slot common.Hash) {
	m, ok := sa.accessSlots[a.ByteValue]
	if !ok {
		m = map[common.Hash]bool{}
		sa.accessSlots[a.ByteValue] = m
	}
	m[slot] = true
}

func (sa *StateAccount) AddressInAccessList(addr common.Address) bool {
	return sa.accessAddrs[addr.ByteValue]
}

func (sa *StateAccount) SlotInAccessList(addr common.Address, slot common.Hash) (addressOk bool, slotOk bool) {
	addressOk = sa.accessAddrs[addr.ByteValue]
	if m, ok := sa.accessSlots[addr.ByteValue]; ok {
		slotOk = m[slot]
	}
	return addressOk, slotOk
}

// AddAddressToAccessList adds the given address to the access list. This operation is safe to perform
// even if the feature/fork is not active yet
func (sa *StateAccount) AddAddressToAccessList(addr common.Address) {
	if sa.accessAddrs == nil {
		sa.accessAddrs = map[[common.AddressLength]byte]bool{}
	}
	if !sa.accessAddrs[addr.ByteValue] {
		sa.journal = append(sa.journal, accessAddrChange{addr: addr.ByteValue})
		sa.SnapShotNum = len(sa.journal)
		sa.accessAddrs[addr.ByteValue] = true
	}
}

// AddSlotToAccessList adds the given (address,slot) to the access list. This operation is safe to perform
// even if the feature/fork is not active yet
func (sa *StateAccount) AddSlotToAccessList(addr common.Address, slot common.Hash) {
	sa.AddAddressToAccessList(addr)
	if sa.accessSlots == nil {
		sa.accessSlots = map[[common.AddressLength]byte]map[common.Hash]bool{}
	}
	m, ok := sa.accessSlots[addr.ByteValue]
	if !ok || !m[slot] {
		sa.journal = append(sa.journal, accessSlotChange{addr: addr.ByteValue, slot: slot})
		sa.SnapShotNum = len(sa.journal)
		sa.addSlotNoJournal(addr, slot)
	}
}

func (sa *StateAccount) RevertToSnapshot(sn int) {
	if sn < 0 {
		sn = 0
	}
	if sn > len(sa.journal) {
		sn = len(sa.journal)
	}
	for i := len(sa.journal) - 1; i >= sn; i-- {
		sa.journal[i].revert(sa)
	}
	sa.journal = sa.journal[:sn]
	sa.SnapShotNum = sn
}

func (sa *StateAccount) Snapshot() int {
	return len(sa.journal)
}

func (sa *StateAccount) AddLog(l *types.Log) {
	sa.journal = append(sa.journal, logChange{})
	sa.SnapShotNum = len(sa.journal)
	sa.logs = append(sa.logs, l)
}

// GetLogs returns the logs accumulated during the current execution.
func (sa *StateAccount) GetLogs() []*types.Log { return sa.logs }

// ClearLogs resets the per-execution log buffer (call before running a tx).
func (sa *StateAccount) ClearLogs() { sa.logs = nil }

// ClearSuicided resets the per-execution suicide set (call before running a tx).
func (sa *StateAccount) ClearSuicided() { sa.suicided = map[[common.AddressLength]byte]bool{} }

// ClearAccessList resets the per-execution EIP-2929 warm address/slot sets
// (call before running a tx).
func (sa *StateAccount) ClearAccessList() {
	sa.accessAddrs = map[[common.AddressLength]byte]bool{}
	sa.accessSlots = map[[common.AddressLength]byte]map[common.Hash]bool{}
}

// ResetTransient clears all per-transaction execution state (journal, snapshot
// counter, logs, suicides, access list). Call it before each top-level VM
// invocation so transient state never leaks across transactions on the shared
// singleton StateAccount.
func (sa *StateAccount) ResetTransient() {
	sa.journal = nil
	sa.SnapShotNum = 0
	sa.logs = nil
	sa.suicided = map[[common.AddressLength]byte]bool{}
	sa.accessAddrs = map[[common.AddressLength]byte]bool{}
	sa.accessSlots = map[[common.AddressLength]byte]map[common.Hash]bool{}
	sa.refund = 0
}
func (sa *StateAccount) AddPreimage(h common.Hash, b []byte) {
	(*sa).States[h] = b
}

func (sa *StateAccount) GetCoinBalance(acc common.Address, coin common.Address) int64 {
	_, ok := sa.Balances[acc.ByteValue]
	if ok {
		return sa.Balances[acc.ByteValue][coin.ByteValue]
	} else {
		return 0
	}
}

func (sa *StateAccount) SetCoinBalance(acc common.Address, coin common.Address, value int64) {
	_, ok := sa.Balances[acc.ByteValue]
	if ok {
		(*sa).Balances[acc.ByteValue][coin.ByteValue] = value
	} else {
		(*sa).Balances[acc.ByteValue] = map[[common.AddressLength]byte]int64{coin.ByteValue: value}
	}
}

//func (sa *StateAccount) getStateObject(a common.Address) *stateObject {
//
//}

func (sa *StateAccount) ForEachStorage(a common.Address, cb func(key common.Hash, value common.Hash) bool) error {

	shs, ok := sa.StatesHashes[a.ByteValue]
	if !ok {
		return nil
	}
	for h, value := range shs {
		if !cb(h, value) {
			return nil
		}
	}

	return nil
}
