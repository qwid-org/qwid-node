package account

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/qwid-org/qwid-node/common"
)

var zeroCommit [common.AddressLength]byte

// EffectiveRecoveryCommit is the commitment a reveal at `height` must match.
func (a Account) EffectiveRecoveryCommit(height int64) [common.AddressLength]byte {
	if a.RecoveryPendingCommit != zeroCommit && height >= a.RecoveryPendingHeight+common.RecoveryCommitMaturityBlocks {
		return a.RecoveryPendingCommit
	}
	return a.RecoveryCommit
}

// SetPendingRecoveryCommit: the latest commitment wins, but only after
// maturing; one that already matured is kept as the active commitment.
func (a *Account) SetPendingRecoveryCommit(c [common.AddressLength]byte, height int64) {
	a.RecoveryCommit = a.EffectiveRecoveryCommit(height)
	a.RecoveryPendingCommit = c
	a.RecoveryPendingHeight = height
}

// ConsumeRecoveryCommit: a reveal is authorised by S itself, so its next
// commitment needs no maturing.
func (a *Account) ConsumeRecoveryCommit(next [common.AddressLength]byte) {
	a.RecoveryCommit = next
	a.RecoveryPendingCommit = zeroCommit
	a.RecoveryPendingHeight = 0
}

func SetAccountPendingRecoveryCommit(addr, c [common.AddressLength]byte, height int64) error {
	AccountsRWMutex.Lock()
	defer AccountsRWMutex.Unlock()
	acc, ok := Accounts.AllAccounts[addr]
	if !ok {
		return fmt.Errorf("no account %x to set a recovery commitment on", addr)
	}
	acc.SetPendingRecoveryCommit(c, height)
	Accounts.AllAccounts[addr] = acc
	return nil
}

func ConsumeAccountRecoveryCommit(addr, next [common.AddressLength]byte) error {
	AccountsRWMutex.Lock()
	defer AccountsRWMutex.Unlock()
	acc, ok := Accounts.AllAccounts[addr]
	if !ok {
		return fmt.Errorf("no account %x to consume a recovery commitment of", addr)
	}
	acc.ConsumeRecoveryCommit(next)
	Accounts.AllAccounts[addr] = acc
	return nil
}

// VoidPendingRecoveryCommits runs when a block marks a signature scheme as
// broken (blocks.schemeBroken). A pending commitment may have been written
// with a key of that scheme, so only those that matured before the break
// survive (promoted); the rest are dropped. Returns how many dropped.
func VoidPendingRecoveryCommits(height int64) int {
	AccountsRWMutex.Lock()
	defer AccountsRWMutex.Unlock()
	dropped := 0
	for k, acc := range Accounts.AllAccounts {
		if acc.RecoveryPendingCommit == zeroCommit {
			continue
		}
		if height >= acc.RecoveryPendingHeight+common.RecoveryCommitMaturityBlocks {
			acc.RecoveryCommit = acc.RecoveryPendingCommit
		} else {
			dropped++
		}
		acc.RecoveryPendingCommit = zeroCommit
		acc.RecoveryPendingHeight = 0
		Accounts.AllAccounts[k] = acc
	}
	return dropped
}

type RecoveryBind struct {
	Identity [common.AddressLength]byte
	Payload  [32]byte
	Height   int64
}

func sortedBindKeys(m map[[32]byte]RecoveryBind) [][32]byte {
	keys := make([][32]byte, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i][:], keys[j][:]) < 0 })
	return keys
}

// SortRecoveryBindKeys is for the state root, which walks binds in a fixed
// order while already holding AccountsRWMutex - so it takes no lock itself
// (a nested RLock deadlocks behind a waiting writer).
func SortRecoveryBindKeys(m map[[32]byte]RecoveryBind) [][32]byte {
	return sortedBindKeys(m)
}

// AddRecoveryBind keeps the FIRST bind per key: S becomes public only when
// revealed, so an attacker's bind for the same tag is always the later one.
func AddRecoveryBind(key [32]byte, b RecoveryBind) bool {
	AccountsRWMutex.Lock()
	defer AccountsRWMutex.Unlock()
	if Accounts.RecoveryBinds == nil {
		Accounts.RecoveryBinds = map[[32]byte]RecoveryBind{}
	}
	if _, exists := Accounts.RecoveryBinds[key]; exists {
		return false
	}
	Accounts.RecoveryBinds[key] = b
	return true
}

func GetRecoveryBind(key [32]byte) (RecoveryBind, bool) {
	AccountsRWMutex.RLock()
	defer AccountsRWMutex.RUnlock()
	b, ok := Accounts.RecoveryBinds[key]
	return b, ok
}

func DeleteRecoveryBind(key [32]byte) {
	AccountsRWMutex.Lock()
	defer AccountsRWMutex.Unlock()
	delete(Accounts.RecoveryBinds, key)
}

// PruneRecoveryBinds bounds the store: binds cost a fee, and expire.
func PruneRecoveryBinds(height int64) int {
	AccountsRWMutex.Lock()
	defer AccountsRWMutex.Unlock()
	n := 0
	for k, b := range Accounts.RecoveryBinds {
		if height > b.Height+common.RecoveryBindExpiryBlocks {
			delete(Accounts.RecoveryBinds, k)
			n++
		}
	}
	return n
}
