package account

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/qwid-org/qwid-node/common"
)

var zeroCommit [common.AddressLength]byte

func matured(pendingHeight, height int64) bool {
	return height >= pendingHeight+common.RecoveryCommitMaturityBlocks
}

// EffectiveRecoveryCommit is the recovery commitment a reveal at `height`
// must match.
func (a Account) EffectiveRecoveryCommit(height int64) [common.AddressLength]byte {
	if a.RecoveryPendingCommit != zeroCommit && matured(a.RecoveryPendingHeight, height) {
		return a.RecoveryPendingCommit
	}
	return a.RecoveryCommit
}

// EffectiveSpareCommit is the address the spare key revealed at `height`
// must have.
func (a Account) EffectiveSpareCommit(height int64) [common.AddressLength]byte {
	if a.SparePendingCommit != zeroCommit && matured(a.RecoveryPendingHeight, height) {
		return a.SparePendingCommit
	}
	return a.SpareCommit
}

// HasCommitments reports whether the account has any commitment, active or
// pending.
func (a Account) HasCommitments() bool {
	return a.RecoveryCommit != zeroCommit || a.RecoveryPendingCommit != zeroCommit ||
		a.SpareCommit != zeroCommit || a.SparePendingCommit != zeroCommit
}

// promoteMatured moves pending commitments that matured by height into the
// active ones and clears them; unmatured ones stay pending.
func (a *Account) promoteMatured(height int64) {
	if !matured(a.RecoveryPendingHeight, height) {
		return
	}
	if a.RecoveryPendingCommit != zeroCommit {
		a.RecoveryCommit = a.RecoveryPendingCommit
	}
	if a.SparePendingCommit != zeroCommit {
		a.SpareCommit = a.SparePendingCommit
	}
	a.RecoveryPendingCommit, a.SparePendingCommit, a.RecoveryPendingHeight = zeroCommit, zeroCommit, 0
}

// SetCommitments records a registration's spare and recovery commitments
// (zero = leave that one unchanged). An account's first commitments - set
// when it is opened - apply at once: there is nothing earlier for an attacker
// to replace. Every later change is pending: it applies after
// RecoveryCommitMaturityBlocks, the latest change wins, and a scheme break
// voids it before then (VoidPendingRecoveryCommits).
func (a *Account) SetCommitments(spare, c [common.AddressLength]byte, height int64) {
	if !a.HasCommitments() {
		a.SpareCommit, a.RecoveryCommit = spare, c
		return
	}
	a.promoteMatured(height)
	a.SparePendingCommit, a.RecoveryPendingCommit, a.RecoveryPendingHeight = spare, c, height
}

// ConsumeRecoveryCommit: a reveal is authorised by S itself, so its next
// recovery commitment needs no maturing. The spare commitment is untouched.
func (a *Account) ConsumeRecoveryCommit(next [common.AddressLength]byte) {
	a.RecoveryCommit = next
	a.RecoveryPendingCommit = zeroCommit
	if a.SparePendingCommit == zeroCommit {
		a.RecoveryPendingHeight = 0
	}
}

func SetAccountCommitments(addr, spare, c [common.AddressLength]byte, height int64) error {
	AccountsRWMutex.Lock()
	defer AccountsRWMutex.Unlock()
	acc, ok := Accounts.AllAccounts[addr]
	if !ok {
		return fmt.Errorf("no account %x to set commitments on", addr)
	}
	acc.SetCommitments(spare, c, height)
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
// broken (blocks.schemeBroken). Pending commitments may have been written with
// a key of that scheme, so only those that matured before the break survive
// (promoted); the rest are dropped. Returns how many accounts lost some.
func VoidPendingRecoveryCommits(height int64) int {
	AccountsRWMutex.Lock()
	defer AccountsRWMutex.Unlock()
	dropped := 0
	for k, acc := range Accounts.AllAccounts {
		if acc.RecoveryPendingCommit == zeroCommit && acc.SparePendingCommit == zeroCommit {
			continue
		}
		acc.promoteMatured(height)
		if acc.RecoveryPendingCommit != zeroCommit || acc.SparePendingCommit != zeroCommit {
			dropped++
			acc.RecoveryPendingCommit, acc.SparePendingCommit, acc.RecoveryPendingHeight = zeroCommit, zeroCommit, 0
		}
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
