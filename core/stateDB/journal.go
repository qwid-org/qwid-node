package stateDB

import (
	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
)

// changeEntry is one reversible mutation recorded during execution.
type changeEntry interface {
	revert(sa *StateAccount)
}

// slotChange restores a storage slot to its prior value (or removes it if it
// did not exist before).
type slotChange struct {
	addr    [common.AddressLength]byte
	key     common.Hash
	prev    common.Hash
	existed bool
}

func (c slotChange) revert(sa *StateAccount) {
	m, ok := sa.StatesHashes[c.addr]
	if !ok {
		return
	}
	if !c.existed {
		delete(m, c.key)
		return
	}
	m[c.key] = c.prev
}

// logChange removes the last-added log on revert.
type logChange struct{}

func (logChange) revert(sa *StateAccount) {
	if n := len(sa.logs); n > 0 {
		sa.logs = sa.logs[:n-1]
	}
}

// suicideChange unmarks a suicide on revert.
type suicideChange struct {
	addr [common.AddressLength]byte
}

func (c suicideChange) revert(sa *StateAccount) {
	delete(sa.suicided, c.addr)
}

// accessAddrChange unmarks a warm address on revert.
type accessAddrChange struct{ addr [common.AddressLength]byte }

func (c accessAddrChange) revert(sa *StateAccount) { delete(sa.accessAddrs, c.addr) }

// accessSlotChange unmarks a warm (address, slot) pair on revert.
type accessSlotChange struct {
	addr [common.AddressLength]byte
	slot common.Hash
}

func (c accessSlotChange) revert(sa *StateAccount) {
	if m, ok := sa.accessSlots[c.addr]; ok {
		delete(m, c.slot)
	}
}

// balanceChange restores a native account balance to its prior value on revert.
type balanceChange struct {
	addr [common.AddressLength]byte
	prev int64
}

func (c balanceChange) revert(sa *StateAccount) {
	account.SetBalance(c.addr, c.prev)
}

// createAccountChange undoes CreateAccount (S6-06): a reverted CREATE must not
// leave its address behind.
type createAccountChange struct {
	addr    [common.AddressLength]byte
	prev    account.Account
	existed bool
}

func (c createAccountChange) revert(sa *StateAccount) {
	if c.existed {
		sa.Accounts[c.addr] = c.prev
		return
	}
	delete(sa.Accounts, c.addr)
}

// nonceChange undoes SetNonce (S6-06): a failed constructor used to leave its
// address at nonce 1, so the same CREATE could never be repeated.
type nonceChange struct {
	addr    [common.AddressLength]byte
	prev    uint64
	existed bool
}

func (c nonceChange) revert(sa *StateAccount) {
	if c.existed {
		sa.Nonces[c.addr] = c.prev
		return
	}
	delete(sa.Nonces, c.addr)
}

// codeChange undoes SetCode (S6-06).
type codeChange struct {
	addr     [common.AddressLength]byte
	prevCode []byte
	prevHash common.Hash
	existed  bool
}

func (c codeChange) revert(sa *StateAccount) {
	if c.existed {
		sa.Codes[c.addr] = c.prevCode
		sa.CodeHashes[c.addr] = c.prevHash
		return
	}
	delete(sa.Codes, c.addr)
	delete(sa.CodeHashes, c.addr)
}
