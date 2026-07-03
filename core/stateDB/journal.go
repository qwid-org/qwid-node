package stateDB

import "github.com/wonabru/qwid-node/common"

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
