package transactionsPool

import (
	"encoding/binary"
	"sort"
	"sync"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// Pending-pool journal (audit 2026-10-07 F3-07).
//
// The escrow and multisig pools are consensus state: block application adds
// held transfers to them and settles, cancels or moves them out again. Both
// are mirrored to the database, but a rewind restored balances from snapshots
// and left the pools as they were. A settlement inside the rewound range was
// never repeated when the canonical blocks were applied again - the entry was
// gone - and an entry added by an orphaned block stayed pending. After a fork
// or a kill -9 under escrow traffic the node's balances drifted from the
// network's and every later block failed its state root check.
//
// Every pool change made while a block is applied is therefore journalled
// under that block's height, with the transaction itself, and
// UndoPendingPoolsAbove reverts the changes above a rewind target, newest
// first. Key: prefix + height (8, big-endian) + sequence (4, big-endian);
// value: pool ('E' escrow, 'M' multisig) + kind ('A' added, 'R' removed) +
// transaction bytes.

const (
	journalEscrow   = 'E'
	journalMultiSig = 'M'
	journalAdded    = 'A'
	journalRemoved  = 'R'
)

var (
	journalMu     sync.Mutex
	journalHeight int64 // 0: no block is being applied, nothing is journalled
	journalSeq    uint32
	// journalPaused is set while the journal itself is being undone.
	journalPaused bool
)

func pendingJournalPrefix(height int64) []byte {
	k := append([]byte{}, common.PendingPoolJournalDBPrefix[:]...)
	return binary.BigEndian.AppendUint64(k, uint64(height))
}

// BeginPendingPoolJournal starts journalling pool changes for the block at
// height. Entries already journalled at that height belong to an apply that
// failed or was cut short by a crash, against the same parent state, so they
// are undone first.
func BeginPendingPoolJournal(height int64) {
	undoPendingPoolsAt(height)
	journalMu.Lock()
	journalHeight, journalSeq = height, 0
	journalMu.Unlock()
}

// EndPendingPoolJournal stops journalling.
func EndPendingPoolJournal() {
	journalMu.Lock()
	journalHeight = 0
	journalMu.Unlock()
}

func journalPendingChange(pool, kind byte, tx transactionsDefinition.Transaction) {
	journalMu.Lock()
	if journalHeight <= 0 || journalPaused {
		journalMu.Unlock()
		return
	}
	key := binary.BigEndian.AppendUint32(pendingJournalPrefix(journalHeight), journalSeq)
	journalSeq++
	height := journalHeight
	journalMu.Unlock()
	value := append([]byte{pool, kind}, tx.GetBytes()...)
	if err := database.MainDB.Put(key, value); err != nil {
		logger.GetLogger().Printf("WARNING: could not journal a pending-pool change at height %d: %v", height, err)
	}
}

// UndoPendingPoolsAbove reverts every journalled pool change of the blocks
// above target, newest first, and drops those journal entries. It is called on
// every rewind and at startup, where a block cut short by a crash may have
// changed the pools without being stored.
func UndoPendingPoolsAbove(target int64) {
	keys, err := database.MainDB.LoadAllKeys(common.PendingPoolJournalDBPrefix[:])
	if err != nil {
		logger.GetLogger().Println("pending-pool journal scan failed:", err)
		return
	}
	undoJournalKeys(keys, func(h int64) bool { return h > target })
}

func undoPendingPoolsAt(height int64) {
	keys, err := database.MainDB.LoadAllKeys(pendingJournalPrefix(height))
	if err != nil {
		logger.GetLogger().Println("pending-pool journal scan failed at height", height, ":", err)
		return
	}
	undoJournalKeys(keys, func(int64) bool { return true })
}

func undoJournalKeys(keys [][]byte, undo func(height int64) bool) {
	const keyLen = 2 + 8 + 4
	sel := keys[:0]
	for _, k := range keys {
		if len(k) == keyLen && undo(int64(binary.BigEndian.Uint64(k[2:10]))) {
			sel = append(sel, k)
		}
	}
	if len(sel) == 0 {
		return
	}
	// Big-endian height and sequence: byte order is apply order.
	sort.Slice(sel, func(i, j int) bool { return string(sel[i]) > string(sel[j]) })
	journalMu.Lock()
	journalPaused = true
	journalMu.Unlock()
	defer func() {
		journalMu.Lock()
		journalPaused = false
		journalMu.Unlock()
	}()
	undone := 0
	for _, k := range sel {
		v, err := database.MainDB.Get(k)
		if err == nil && len(v) > 2 {
			mt := &transactionsDefinition.Transaction{}
			if tx, _, derr := mt.GetFromBytes(v[2:]); derr == nil {
				undoPendingChange(v[0], v[1], tx)
				undone++
			} else {
				logger.GetLogger().Println("undecodable pending-pool journal entry dropped:", derr)
			}
		}
		_ = database.MainDB.Delete(k)
	}
	logger.GetLogger().Printf("pending pools: undid %d journalled change(s)", undone)
}

func undoPendingChange(pool, kind byte, tx transactionsDefinition.Transaction) {
	hash := tx.GetHash().GetBytes()
	switch {
	case pool == journalEscrow && kind == journalAdded:
		RemoveEscrowTransaction(hash)
	case pool == journalEscrow && kind == journalRemoved:
		AddEscrowTransaction(tx)
	case pool == journalMultiSig && kind == journalAdded:
		RemoveMultiSignTransaction(hash)
	case pool == journalMultiSig && kind == journalRemoved:
		AddMultiSignTransaction(tx)
	}
}
