package blocks

import (
	"bytes"
	"fmt"
	"hash"
	"sort"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/blake2b"
	"github.com/qwid-org/qwid-node/database"
)

// ComputeStateRoot hashes the consensus state - accounts, staking, DEX and
// EVM - in a canonical order (S3-05). It is what a block's StateRoot commits
// to: the producer stamps the root of its state after the parent block, and
// every validator compares it with its own before applying the block.
//
// Only consensus-relevant fields are hashed. Histories (transaction index
// counters, staking detail logs, EVM preimages) and wall-clock stamps are left
// out: they are bookkeeping, and staking details carry time.Now() values that
// differ between nodes by design.
func ComputeStateRoot() (common.Hash, error) {
	h, err := blake2b.New256(nil)
	if err != nil {
		return common.Hash{}, err
	}
	w := rootWriter{h: h}

	w.section("accounts")
	account.AccountsRWMutex.RLock()
	accs := account.Accounts.AllAccounts
	for _, k := range sortedAddrKeys(accs) {
		a := accs[k]
		w.bytes(k[:])
		w.i64(a.Balance)
		w.i64(a.TransactionDelay)
		w.i64(int64(a.MultiSignNumber))
		w.i64(int64(len(a.MultiSignAddresses)))
		for _, m := range a.MultiSignAddresses {
			w.bytes(m[:])
		}
	}
	account.AccountsRWMutex.RUnlock()

	w.section("staking")
	account.StakingRWMutex.RLock()
	for id := range account.StakingAccounts {
		all := account.StakingAccounts[id].AllStakingAccounts
		if len(all) == 0 {
			continue
		}
		w.i64(int64(id))
		for _, k := range sortedAddrKeys(all) {
			sa := all[k]
			w.bytes(k[:])
			w.i64(sa.StakedBalance)
			w.i64(sa.StakingRewards)
			w.i64s(sa.LockedAmount)
			w.i64s(sa.ReleasePerBlock)
			w.i64s(sa.LockedInitBlock)
			w.bytes(sa.DelegatedAccount[:])
			w.bool(sa.OperationalAccount)
			w.i64(sa.OperationalSince)
			w.i64(sa.LastStakeHeight)
			w.bytes(sa.RandCommit[:])
			w.i64(sa.RandCommitHeight)
		}
	}
	account.StakingRWMutex.RUnlock()

	w.section("dex")
	account.DexRWMutex.RLock()
	dex := account.DexAccounts.AllDexAccounts
	for _, k := range sortedAddrKeys(dex) {
		d := dex[k]
		w.bytes(k[:])
		w.i64(d.CoinPool)
		w.i64(d.TokenPool)
		w.i64(d.TokenPrice)
		for _, owner := range sortedAddrKeys(d.Balances) {
			w.bytes(owner[:])
			w.i64(d.Balances[owner].CoinBalance)
			w.i64(d.Balances[owner].TokenBalance)
		}
	}
	account.DexRWMutex.RUnlock()

	w.section("evm")
	StateMutex.RLock()
	for _, k := range sortedAddrKeys(State.Accounts) {
		w.bytes(k[:])
	}
	for _, k := range sortedAddrKeys(State.Codes) {
		w.bytes(k[:])
		w.bytes(State.Codes[k])
	}
	for _, k := range sortedAddrKeys(State.Nonces) {
		w.bytes(k[:])
		w.i64(int64(State.Nonces[k]))
	}
	for _, k := range sortedAddrKeys(State.StatesHashes) {
		slots := State.StatesHashes[k]
		w.bytes(k[:])
		keys := make([]common.Hash, 0, len(slots))
		for s := range slots {
			keys = append(keys, s)
		}
		sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i][:], keys[j][:]) < 0 })
		for _, s := range keys {
			v := slots[s]
			w.bytes(s[:])
			w.bytes(v[:])
		}
	}
	for _, k := range sortedAddrKeys(State.Tokens) {
		t := State.Tokens[k]
		w.bytes(k[:])
		w.bytes([]byte(t.Name))
		w.bytes([]byte(t.Symbols))
		w.i64(int64(t.Decimals))
	}
	StateMutex.RUnlock()

	return common.GetHashFromBytes(h.Sum(nil)), nil
}

// VerifyStateRoot checks a block's StateRoot against this node's current
// state, which must be the state after the block's parent. Height 0 has no
// parent state and carries none.
func VerifyStateRoot(block Block) error {
	if block.GetHeader().Height == 0 {
		return nil
	}
	ours, err := ComputeStateRoot()
	if err != nil {
		return err
	}
	if !bytes.Equal(ours.GetBytes(), block.GetHeader().StateRoot.GetBytes()) {
		return fmt.Errorf("block %d state root %x does not match our state %x", block.GetHeader().Height,
			block.GetHeader().StateRoot.GetBytes()[:8], ours.GetBytes()[:8])
	}
	return nil
}

// rootWriter writes length-delimited fields, so concatenations of different
// fields can never produce the same byte stream.
type rootWriter struct{ h hash.Hash }

func (w rootWriter) bytes(b []byte) {
	w.h.Write(common.GetByteInt64(int64(len(b))))
	w.h.Write(b)
}
func (w rootWriter) i64(v int64)      { w.h.Write(common.GetByteInt64(v)) }
func (w rootWriter) section(s string) { w.bytes([]byte(s)) }
func (w rootWriter) bool(v bool) {
	if v {
		w.i64(1)
	} else {
		w.i64(0)
	}
}
func (w rootWriter) i64s(vs []int64) {
	w.i64(int64(len(vs)))
	for _, v := range vs {
		w.i64(v)
	}
}

func sortedAddrKeys[V any](m map[[common.AddressLength]byte]V) [][common.AddressLength]byte {
	keys := make([][common.AddressLength]byte, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i][:], keys[j][:]) < 0 })
	return keys
}

// Crash consistency (S9-03). Applying a block writes the block and then the
// accounts, staking, EVM and DEX snapshots separately; a crash in between left
// a height whose block is stored but whose state is partly missing or stale,
// and startup only checked accounts and staking. StoreStateCommit is called
// after the last snapshot write and records the root of the in-memory state
// (the state after block height). VerifyStateCommit, run at startup once all
// snapshots of that height are loaded, accepts the height only if the marker
// exists and the loaded state hashes to it.
func StoreStateCommit(height int64) error {
	root, err := ComputeStateRoot()
	if err != nil {
		return err
	}
	return database.MainDB.Put(stateCommitKey(height), root.GetBytes())
}

func VerifyStateCommit(height int64) error {
	want, err := database.MainDB.Get(stateCommitKey(height))
	if err != nil || len(want) != common.HashLength {
		return fmt.Errorf("height %d was never committed (no state commit marker)", height)
	}
	root, err := ComputeStateRoot()
	if err != nil {
		return err
	}
	if !bytes.Equal(root.GetBytes(), want) {
		return fmt.Errorf("stored state at height %d does not match its commit marker", height)
	}
	return nil
}

func stateCommitKey(height int64) []byte {
	return append(common.StateCommitDBPrefix[:], common.GetByteInt64(height)...)
}
