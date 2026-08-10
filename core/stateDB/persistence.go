package stateDB

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/core/types"
	"github.com/wonabru/qwid-node/database"
	"github.com/wonabru/qwid-node/logger"
)

// persistedStateJSON is the JSON-serializable representation with string keys.
type persistedStateJSON struct {
	Accounts     map[string]account.Account   `json:"accounts"`
	Codes        map[string][]byte            `json:"codes"`
	CodeHashes   map[string]string            `json:"codeHashes"`
	StatesHashes map[string]map[string]string `json:"statesHashes"`
	Nonces       map[string]uint64            `json:"nonces"`
	States       map[string][]byte            `json:"states"`
	Balances     map[string]map[string]int64  `json:"balances"`
	Tokens       map[string]TokenInfo         `json:"tokens"`
}

func (sa *StateAccount) Marshal() ([]byte, error) {
	psj := persistedStateJSON{
		Accounts:     hexAddrKeyMap(sa.Accounts),
		Codes:        hexAddrKeyMap(sa.Codes),
		CodeHashes:   hexAddrKeyHashValMap(sa.CodeHashes),
		StatesHashes: hexAddrKeyedStorageToJSON(sa.StatesHashes),
		Nonces:       hexAddrKeyMap(sa.Nonces),
		States:       hexHashKeyMap(sa.States),
		Balances:     hexAddrKeyAddrValMap(sa.Balances),
		Tokens:       hexAddrKeyMap(sa.Tokens),
	}
	return json.Marshal(psj)
}

func (sa *StateAccount) Unmarshal(b []byte) error {
	var psj persistedStateJSON
	if err := json.Unmarshal(b, &psj); err != nil {
		return err
	}

	var err error
	if sa.Accounts, err = addrKeyMapFromHex(psj.Accounts); err != nil {
		return fmt.Errorf("decode accounts: %w", err)
	}
	if sa.Codes, err = addrKeyMapFromHex(psj.Codes); err != nil {
		return fmt.Errorf("decode codes: %w", err)
	}
	if sa.CodeHashes, err = addrKeyHashValMapFromHex(psj.CodeHashes); err != nil {
		return fmt.Errorf("decode codeHashes: %w", err)
	}
	if sa.StatesHashes, err = addrKeyMapFromJSON(psj.StatesHashes); err != nil {
		return fmt.Errorf("decode statesHashes: %w", err)
	}
	if sa.Nonces, err = addrKeyMapFromHex(psj.Nonces); err != nil {
		return fmt.Errorf("decode nonces: %w", err)
	}
	if sa.States, err = hashKeyMapFromHex(psj.States); err != nil {
		return fmt.Errorf("decode states: %w", err)
	}
	if sa.Balances, err = addrKeyAddrValMapFromHex(psj.Balances); err != nil {
		return fmt.Errorf("decode balances: %w", err)
	}
	if sa.Tokens, err = addrKeyMapFromHex(psj.Tokens); err != nil {
		return fmt.Errorf("decode tokens: %w", err)
	}

	// The journal (and derived SnapShotNum) is per-transaction transient
	// state and is never part of the persisted JSON. A freshly-loaded state
	// must start with a clean journal, otherwise stale journal entries from
	// before the Load() could be reverted against the newly-restored maps.
	sa.journal = nil
	sa.SnapShotNum = 0
	// Defensively ensure the remaining transient fields are non-nil empty
	// maps/slices rather than nil (a nil slice/map behaves fine for reads
	// and appends, but this keeps the post-Load state's invariants explicit
	// and consistent with ResetTransient/ClearSuicided/ClearAccessList).
	if sa.logs == nil {
		sa.logs = []*types.Log{}
	}
	if sa.suicided == nil {
		sa.suicided = map[[common.AddressLength]byte]bool{}
	}
	if sa.accessAddrs == nil {
		sa.accessAddrs = map[[common.AddressLength]byte]bool{}
	}
	if sa.accessSlots == nil {
		sa.accessSlots = map[[common.AddressLength]byte]map[common.Hash]bool{}
	}
	return nil
}

// decodeAddress hex-decodes an address key, validating both the hex encoding
// and the decoded length.
func decodeAddress(k string) ([common.AddressLength]byte, error) {
	var addr [common.AddressLength]byte
	b, err := hex.DecodeString(k)
	if err != nil {
		return addr, fmt.Errorf("invalid address hex %q: %w", k, err)
	}
	if len(b) != common.AddressLength {
		return addr, fmt.Errorf("invalid address length for %q: got %d want %d", k, len(b), common.AddressLength)
	}
	copy(addr[:], b)
	return addr, nil
}

// decodeHash hex-decodes a hash key, validating both the hex encoding and the
// decoded length.
func decodeHash(k string) (common.Hash, error) {
	var h common.Hash
	b, err := hex.DecodeString(k)
	if err != nil {
		return h, fmt.Errorf("invalid hash hex %q: %w", k, err)
	}
	if len(b) != common.HashLength {
		return h, fmt.Errorf("invalid hash length for %q: got %d want %d", k, len(b), common.HashLength)
	}
	copy(h[:], b)
	return h, nil
}

// hexAddrKeyMap hex-encodes an address-keyed map's keys for JSON marshaling.
func hexAddrKeyMap[V any](m map[[common.AddressLength]byte]V) map[string]V {
	result := make(map[string]V, len(m))
	for k, v := range m {
		result[hex.EncodeToString(k[:])] = v
	}
	return result
}

// addrKeyMapFromHex hex-decodes an address-keyed map's keys, propagating any
// decode error.
func addrKeyMapFromHex[V any](m map[string]V) (map[[common.AddressLength]byte]V, error) {
	result := make(map[[common.AddressLength]byte]V, len(m))
	for k, v := range m {
		addr, err := decodeAddress(k)
		if err != nil {
			return nil, err
		}
		result[addr] = v
	}
	return result, nil
}

// hexHashKeyMap hex-encodes a Hash-keyed map's keys for JSON marshaling.
func hexHashKeyMap[V any](m map[common.Hash]V) map[string]V {
	result := make(map[string]V, len(m))
	for k, v := range m {
		result[hex.EncodeToString(k[:])] = v
	}
	return result
}

// hashKeyMapFromHex hex-decodes a Hash-keyed map's keys, propagating any
// decode error.
func hashKeyMapFromHex[V any](m map[string]V) (map[common.Hash]V, error) {
	result := make(map[common.Hash]V, len(m))
	for k, v := range m {
		h, err := decodeHash(k)
		if err != nil {
			return nil, err
		}
		result[h] = v
	}
	return result, nil
}

// hexAddrKeyHashValMap hex-encodes both the address keys and Hash values of a
// map for JSON marshaling.
func hexAddrKeyHashValMap(m map[[common.AddressLength]byte]common.Hash) map[string]string {
	result := make(map[string]string, len(m))
	for k, v := range m {
		result[hex.EncodeToString(k[:])] = hex.EncodeToString(v[:])
	}
	return result
}

// addrKeyHashValMapFromHex hex-decodes both the address keys and Hash values
// of a map, propagating any decode error.
func addrKeyHashValMapFromHex(m map[string]string) (map[[common.AddressLength]byte]common.Hash, error) {
	result := make(map[[common.AddressLength]byte]common.Hash, len(m))
	for k, v := range m {
		addr, err := decodeAddress(k)
		if err != nil {
			return nil, err
		}
		h, err := decodeHash(v)
		if err != nil {
			return nil, err
		}
		result[addr] = h
	}
	return result, nil
}

// hexHashKeyHashValMap hex-encodes both the keys and values of a
// Hash-to-Hash map for JSON marshaling.
func hexHashKeyHashValMap(m map[common.Hash]common.Hash) map[string]string {
	result := make(map[string]string, len(m))
	for k, v := range m {
		result[hex.EncodeToString(k[:])] = hex.EncodeToString(v[:])
	}
	return result
}

// hashKeyHashValMapFromHex hex-decodes both the keys and values of a
// Hash-to-Hash map, propagating any decode error.
func hashKeyHashValMapFromHex(m map[string]string) (map[common.Hash]common.Hash, error) {
	result := make(map[common.Hash]common.Hash, len(m))
	for k, v := range m {
		key, err := decodeHash(k)
		if err != nil {
			return nil, err
		}
		val, err := decodeHash(v)
		if err != nil {
			return nil, err
		}
		result[key] = val
	}
	return result, nil
}

// hexAddrKeyedStorageToJSON hex-encodes the address->(Hash->Hash) nested
// storage map for JSON marshaling.
func hexAddrKeyedStorageToJSON(m map[[common.AddressLength]byte]map[common.Hash]common.Hash) map[string]map[string]string {
	result := make(map[string]map[string]string, len(m))
	for k, innerMap := range m {
		result[hex.EncodeToString(k[:])] = hexHashKeyHashValMap(innerMap)
	}
	return result
}

// addrKeyMapFromJSON hex-decodes the address->(Hash->Hash) nested storage
// map, propagating any decode error.
func addrKeyMapFromJSON(m map[string]map[string]string) (map[[common.AddressLength]byte]map[common.Hash]common.Hash, error) {
	result := make(map[[common.AddressLength]byte]map[common.Hash]common.Hash, len(m))
	for k, innerMap := range m {
		addr, err := decodeAddress(k)
		if err != nil {
			return nil, err
		}
		innerResult, err := hashKeyHashValMapFromHex(innerMap)
		if err != nil {
			return nil, err
		}
		result[addr] = innerResult
	}
	return result, nil
}

// hexAddrKeyAddrValMap hex-encodes the address->(address->int64) nested
// balances map for JSON marshaling.
func hexAddrKeyAddrValMap(m map[[common.AddressLength]byte]map[[common.AddressLength]byte]int64) map[string]map[string]int64 {
	result := make(map[string]map[string]int64, len(m))
	for k, innerMap := range m {
		result[hex.EncodeToString(k[:])] = hexAddrKeyMap(innerMap)
	}
	return result
}

// addrKeyAddrValMapFromHex hex-decodes the address->(address->int64) nested
// balances map, propagating any decode error.
func addrKeyAddrValMapFromHex(m map[string]map[string]int64) (map[[common.AddressLength]byte]map[[common.AddressLength]byte]int64, error) {
	result := make(map[[common.AddressLength]byte]map[[common.AddressLength]byte]int64, len(m))
	for k, innerMap := range m {
		addr, err := decodeAddress(k)
		if err != nil {
			return nil, err
		}
		innerResult, err := addrKeyMapFromHex(innerMap)
		if err != nil {
			return nil, err
		}
		result[addr] = innerResult
	}
	return result, nil
}

// Store persists the committed EVM state under EVMStateDBPrefix+height and
// marks the in-memory state as in sync with disk.
func (sa *StateAccount) Store(height int64) error {
	b, err := sa.Marshal()
	if err != nil {
		return err
	}
	prefix := append(common.EVMStateDBPrefix[:], common.GetByteInt64(height)...)
	if err := database.MainDB.Put(prefix, b); err != nil {
		logger.GetLogger().Println("cannot store EVM state", err)
		return err
	}
	sa.changedSinceStore = false
	return nil
}

// Load restores EVM state for a height (height < 0 => latest stored).
func (sa *StateAccount) Load(height int64) error {
	if height < 0 {
		h, err := sa.LastStoredHeight()
		if err != nil {
			return err
		}
		if h < 0 {
			return fmt.Errorf("no persisted EVM state")
		}
		height = h
	}
	prefix := append(common.EVMStateDBPrefix[:], common.GetByteInt64(height)...)
	b, err := database.MainDB.Get(prefix)
	if err != nil || b == nil {
		return err
	}
	if err := sa.Unmarshal(b); err != nil {
		return err
	}
	sa.changedSinceStore = false
	return nil
}

// LoadAtOrBelow restores the closest persisted EVM snapshot at or below height
// and returns the height it actually loaded. Under the store-on-change model
// this is exact, not approximate: a snapshot is written at every height whose
// block changed the state, so the state at the closest stored height below is
// byte-for-byte the state at `height` itself.
func (sa *StateAccount) LoadAtOrBelow(height int64) (int64, error) {
	h, err := sa.ClosestStoredHeight(height)
	if err != nil {
		return -1, err
	}
	if h < 0 {
		return -1, fmt.Errorf("no persisted EVM state at or below height %d", height)
	}
	if err := sa.Load(h); err != nil {
		return -1, err
	}
	return h, nil
}

// storedHeights enumerates every height that has a persisted EVM snapshot.
// The EV keyspace holds one key per contract-bearing block, so a full prefix
// scan stays cheap regardless of chain length. The heights are little-endian
// in the key, so RocksDB iteration order is meaningless — callers get an
// unordered list.
func (sa *StateAccount) storedHeights() ([]int64, error) {
	keys, err := database.MainDB.LoadAllKeys(common.EVMStateDBPrefix[:])
	if err != nil {
		return nil, err
	}
	heights := make([]int64, 0, len(keys))
	for _, k := range keys {
		if len(k) != len(common.EVMStateDBPrefix)+8 {
			continue
		}
		heights = append(heights, common.GetInt64FromByte(k[len(common.EVMStateDBPrefix):]))
	}
	return heights, nil
}

// LastStoredHeight returns the highest stored EVM-state height, or -1 when
// nothing is stored. Snapshot heights are NOT contiguous (store-on-change
// leaves gaps at contract-free blocks), so this enumerates the EV keyspace
// instead of binary-searching it.
func (sa *StateAccount) LastStoredHeight() (int64, error) {
	return sa.highestStored(func(int64) bool { return true })
}

// ClosestStoredHeight returns the highest stored EVM-state height that is
// <= height, or -1 when there is none.
func (sa *StateAccount) ClosestStoredHeight(height int64) (int64, error) {
	return sa.highestStored(func(h int64) bool { return h <= height })
}

func (sa *StateAccount) highestStored(accept func(int64) bool) (int64, error) {
	heights, err := sa.storedHeights()
	if err != nil {
		return -1, err
	}
	best := int64(-1)
	for _, h := range heights {
		if accept(h) && h > best {
			best = h
		}
	}
	return best, nil
}

// RemoveStoredAbove deletes every persisted EVM snapshot above height. A rewind
// must call this: an orphaned snapshot from the abandoned branch would otherwise
// be picked up by LastStoredHeight/Load(-1) on the next restart and resurrect
// state from a chain that no longer exists.
func (sa *StateAccount) RemoveStoredAbove(height int64) error {
	heights, err := sa.storedHeights()
	if err != nil {
		return err
	}
	for _, h := range heights {
		if h <= height {
			continue
		}
		key := append(common.EVMStateDBPrefix[:], common.GetByteInt64(h)...)
		if err := database.MainDB.Delete(key); err != nil {
			return err
		}
	}
	return nil
}
