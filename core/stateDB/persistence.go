package stateDB

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/common"
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

// Store/Load are added in Task 2 (they use database + logger, imported above).
var _ = database.MainDB
var _ = logger.GetLogger
