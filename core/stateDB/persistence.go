package stateDB

import (
	"encoding/hex"
	"encoding/json"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/database"
	"github.com/wonabru/qwid-node/logger"
)

// persistedState is the subset of StateAccount written to disk. Transient
// snapshot/journal fields are intentionally excluded — they are execution-scoped
// and meaningless across a restart.
type persistedState struct {
	Accounts     map[[common.AddressLength]byte]account.Account                      `json:"accounts"`
	Codes        map[[common.AddressLength]byte][]byte                               `json:"codes"`
	CodeHashes   map[[common.AddressLength]byte]common.Hash                          `json:"codeHashes"`
	StatesHashes map[[common.AddressLength]byte]map[common.Hash]common.Hash          `json:"statesHashes"`
	Nonces       map[[common.AddressLength]byte]uint64                               `json:"nonces"`
	States       map[common.Hash][]byte                                              `json:"states"`
	Balances     map[[common.AddressLength]byte]map[[common.AddressLength]byte]int64 `json:"balances"`
	Tokens       map[[common.AddressLength]byte]TokenInfo                            `json:"tokens"`
}

// persistedStateJSON is the JSON-serializable representation with string keys.
type persistedStateJSON struct {
	Accounts     map[string]account.Account           `json:"accounts"`
	Codes        map[string][]byte                    `json:"codes"`
	CodeHashes   map[string]string                    `json:"codeHashes"`
	StatesHashes map[string]map[string]string         `json:"statesHashes"`
	Nonces       map[string]uint64                    `json:"nonces"`
	States       map[string][]byte                    `json:"states"`
	Balances     map[string]map[string]int64          `json:"balances"`
	Tokens       map[string]TokenInfo                 `json:"tokens"`
}

func (sa *StateAccount) Marshal() ([]byte, error) {
	psj := persistedStateJSON{
		Accounts:     convertAccountsToJSON(sa.Accounts),
		Codes:        convertCodesToJSON(sa.Codes),
		CodeHashes:   convertHashesToJSON(sa.CodeHashes),
		StatesHashes: convertStorageToJSON(sa.StatesHashes),
		Nonces:       convertNoncesToJSON(sa.Nonces),
		States:       convertStatesToJSON(sa.States),
		Balances:     convertBalancesToJSON(sa.Balances),
		Tokens:       convertTokensToJSON(sa.Tokens),
	}
	return json.Marshal(psj)
}

func (sa *StateAccount) Unmarshal(b []byte) error {
	var psj persistedStateJSON
	if err := json.Unmarshal(b, &psj); err != nil {
		return err
	}
	sa.Accounts = convertAccountsFromJSON(psj.Accounts)
	sa.Codes = convertCodesFromJSON(psj.Codes)
	sa.CodeHashes = convertHashesFromJSON(psj.CodeHashes)
	sa.StatesHashes = convertStorageFromJSON(psj.StatesHashes)
	sa.Nonces = convertNoncesFromJSON(psj.Nonces)
	sa.States = convertStatesFromJSON(psj.States)
	sa.Balances = convertBalancesFromJSON(psj.Balances)
	sa.Tokens = convertTokensFromJSON(psj.Tokens)
	return nil
}

// Conversion functions: array keys to string keys (for JSON marshaling)
func convertAccountsToJSON(m map[[common.AddressLength]byte]account.Account) map[string]account.Account {
	result := make(map[string]account.Account)
	for k, v := range m {
		result[hex.EncodeToString(k[:])] = v
	}
	return result
}

func convertCodesToJSON(m map[[common.AddressLength]byte][]byte) map[string][]byte {
	result := make(map[string][]byte)
	for k, v := range m {
		result[hex.EncodeToString(k[:])] = v
	}
	return result
}

func convertHashesToJSON(m map[[common.AddressLength]byte]common.Hash) map[string]string {
	result := make(map[string]string)
	for k, v := range m {
		result[hex.EncodeToString(k[:])] = hex.EncodeToString(v[:])
	}
	return result
}

func convertStorageToJSON(m map[[common.AddressLength]byte]map[common.Hash]common.Hash) map[string]map[string]string {
	result := make(map[string]map[string]string)
	for k, innerMap := range m {
		innerResult := make(map[string]string)
		for hashKey, hashVal := range innerMap {
			innerResult[hex.EncodeToString(hashKey[:])] = hex.EncodeToString(hashVal[:])
		}
		result[hex.EncodeToString(k[:])] = innerResult
	}
	return result
}

func convertNoncesToJSON(m map[[common.AddressLength]byte]uint64) map[string]uint64 {
	result := make(map[string]uint64)
	for k, v := range m {
		result[hex.EncodeToString(k[:])] = v
	}
	return result
}

func convertStatesToJSON(m map[common.Hash][]byte) map[string][]byte {
	result := make(map[string][]byte)
	for k, v := range m {
		result[hex.EncodeToString(k[:])] = v
	}
	return result
}

func convertBalancesToJSON(m map[[common.AddressLength]byte]map[[common.AddressLength]byte]int64) map[string]map[string]int64 {
	result := make(map[string]map[string]int64)
	for k, innerMap := range m {
		innerResult := make(map[string]int64)
		for innerK, v := range innerMap {
			innerResult[hex.EncodeToString(innerK[:])] = v
		}
		result[hex.EncodeToString(k[:])] = innerResult
	}
	return result
}

func convertTokensToJSON(m map[[common.AddressLength]byte]TokenInfo) map[string]TokenInfo {
	result := make(map[string]TokenInfo)
	for k, v := range m {
		result[hex.EncodeToString(k[:])] = v
	}
	return result
}

// Conversion functions: string keys to array keys (for JSON unmarshaling)
func convertAccountsFromJSON(m map[string]account.Account) map[[common.AddressLength]byte]account.Account {
	result := make(map[[common.AddressLength]byte]account.Account)
	for k, v := range m {
		b, _ := hex.DecodeString(k)
		var addr [common.AddressLength]byte
		copy(addr[:], b)
		result[addr] = v
	}
	return result
}

func convertCodesFromJSON(m map[string][]byte) map[[common.AddressLength]byte][]byte {
	result := make(map[[common.AddressLength]byte][]byte)
	for k, v := range m {
		b, _ := hex.DecodeString(k)
		var addr [common.AddressLength]byte
		copy(addr[:], b)
		result[addr] = v
	}
	return result
}

func convertHashesFromJSON(m map[string]string) map[[common.AddressLength]byte]common.Hash {
	result := make(map[[common.AddressLength]byte]common.Hash)
	for k, v := range m {
		b, _ := hex.DecodeString(k)
		var addr [common.AddressLength]byte
		copy(addr[:], b)
		hashB, _ := hex.DecodeString(v)
		var hash common.Hash
		copy(hash[:], hashB)
		result[addr] = hash
	}
	return result
}

func convertStorageFromJSON(m map[string]map[string]string) map[[common.AddressLength]byte]map[common.Hash]common.Hash {
	result := make(map[[common.AddressLength]byte]map[common.Hash]common.Hash)
	for k, innerMap := range m {
		b, _ := hex.DecodeString(k)
		var addr [common.AddressLength]byte
		copy(addr[:], b)
		innerResult := make(map[common.Hash]common.Hash)
		for hashKey, hashVal := range innerMap {
			keyB, _ := hex.DecodeString(hashKey)
			valB, _ := hex.DecodeString(hashVal)
			var keyHash, valHash common.Hash
			copy(keyHash[:], keyB)
			copy(valHash[:], valB)
			innerResult[keyHash] = valHash
		}
		result[addr] = innerResult
	}
	return result
}

func convertNoncesFromJSON(m map[string]uint64) map[[common.AddressLength]byte]uint64 {
	result := make(map[[common.AddressLength]byte]uint64)
	for k, v := range m {
		b, _ := hex.DecodeString(k)
		var addr [common.AddressLength]byte
		copy(addr[:], b)
		result[addr] = v
	}
	return result
}

func convertStatesFromJSON(m map[string][]byte) map[common.Hash][]byte {
	result := make(map[common.Hash][]byte)
	for k, v := range m {
		b, _ := hex.DecodeString(k)
		var hash common.Hash
		copy(hash[:], b)
		result[hash] = v
	}
	return result
}

func convertBalancesFromJSON(m map[string]map[string]int64) map[[common.AddressLength]byte]map[[common.AddressLength]byte]int64 {
	result := make(map[[common.AddressLength]byte]map[[common.AddressLength]byte]int64)
	for k, innerMap := range m {
		b, _ := hex.DecodeString(k)
		var addr [common.AddressLength]byte
		copy(addr[:], b)
		innerResult := make(map[[common.AddressLength]byte]int64)
		for innerK, v := range innerMap {
			innerB, _ := hex.DecodeString(innerK)
			var innerAddr [common.AddressLength]byte
			copy(innerAddr[:], innerB)
			innerResult[innerAddr] = v
		}
		result[addr] = innerResult
	}
	return result
}

func convertTokensFromJSON(m map[string]TokenInfo) map[[common.AddressLength]byte]TokenInfo {
	result := make(map[[common.AddressLength]byte]TokenInfo)
	for k, v := range m {
		b, _ := hex.DecodeString(k)
		var addr [common.AddressLength]byte
		copy(addr[:], b)
		result[addr] = v
	}
	return result
}

// Store/Load are added in Task 2 (they use database + logger, imported above).
var _ = database.MainDB
var _ = logger.GetLogger
