package pubkeys

import (
	"bytes"
	"fmt"
	"math"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
)

// The historical key registry (S3-06). The registry itself - the key records
// and each identity's address list - only ever holds the CURRENT set of keys.
// Next to it, every key registered by a block carries the height of that
// block, and the *AsOf readers below answer "which keys existed after block
// asOf". Block application reads the registry as of the parent block, which
// makes a verdict independent of
//   - registrations of the block being applied (ProcessBlockPubKey runs
//     between the check and apply passes, so the two passes saw different
//     registries), and
//   - a registration that outlived the apply attempt that wrote it.
// Those differences used to be papered over by skipping the key checks while
// syncing, a mode any peer can force on a node (S2-03).

// NoHeightLimit makes an *AsOf reader see every registered key: admission and
// gossip verify against the registry as it is now.
const NoHeightLimit int64 = math.MaxInt64

func registrationHeightKey(derived []byte) []byte {
	return append(append([]byte{}, common.PubKeyRegistrationHeightDBPrefix[:]...), derived...)
}

// StoreRegistrationHeight records that the key deriving `derived` was
// registered by the block at `height`.
func StoreRegistrationHeight(derived common.Address, height int64) error {
	return database.MainDB.Put(registrationHeightKey(derived.GetBytes()), common.GetByteInt64(height))
}

// DeleteRegistrationHeight drops the record when a rewind unregisters the key.
func DeleteRegistrationHeight(derived common.Address) error {
	return database.MainDB.Delete(registrationHeightKey(derived.GetBytes()))
}

// RegistrationHeight returns the height of the block that registered the key
// deriving `derived`. A key without a record - a genesis key, or one stored
// before this index existed - counts as registered at height 0.
func RegistrationHeight(derived []byte) int64 {
	b, err := database.MainDB.Get(registrationHeightKey(derived))
	if err != nil || len(b) != 8 {
		return 0
	}
	return common.GetInt64FromByte(b)
}

// RegisteredAsOf reports whether the key deriving `derived` was registered by
// block asOf or earlier.
func RegisteredAsOf(derived []byte, asOf int64) bool {
	return asOf == NoHeightLimit || RegistrationHeight(derived) <= asOf
}

// IsRegisteredUnder reports whether `derived` is in mainAddress's address
// list - the authoritative membership test. (FindAddressForMainAddress
// compares the raw address against hashed trie leaves and never matches.)
func IsRegisteredUnder(mainAddress, derived common.Address) bool {
	addrs, err := LoadAddresses(mainAddress)
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if bytes.Equal(a.GetBytes(), derived.GetBytes()) {
			return true
		}
	}
	return false
}

// LoadAddressesAsOf is LoadAddresses limited to keys registered by block asOf
// or earlier. An identity with no key by then reports "key not found", like
// one that never registered.
func LoadAddressesAsOf(mainAddress common.Address, asOf int64) ([]common.Address, error) {
	addrs, err := LoadAddresses(mainAddress)
	if err != nil || asOf == NoHeightLimit {
		return addrs, err
	}
	kept := make([]common.Address, 0, len(addrs))
	for _, a := range addrs {
		if RegisteredAsOf(a.GetBytes(), asOf) {
			kept = append(kept, a)
		}
	}
	if len(kept) == 0 {
		return nil, fmt.Errorf("key not found")
	}
	return kept, nil
}

// LoadPubKeyAsOf is LoadPubKey limited to keys registered by block asOf or
// earlier.
func LoadPubKeyAsOf(a []byte, asOf int64) (common.PubKey, error) {
	if !RegisteredAsOf(a, asOf) {
		return common.PubKey{}, fmt.Errorf("key not registered as of height %d", asOf)
	}
	return LoadPubKey(a)
}

// LoadPubKeyWithPrimaryAsOf is LoadPubKeyWithPrimary limited to keys
// registered by block asOf or earlier.
func LoadPubKeyWithPrimaryAsOf(mainAddress common.Address, primary bool, asOf int64) (common.PubKey, error) {
	addresses, err := LoadAddressesAsOf(mainAddress, asOf)
	if err != nil {
		return common.PubKey{}, err
	}
	for i := len(addresses) - 1; i >= 0; i-- {
		if addresses[i].Primary == primary {
			return LoadPubKey(addresses[i].GetBytes())
		}
	}
	return common.PubKey{}, fmt.Errorf("no pubkey found")
}

// LoadPubKeyWithPrimaryOfLengthAsOf is LoadPubKeyWithPrimaryOfLength limited
// to keys registered by block asOf or earlier.
func LoadPubKeyWithPrimaryOfLengthAsOf(mainAddress common.Address, primary bool, length int, asOf int64) (common.PubKey, error) {
	addresses, err := LoadAddressesAsOf(mainAddress, asOf)
	if err != nil {
		return common.PubKey{}, err
	}
	for i := len(addresses) - 1; i >= 0; i-- {
		addr := addresses[i]
		if addr.Primary != primary {
			continue
		}
		pkm, err := LoadPubKey(addr.GetBytes())
		if err != nil {
			continue
		}
		if len(pkm.GetBytes()) == length {
			return pkm, nil
		}
	}
	return common.PubKey{}, fmt.Errorf("no pubkey of length %d found", length)
}

// HasOperatorKeysAsOf reports whether mainAddress had both a primary and a
// secondary key registered by block asOf or earlier - the requirement for
// operational staking.
func HasOperatorKeysAsOf(mainAddress common.Address, asOf int64) bool {
	addrs, err := LoadAddressesAsOf(mainAddress, asOf)
	if err != nil {
		return false
	}
	hasPrimary, hasSecondary := false, false
	for _, a := range addrs {
		if a.Primary {
			hasPrimary = true
		} else {
			hasSecondary = true
		}
	}
	return hasPrimary && hasSecondary
}
