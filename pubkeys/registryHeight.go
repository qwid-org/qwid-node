package pubkeys

import (
	"bytes"
	"fmt"
	"math"
	"sort"

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
// registered by the block at `height`, on its own authority (never voided).
func StoreRegistrationHeight(derived common.Address, height int64) error {
	return StoreRegistration(derived, height, false)
}

// StoreRegistration records the block that registered the key deriving
// `derived` and whether the registration is voidable: the key joined its
// identity on the strength of ANOTHER key's signature, so it is worth exactly
// as much as that signature (see VoidedAsOf). The record is the height (8
// bytes) followed, for a voidable key, by one byte 1.
func StoreRegistration(derived common.Address, height int64, voidable bool) error {
	rec := common.GetByteInt64(height)
	if voidable {
		rec = append(rec, 1)
	}
	return database.MainDB.Put(registrationHeightKey(derived.GetBytes()), rec)
}

// RegistrationRecord is the raw record of a key, nil without one; a rewind
// puts it back with RestoreRegistrationRecord.
func RegistrationRecord(derived common.Address) []byte {
	b, err := database.MainDB.Get(registrationHeightKey(derived.GetBytes()))
	if err != nil || (len(b) != 8 && len(b) != 9) {
		return nil
	}
	return b
}

func RestoreRegistrationRecord(derived common.Address, rec []byte) error {
	return database.MainDB.Put(registrationHeightKey(derived.GetBytes()), rec)
}

// DeleteRegistrationHeight drops the record when a rewind unregisters the key.
func DeleteRegistrationHeight(derived common.Address) error {
	return database.MainDB.Delete(registrationHeightKey(derived.GetBytes()))
}

func registration(derived []byte) (height int64, voidable bool) {
	b, err := database.MainDB.Get(registrationHeightKey(derived))
	if err != nil || (len(b) != 8 && len(b) != 9) {
		return 0, false
	}
	return common.GetInt64FromByte(b[:8]), len(b) == 9 && b[8] == 1
}

// RegistrationHeight returns the height of the block that registered the key
// deriving `derived`. A key without a record - a genesis key, or one stored
// before this index existed - counts as registered at height 0.
func RegistrationHeight(derived []byte) int64 {
	h, _ := registration(derived)
	return h
}

// Scheme breaks (P-01). The heights of the blocks that marked a signature
// scheme as broken, ascending, in one record.

func schemeBreaks() []int64 {
	b, err := database.MainDB.Get(common.SchemeBreaksDBPrefix[:])
	if err != nil || len(b)%8 != 0 {
		return nil
	}
	hs := make([]int64, 0, len(b)/8)
	for i := 0; i < len(b); i += 8 {
		hs = append(hs, common.GetInt64FromByte(b[i:i+8]))
	}
	return hs
}

func storeSchemeBreaks(hs []int64) error {
	b := make([]byte, 0, 8*len(hs))
	for _, h := range hs {
		b = append(b, common.GetByteInt64(h)...)
	}
	return database.MainDB.Put(common.SchemeBreaksDBPrefix[:], b)
}

// RecordSchemeBreak notes that the block at `height` marked a scheme as
// broken. Applying the same block again changes nothing.
func RecordSchemeBreak(height int64) error {
	hs := schemeBreaks()
	i := sort.Search(len(hs), func(i int) bool { return hs[i] >= height })
	if i < len(hs) && hs[i] == height {
		return nil
	}
	hs = append(hs, 0)
	copy(hs[i+1:], hs[i:])
	hs[i] = height
	return storeSchemeBreaks(hs)
}

// DropSchemeBreaksAbove forgets the breaks of rewound blocks.
func DropSchemeBreaksAbove(target int64) error {
	hs := schemeBreaks()
	i := sort.Search(len(hs), func(i int) bool { return hs[i] > target })
	if i == len(hs) {
		return nil
	}
	return storeSchemeBreaks(hs[:i])
}

// Retired schemes (P-08): the signature schemes this chain replaced, with the
// height of the replacing block, in one record of height(8) ‖ LB(name)
// entries in block order.

type retiredScheme struct {
	height int64
	name   string
}

func retiredSchemes() []retiredScheme {
	b, err := database.MainDB.Get(common.RetiredSchemesDBPrefix[:])
	if err != nil {
		return nil
	}
	var out []retiredScheme
	for len(b) >= 8 {
		h := common.GetInt64FromByte(b[:8])
		name, rest, err := common.BytesWithLenToBytes(b[8:])
		if err != nil {
			return out
		}
		out = append(out, retiredScheme{h, string(name)})
		b = rest
	}
	return out
}

func storeRetiredSchemes(rs []retiredScheme) error {
	var b []byte
	for _, r := range rs {
		b = append(b, common.GetByteInt64(r.height)...)
		b = append(b, common.BytesToLenAndBytes([]byte(r.name))...)
	}
	return database.MainDB.Put(common.RetiredSchemesDBPrefix[:], b)
}

// RecordRetiredScheme notes that the block at `height` replaced the scheme
// `name`. Applying the same block again changes nothing.
func RecordRetiredScheme(height int64, name string) error {
	rs := retiredSchemes()
	for _, r := range rs {
		if r.height == height && r.name == name {
			return nil
		}
	}
	rs = append(rs, retiredScheme{height, name})
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].height < rs[j].height })
	return storeRetiredSchemes(rs)
}

// DropRetiredSchemesAbove forgets the replacements of rewound blocks.
func DropRetiredSchemesAbove(target int64) error {
	rs := retiredSchemes()
	kept := rs[:0]
	for _, r := range rs {
		if r.height <= target {
			kept = append(kept, r)
		}
	}
	if len(kept) == len(rs) {
		return nil
	}
	return storeRetiredSchemes(kept)
}

// SchemeRetiredAsOf reports whether the chain had replaced the scheme `name`
// by block asOf.
func SchemeRetiredAsOf(name string, asOf int64) bool {
	for _, r := range retiredSchemes() {
		if r.name == name && r.height <= asOf {
			return true
		}
	}
	return false
}

// voidedBy reports whether a voidable key registered at regHeight is void as
// of block asOf: some block in [regHeight, regHeight+maturity) and no later
// than asOf marked a scheme as broken. The rule is the one unmatured
// commitments get (account.VoidPendingRecoveryCommits): the signature that
// authorised the key may have been forged with the scheme that then turned
// out to be broken.
func voidedBy(breaks []int64, regHeight, asOf int64) bool {
	for _, b := range breaks {
		if b >= regHeight && b < regHeight+common.RecoveryCommitMaturityBlocks && b <= asOf {
			return true
		}
	}
	return false
}

// VoidedAsOf reports whether the key deriving `derived` was voided by a
// scheme break at or before block asOf. A voided key stays in its identity's
// address list - so the registry as of earlier blocks is unchanged and a
// rewind needs nothing put back - but no *AsOf reader returns it.
func VoidedAsOf(derived []byte, asOf int64) bool {
	h, voidable := registration(derived)
	return voidable && voidedBy(schemeBreaks(), h, asOf)
}

// SurvivesBreakAt reports whether the key would still stand if the block at
// breakHeight marked a scheme as broken.
func SurvivesBreakAt(derived []byte, breakHeight int64) bool {
	h, voidable := registration(derived)
	return !voidable || !voidedBy([]int64{breakHeight}, h, breakHeight)
}

// RegisteredAsOf reports whether the key deriving `derived` was registered by
// block asOf or earlier and not voided by then. NoHeightLimit asks about now.
func RegisteredAsOf(derived []byte, asOf int64) bool {
	h, voidable := registration(derived)
	if asOf != NoHeightLimit && h > asOf {
		return false
	}
	return !voidable || !voidedBy(schemeBreaks(), h, asOf)
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
// or earlier and not voided by then (with NoHeightLimit: the keys in force
// now - LoadAddresses itself also lists voided ones). An identity with no key by then reports "key not found", like
// one that never registered.
func LoadAddressesAsOf(mainAddress common.Address, asOf int64) ([]common.Address, error) {
	addrs, err := LoadAddresses(mainAddress)
	if err != nil {
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

// HasKeySurvivingBreakAt reports whether mainAddress held, as of block asOf, a
// key of the given slot and length that a scheme break at breakHeight would
// not void - a key it can still sign with after that block.
func HasKeySurvivingBreakAt(mainAddress common.Address, primary bool, length int, asOf, breakHeight int64) bool {
	addresses, err := LoadAddressesAsOf(mainAddress, asOf)
	if err != nil {
		return false
	}
	for _, addr := range addresses {
		if addr.Primary != primary || !SurvivesBreakAt(addr.GetBytes(), breakHeight) {
			continue
		}
		if pkm, err := LoadPubKey(addr.GetBytes()); err == nil && len(pkm.GetBytes()) == length {
			return true
		}
	}
	return false
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
