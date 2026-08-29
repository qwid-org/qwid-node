package pubkeys

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
)

// Decoded public keys, kept because LoadPubKey sits on the hottest path there
// is: every transaction whose signature is verified without an embedded key
// costs a RocksDB read plus a JSON unmarshal of the key. JSON stores the key
// bytes base64-encoded, so the decode grows with the scheme — about 1.2KB for
// Falcon-512 but roughly 89KB for a 66576-byte OV key, at which point parsing
// the key costs more than verifying the signature. Caching decouples the choice
// of signature scheme from the per-transaction cost of its key size.
//
// Correctness rests on the record being immutable: the database key is the
// address DERIVED from the key bytes, and nothing ever deletes a stored key.
// The one writer, blocks.StorePubKey, drops the entry so the next read comes
// from the database — invalidating rather than populating keeps the database
// the single source of truth even if a write is later rolled back.
var (
	pubKeyCacheMu sync.RWMutex
	pubKeyCache   = map[string]common.PubKey{}
	// pubKeyCacheGen counts invalidations. A reader samples it before going to
	// the database and refuses to cache what it read if the count moved,
	// because a write landed in between and what it holds may already be
	// superseded. Without this the cache is racy in BOTH orderings: invalidate
	// before the write and a reader can re-cache the old record from the
	// database; invalidate after, and a reader that read early can install its
	// stale copy afterwards.
	pubKeyCacheGen uint64
)

// pubKeyCacheMaxEntries bounds the cache. Without it the map would eventually
// hold every key the chain has ever registered — at a megabyte per thousand
// Falcon keys, and far worse for the large-key schemes this cache exists to
// make affordable.
const pubKeyCacheMaxEntries = 100000

// InvalidatePubKeyCache drops the cached entry for one key address. Called by
// the writer after a key is stored, so a re-registration cannot be served from
// a stale decode.
func InvalidatePubKeyCache(a []byte) {
	pubKeyCacheMu.Lock()
	delete(pubKeyCache, string(a))
	pubKeyCacheGen++
	pubKeyCacheMu.Unlock()
}

// clonePubKey returns a copy whose byte slice the caller cannot use to mutate
// the cached entry. The copy costs well under a microsecond against the
// unmarshal it replaces, and it removes any need to reason about which callers
// treat the returned key as read-only.
func clonePubKey(pk common.PubKey) common.PubKey {
	out := pk
	out.ByteValue = append([]byte(nil), pk.ByteValue...)
	return out
}

func AddPubKeyToAddress(pk common.PubKey, mainAddress common.Address) error {
	as, err := LoadAddresses(mainAddress)
	if err != nil {
		if err.Error() != "key not found" {
			return err
		}
		as = []common.Address{}
	}
	address, err := common.PubKeyToAddress(pk.GetBytes(), pk.Primary)
	if err != nil {
		return err
	}
	as = append(as, address)
	tree, err := BuildMerkleTree(mainAddress, as, GlobalMerkleTree.DB)
	if err != nil {
		return err
	}
	for _, a := range as {
		if !tree.IsAddressInTree(a) {
			return fmt.Errorf("pubkey patricia trie fails to add pubkey")
		}
	}
	err = tree.StoreTree(mainAddress)
	if err != nil {
		return err
	}
	return nil
}

func CreateAddressFromFirstPubKey(p common.PubKey) (common.Address, error) {
	address, err := common.PubKeyToAddress(p.GetBytes(), p.Primary)
	if err != nil {
		return common.Address{}, err
	}
	as, err := LoadAddresses(address)
	if err != nil {
		if err.Error() != "key not found" {
			return common.Address{}, err
		}
		as = []common.Address{}
	}
	if len(as) > 0 {
		return common.Address{}, fmt.Errorf("there are just generated markle trie for given pubkey")
	}
	tree, err := BuildMerkleTree(address, []common.Address{address}, GlobalMerkleTree.DB)
	if err != nil {
		return common.Address{}, err
	}
	if !tree.IsAddressInTree(address) {
		return common.Address{}, fmt.Errorf("addresses patricia trie fails to initialize")
	}
	err = tree.StoreTree(address)
	if err != nil {
		return common.Address{}, err
	}
	return address, nil
}

// LoadPubKey : a - address in bytes of pubkey
func LoadPubKey(a []byte) (common.PubKey, error) {
	ck := string(a)
	pubKeyCacheMu.RLock()
	cached, hit := pubKeyCache[ck]
	gen := pubKeyCacheGen
	pubKeyCacheMu.RUnlock()
	if hit {
		return clonePubKey(cached), nil
	}

	pkb, err := database.MainDB.Get(append(common.PubKeyMarshalDBPrefix[:], a...))
	if err != nil {
		// Misses are NOT cached: "not yet registered" is a state that changes,
		// and caching it would hide the registration that follows.
		return common.PubKey{}, err
	}
	var pk common.PubKey
	err = json.Unmarshal(pkb, &pk)
	if err != nil {
		return common.PubKey{}, err
	}

	pubKeyCacheMu.Lock()
	if pubKeyCacheGen != gen {
		// A key was stored while this read was in flight. What we decoded may
		// be the superseded record, so return it to this caller but do not let
		// it become the cached answer for everyone else.
		pubKeyCacheMu.Unlock()
		return pk, nil
	}
	if len(pubKeyCache) >= pubKeyCacheMaxEntries {
		// Evict one arbitrary entry to stay at the bound. Go randomises map
		// iteration order, so this is random eviction — good enough here,
		// where every entry costs the same to rebuild and no access pattern
		// is worth tracking.
		for k := range pubKeyCache {
			delete(pubKeyCache, k)
			break
		}
	}
	pubKeyCache[ck] = clonePubKey(pk)
	pubKeyCacheMu.Unlock()

	return pk, nil
}

// LoadPubKeyWithPrimaryOfLength returns the newest key registered for
// mainAddress that has the requested primary flag AND the requested byte
// length. After a signature-scheme change an account carries keys for both the
// old and the new scheme under the same primary flag; selecting by the
// verifying scheme's expected public-key length lets a signature made under a
// superseded scheme (e.g. an oracle proof verified against the config at its
// own signing height) still find the key it was made with.
func LoadPubKeyWithPrimaryOfLength(mainAddress common.Address, primary bool, length int) (common.PubKey, error) {
	addresses, err := LoadAddresses(mainAddress)
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
			// A missing entry for one address must not hide an older key that
			// is still present; keep scanning.
			continue
		}
		if len(pkm.GetBytes()) == length {
			return pkm, nil
		}
	}
	return common.PubKey{}, fmt.Errorf("no pubkey of length %d found", length)
}

func LoadPubKeyWithPrimary(mainAddress common.Address, primary bool) (common.PubKey, error) {
	addresses, err := LoadAddresses(mainAddress)
	if err != nil {
		return common.PubKey{}, err
	}
	//logger.GetLogger().Println("addresses:", addresses)
	if len(addresses) > 0 {
		for i := len(addresses) - 1; i >= 0; i-- {
			addr := addresses[i]
			if addr.Primary == primary {
				pkm, err := LoadPubKey(addr.GetBytes())
				if err != nil {
					return common.PubKey{}, err
				}
				return pkm, nil
			}
		}
	}
	return common.PubKey{}, fmt.Errorf("no pubkey found")
}
