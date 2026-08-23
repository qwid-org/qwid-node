package pubkeys

import (
	"encoding/json"
	"fmt"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
)

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
	pkb, err := database.MainDB.Get(append(common.PubKeyMarshalDBPrefix[:], a...))
	if err != nil {
		return common.PubKey{}, err
	}
	var pk common.PubKey
	err = json.Unmarshal(pkb, &pk)
	if err != nil {
		return common.PubKey{}, err
	}
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
