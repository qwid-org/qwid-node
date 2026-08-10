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
