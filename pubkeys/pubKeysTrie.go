package pubkeys

import (
	"bytes"
	"fmt"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
)

type MerkleTree struct {
	Root        []MerkleNode
	Addresses   []common.Address
	MainAddress common.Address
	DB          *database.BlockchainDB
}
type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Data  []byte
}

var GlobalMerkleTree *MerkleTree

func InitPermanentTrie() {
	merkleNodes, err := NewMerkleTree([]common.Address{})
	if err != nil {
		logger.GetLogger().Fatal(err)
	}
	GlobalMerkleTree = new(MerkleTree)
	GlobalMerkleTree.Root = merkleNodes

	// Use the global MainDB instance
	if database.MainDB == nil {
		logger.GetLogger().Fatal("MainDB is not initialized")
	}
	GlobalMerkleTree.DB = database.MainDB
}

func InitTrie() {
	InitPermanentTrie()
}

func NewMerkleTree(data []common.Address) ([]MerkleNode, error) {
	var nodes []MerkleNode
	for _, a := range data {
		node, err := NewMerkleNode(nil, nil, a.GetBytes())
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, *node)
	}
	for len(nodes) > 1 {
		if len(nodes)%2 != 0 {
			nodes = append(nodes, nodes[len(nodes)-1])
		}
		var level []MerkleNode
		for i := 0; i < len(nodes); i += 2 {
			node, err := NewMerkleNode(&nodes[i], &nodes[i+1], nil)
			if err != nil {
				return nil, err
			}
			level = append(level, *node)
		}
		nodes = level
	}
	return nodes, nil
}
func NewMerkleNode(left, right *MerkleNode, data []byte) (*MerkleNode, error) {
	node := MerkleNode{}
	if left == nil && right == nil {
		hash, err := common.CalcHashToByte(data)
		if err != nil {
			logger.GetLogger().Println("hash calculation fails")
			return nil, err
		}
		node.Data = hash[:]
	} else {
		prevHashes := append(left.Data, right.Data...)
		hash, err := common.CalcHashToByte(prevHashes)
		if err != nil {
			logger.GetLogger().Println("hash calculation fails")
		}
		node.Data = hash[:]
	}
	node.Left = left
	node.Right = right
	return &node, nil
}

func (t *MerkleTree) IsAddressInTree(a common.Address) bool {
	hash, err := common.CalcHashToByte(a.GetBytes())
	if err != nil {
		return false
	}
	left, _ := t.Root[0].containsAddress(0, hash)
	if left {
		return true
	}
	var right bool
	if len(t.Root) > 1 {
		right, _ = t.Root[1].containsAddress(0, hash)
	}
	return right
}

func (n *MerkleNode) containsAddress(index int64, hash []byte) (bool, int64) {
	index++
	if n == nil {
		return false, index - 1
	}
	if bytes.Equal(n.Data, hash) {
		return true, index - 1
	}

	left, indexLeft := n.Left.containsAddress(index, hash)
	right, indexRight := n.Right.containsAddress(index, hash)
	contrains := left || right
	ind := index - 1
	if left {
		ind = indexLeft
	}
	if right {
		ind = indexRight
	}
	return contrains, ind
}

func (t *MerkleTree) GetRootHash() []byte {
	if len(t.Root) > 0 {
		return t.Root[0].Data
	}
	return common.EmptyHash().GetBytes()
}

func BuildMerkleTree(mainAddress common.Address, addresses []common.Address, db *database.BlockchainDB) (*MerkleTree, error) {

	merkleNodes, err := NewMerkleTree(addresses)
	if err != nil {
		return nil, err
	}
	tree := new(MerkleTree)
	tree.Root = merkleNodes
	tree.DB = db
	tree.Addresses = addresses
	tree.MainAddress = mainAddress
	return tree, nil
}

func (tree *MerkleTree) StoreTree(address common.Address) error {
	if tree.DB == nil {
		return fmt.Errorf("database is nil")
	}

	merkleNodes := tree.Root
	prefix := common.PubKeyMerkleTrieDBPrefix[:]
	key := append(prefix, address.GetBytes()...)

	treeb, err := common.Marshal(merkleNodes, common.MerkleNodeDBPrefix)
	if err != nil {
		return err
	}
	err = tree.DB.Put(key, treeb)
	if err != nil {
		return err
	}
	prefix = common.PubKeyRootHashMerkleTreeDBPrefix[:]
	key = append(prefix, address.GetBytes()...)
	err = tree.DB.Put(key, tree.GetRootHash())
	if err != nil {
		return err
	}
	ret := []byte{}
	for _, a := range tree.Addresses {
		ret = append(ret, a.GetBytesWithPrimary()...)
	}
	prefix = common.PubKeyBytesMerkleTrieDBPrefix[:]
	key = append(prefix, address.GetBytes()...)
	err = tree.DB.Put(key, ret)
	if err != nil {
		return err
	}
	return nil
}

func LoadAddresses(mainAddress common.Address) ([]common.Address, error) {
	prefix := common.PubKeyBytesMerkleTrieDBPrefix[:]
	key := append(prefix, mainAddress.GetBytes()...)
	pkbytes, err := GlobalMerkleTree.DB.Get(key)
	if err != nil {
		return nil, err
	}
	len_addr_pr := common.AddressLength + 1
	ret := []common.Address{}
	for i := 0; i < len(pkbytes)/len_addr_pr; i++ {
		a := common.Address{}
		err = a.Init(pkbytes[len_addr_pr*i : len_addr_pr*(i+1)])
		if err != nil {
			return nil, err
		}
		ret = append(ret, a)
	}
	return ret, nil
}

func LoadHashMerkleTreeByAddress(mainAddress common.Address) ([]byte, error) {
	prefix := common.PubKeyRootHashMerkleTreeDBPrefix[:]
	key := append(prefix, mainAddress.GetBytes()...)
	hash, err := GlobalMerkleTree.DB.Get(key)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

func (t *MerkleTree) Destroy() {
	if t != nil {
		t.Root = nil
		t.Addresses = nil
		t.MainAddress = common.Address{}
		t.DB = nil
	}
}

func LoadTreeWithoutAddresses(mainAddress common.Address) (*MerkleTree, error) {
	tree := new(MerkleTree)
	prefix := common.PubKeyMerkleTrieDBPrefix[:]
	key := append(prefix, mainAddress.GetBytes()...)
	treeb, err := GlobalMerkleTree.DB.Get(key)
	if err != nil {
		return &MerkleTree{}, err
	}
	var merkleNodes []MerkleNode
	err = common.Unmarshal(treeb, common.MerkleNodeDBPrefix, &merkleNodes)
	if err != nil {
		return &MerkleTree{}, err
	}
	tree.Root = merkleNodes

	prefix = common.PubKeyRootHashMerkleTreeDBPrefix[:]
	key = append(prefix, mainAddress.GetBytes()...)
	rootHash, err := GlobalMerkleTree.DB.Get(key)
	if err != nil || len(tree.Root) == 0 {
		return &MerkleTree{}, err
	}
	tree.Root[0].Data = rootHash

	return tree, nil
}

func FindAddressForMainAddress(mainAddress common.Address, address common.Address) (int64, error) {

	tree, err := LoadTreeWithoutAddresses(mainAddress)
	if err != nil {
		return -1, err
	}
	if len(tree.Root) == 0 {
		return -1, fmt.Errorf("no merkle tree root hash")
	}
	left, hl := tree.Root[0].containsAddress(0, address.GetBytes())
	if left {
		return hl, nil
	}
	if len(tree.Root) > 1 {
		right, hr := tree.Root[1].containsAddress(0, address.GetBytes())
		if right {
			return hr, nil
		}
	}

	return -1, fmt.Errorf("pub key not found")
}

func LastIndexStoredInMerleTrie() (int64, error) {
	i := int64(0)
	for {
		ib := common.GetByteInt64(i)
		prefix := append(common.PubKeyRootHashMerkleTreeDBPrefix[:], ib...)
		isKey, err := GlobalMerkleTree.DB.IsKey(prefix)
		if err != nil {
			return i - 1, err
		}
		if isKey == false {
			break
		}
		i++
	}
	return i - 1, nil
}

func RemoveMerkleTrieFromDB(mainAddress common.Address) error {
	hb := mainAddress.GetBytes()
	prefix := append(common.PubKeyRootHashMerkleTreeDBPrefix[:], hb...)
	err := GlobalMerkleTree.DB.Delete(prefix)
	if err != nil {
		logger.GetLogger().Println("cannot remove root merkle trie hash", err)
		return err
	}
	prefix = append(common.PubKeyMerkleTrieDBPrefix[:], hb...)
	err = GlobalMerkleTree.DB.Delete(prefix)
	if err != nil {
		logger.GetLogger().Println("cannot remove merkle trie node", err)
		return err
	}
	prefix = append(common.PubKeyBytesMerkleTrieDBPrefix[:], hb...)
	err = GlobalMerkleTree.DB.Delete(prefix)
	if err != nil {
		logger.GetLogger().Println("cannot remove merkle trie transaction hashes", err)
		return err
	}
	return nil
}
