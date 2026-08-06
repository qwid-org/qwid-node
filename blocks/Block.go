package blocks

import (
	"fmt"
	"strings"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/database"
	"github.com/wonabru/qwid-node/transactionsPool"
)

type Block struct {
	BaseBlock          BaseBlock     `json:"base_block"`
	TransactionsHashes []common.Hash `json:"transactions_hashes"`
	BlockHash          common.Hash   `json:"block_hash"`
	BlockFee           int64         `json:"block_fee"`
}

// GetString returns a string representation of Block.
func (b Block) GetString() string {
	// Convert transaction hashes to a slice of strings
	var txHashesStrings []string
	for _, hash := range b.TransactionsHashes {
		txHashesStrings = append(txHashesStrings, hash.GetHex())
	}
	// Join the slice of transaction hash strings with a separator
	transactionsHashesString := strings.Join(txHashesStrings, ", ")

	// Use the GetString method of BaseBlock to get its string representation
	return fmt.Sprintf("BaseBlock: {%s}\nTransactionsHashes: [%s]\nBlockHash: %s",
		b.BaseBlock.GetString(), transactionsHashesString, b.BlockHash.GetHex())
}

func (tb Block) GetBaseBlock() BaseBlock {
	return tb.BaseBlock
}
func (tb Block) GetBlockHeaderHash() common.Hash {
	return tb.BaseBlock.BlockHeaderHash
}
func (tb Block) GetBlockTimeStamp() int64 {
	return tb.BaseBlock.BlockTimeStamp
}
func (tb Block) GetBlockSupply() int64 {
	return tb.BaseBlock.Supply
}
func (tb Block) GetRewardPercentage() int16 {
	return tb.BaseBlock.RewardPercentage
}
func (tb Block) GetHeader() BaseHeader {
	return tb.GetBaseBlock().BaseHeader
}
func (tb Block) GetBlockTransactionsHashes() []common.Hash {
	return tb.TransactionsHashes
}
func (tb Block) GetBlockHash() common.Hash {
	return tb.BlockHash
}
func (tb Block) GetBytes() []byte {
	b := tb.BaseBlock.GetBytes()
	b = append(b, tb.BlockHash.GetBytes()...)
	b = append(b, common.GetByteInt64(tb.BlockFee)...)
	for _, tx := range tb.TransactionsHashes {
		b = append(b, tx.GetBytes()...)
	}
	return b
}

func (tb Block) GetBytesForHash() []byte {
	b := tb.BaseBlock.GetBytes()
	return b
}

func (tb Block) GetFromBytes(b []byte) (Block, error) {
	b, err := tb.BaseBlock.GetFromBytes(b)
	if err != nil {
		return Block{}, err
	}
	tb.BlockHash = common.GetHashFromBytes(b[0:32])
	b = b[32:]
	tb.BlockFee = common.GetInt64FromByte(b[0:8])
	b = b[8:]
	if len(b)%32 != 0 {
		return Block{}, fmt.Errorf("wrongly decompile block")
	}
	transactionHashesLength := len(b) / 32
	for i := 0; i < transactionHashesLength; i++ {
		bb := b[i*32 : (i+1)*32]
		tb.TransactionsHashes = append(tb.TransactionsHashes, common.GetHashFromBytes(bb))
	}

	return tb, nil
}

func (tb Block) CalcBlockHash() (common.Hash, error) {
	toByte, err := common.CalcHashToByte(tb.GetBytesForHash())
	if err != nil {
		return common.Hash{}, err
	}
	hash := common.GetHashFromBytes(toByte)
	return hash, nil
}

func (tb Block) CheckProofOfSynergy() bool {
	return CheckProofOfSynergy(tb.BaseBlock)
}

func (b Block) GetTransactionsHashes(height int64) ([]common.Hash, error) {
	txsHashes, err := transactionsPool.LoadTxHashes(height)
	if err != nil {
		return nil, err
	}
	hs := []common.Hash{}
	for _, hb := range txsHashes {
		eh := common.GetHashFromBytes(hb)
		hs = append(hs, eh)
	}
	return hs, nil
}

func (bl Block) StoreBlock() error {
	err := database.MainDB.Put(append(common.BlocksDBPrefix[:], bl.GetBlockHash().GetBytes()...), bl.GetBytes())
	if err != nil {
		return err
	}
	bh := common.GetByteInt64(bl.GetBaseBlock().BaseHeader.Height)
	err = database.MainDB.Put(append(common.BlockByHeightDBPrefix[:], bh...), bl.GetBlockHash().GetBytes())
	if err != nil {
		return err
	}

	return nil
}

func RemoveBlockFromDB(height int64) error {
	bh := common.GetByteInt64(height)
	hb, err := database.MainDB.Get(append(common.BlockByHeightDBPrefix[:], bh...))
	if err != nil {
		return err
	}
	err = database.MainDB.Delete(append(common.BlocksDBPrefix[:], hb...))
	if err != nil {
		return err
	}
	err = database.MainDB.Delete(append(common.BlockByHeightDBPrefix[:], bh...))
	if err != nil {
		return err
	}
	return nil
}

func LastHeightStoredInBlocks() (int64, error) {
	return database.LastContiguousHeight(database.MainDB, func(h int64) []byte {
		return append(common.BlockByHeightDBPrefix[:], common.GetByteInt64(h)...)
	})
}

func LoadHashOfBlock(height int64) ([]byte, error) {
	bh := common.GetByteInt64(height)
	hashb, err := database.MainDB.Get(append(common.BlockByHeightDBPrefix[:], bh...))
	if err != nil {
		return nil, err
	}
	return hashb, nil
}

func LoadBlock(height int64) (Block, error) {
	bh := common.GetByteInt64(height)
	hb, err := database.MainDB.Get(append(common.BlockByHeightDBPrefix[:], bh...))
	if err != nil {
		return Block{}, err
	}
	abl, err := database.MainDB.Get(append(common.BlocksDBPrefix[:], hb...))
	if err != nil {
		return Block{}, err
	}
	block := Block{}
	b, err := block.GetFromBytes(abl)
	if err != nil {
		return Block{}, err
	}
	return b, nil
}
