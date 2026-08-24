package services

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/message"
	"github.com/qwid-org/qwid-node/oracles"
	"github.com/qwid-org/qwid-node/pubkeys"
	"github.com/qwid-org/qwid-node/tcpip"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
	"github.com/qwid-org/qwid-node/wallet"
)

var (
	SendChanNonce      chan []byte
	SendChanSelfNonce  chan []byte
	SendMutexNonce     sync.RWMutex
	SendMutexSelfNonce sync.RWMutex
	SendChanTx         chan []byte
	SendMutexTx        sync.RWMutex
	SendChanSync       chan []byte
	SendMutexSync      sync.RWMutex
)

func CreateBlockFromNonceMessage(nonceTx []transactionsDefinition.Transaction,
	lastBlock blocks.Block,
	merkleTrie *transactionsPool.MerkleTree,
	txs []common.Hash) (blocks.Block, error) {

	encryption1 := []byte{}
	encryption2 := []byte{}
	b := []byte{}
	var err error
	myWallet := wallet.GetActiveWallet()
	heightTransaction := nonceTx[0].GetHeight()
	//totalFee := int64(0)
	for _, at := range nonceTx {
		heightLastBlocktransaction := common.GetInt64FromByte(at.GetData().GetOptData()[:8])
		hashLastBlocktransaction := at.GetData().GetOptData()[8:40]
		if !bytes.Equal(hashLastBlocktransaction, lastBlock.GetBlockHash().GetBytes()) {
			ha, err := blocks.LoadHashOfBlock(heightTransaction - 2)
			if err != nil {
				return blocks.Block{}, err
			}
			return blocks.Block{}, fmt.Errorf("last block hash and nonce hash do not match %v %v", ha, hashLastBlocktransaction)
		}
		if heightTransaction != heightLastBlocktransaction+1 {
			return blocks.Block{}, fmt.Errorf("last block height and nonce height do not match")
		}
		encryption1, b, err = common.BytesWithLenToBytes(at.GetData().GetOptData()[56:])
		if err != nil {
			return blocks.Block{}, err
		}
		encryption2, b, err = common.BytesWithLenToBytes(b[:])
		if err != nil {
			return blocks.Block{}, err
		}
		if len(encryption1) == 0 {
			encryption1, err = oqs.GenerateBytesFromParams(common.SigName(), common.PubKeyLength(false), common.PrivateKeyLength(), common.SignatureLength(false), common.IsPaused())
			if err != nil {
				return blocks.Block{}, err
			}
		}
		if len(encryption2) == 0 {
			encryption2, err = oqs.GenerateBytesFromParams(common.SigName2(), common.PubKeyLength2(false), common.PrivateKeyLength2(), common.SignatureLength2(false), common.IsPaused2())
			if err != nil {
				return blocks.Block{}, err
			}
		}
	}

	reward := account.GetReward(lastBlock.GetBlockSupply())
	supply := lastBlock.GetBlockSupply() + reward

	// Derive difficulty from the block's own committed timestamp relative to the
	// parent so validators can recompute and verify it (see blocks.ValidDifficulty).
	blockTimeStamp := common.GetCurrentTimeStampInSecond()
	ti := blockTimeStamp - lastBlock.GetBlockTimeStamp()
	bblock := lastBlock.GetBaseBlock()
	diff := blocks.AdjustDifficulty(bblock.BaseHeader.Difficulty, ti)
	sendingTimeMessage := common.GetByteInt64(nonceTx[0].GetParam().SendingTime)
	rootMerkleTrie := common.Hash{}
	rootMerkleTrie.Set(merkleTrie.GetRootHash())
	bh := blocks.BaseHeader{
		PreviousHash:     lastBlock.GetBlockHash(),
		Difficulty:       diff,
		Height:           heightTransaction,
		DelegatedAccount: common.GetDelegatedAccount(),
		OperatorAccount:  myWallet.MainAddress,
		RootMerkleTree:   rootMerkleTrie,
		Encryption1:      encryption1,
		Encryption2:      encryption2,
		Signature:        common.Signature{},
		SignatureMessage: sendingTimeMessage,
	}
	signPrimary := common.GetNodeSignPrimary(heightTransaction)
	if !signPrimary && !common.IsPaused() {
		// Never sign a header with a key peers cannot verify. After a signature-
		// scheme change the freshly derived secondary key is unregistered until
		// the operator MANUALLY sends a transaction carrying the pubkey and it
		// lands in a block (ProcessBlockPubKey), and a header — unlike a
		// transaction — cannot carry the pubkey itself. Until the key of the
		// CURRENT secondary scheme is registered, keep headers primary-signed.
		if _, err := pubkeys.LoadPubKeyWithPrimaryOfLength(myWallet.MainAddress, false, common.PubKeyLength2(false)); err != nil {
			logger.GetLogger().Println("secondary key not yet registered on-chain - signing block header with primary key")
			signPrimary = true
		}
	}
	sign, signatureBlockHeaderMessage, err := bh.Sign(signPrimary)
	if err != nil {
		return blocks.Block{}, err
	}
	bh.Signature = sign
	bh.SignatureMessage = signatureBlockHeaderMessage
	bhHash, err := bh.CalcHash()
	if err != nil {
		return blocks.Block{}, err
	}
	totalStaked := account.GetStakedInAllDelegatedAccounts()
	priceOracle, priceOracleData, err := oracles.CalculatePriceOracle(heightTransaction, totalStaked)
	if err != nil {
		logger.GetLogger().Println("could not establish price oracle", err)
	}
	randOracle, randOracleData, err := oracles.CalculateRandOracle(heightTransaction, totalStaked)
	if err != nil {
		logger.GetLogger().Println("could not establish rand oracle", err)
	}
	bb := blocks.BaseBlock{
		BaseHeader:       bh,
		BlockHeaderHash:  bhHash,
		BlockTimeStamp:   blockTimeStamp,
		RewardPercentage: common.GetMyRewardPercentage(),
		Supply:           supply,
		PriceOracle:      priceOracle,
		RandOracle:       randOracle,
		PriceOracleData:  priceOracleData,
		RandOracleData:   randOracleData,
		OracleProofs:     oracles.GenerateOracleProofs(heightTransaction),
	}

	bl := blocks.Block{
		BaseBlock:          bb,
		TransactionsHashes: txs,
		BlockHash:          common.Hash{},
	}
	hash, err := bl.CalcBlockHash()
	if err != nil {
		return blocks.Block{}, err
	}
	bl.BlockHash = hash

	return bl, nil
}

func GenerateBlockMessage(bl blocks.Block) message.TransactionsMessage {

	bm := message.BaseMessage{
		Head:    []byte("bl"),
		ChainID: common.GetChainID(),
	}
	txm := [2]byte{}
	copy(txm[:], append([]byte("N"), 0))
	atm := message.TransactionsMessage{
		BaseMessage:       bm,
		TransactionsBytes: map[[2]byte][][]byte{},
	}
	atm.TransactionsBytes[txm] = [][]byte{bl.GetBytes()}

	return atm
}

func SendNonce(ip [4]byte, nb []byte) {
	nb = append(ip[:], nb...)
	SendMutexNonce.Lock()
	defer SendMutexNonce.Unlock()
	select {
	case SendChanNonce <- nb:
	default:
		logger.GetLogger().Println("SendNonce: channel full, dropping message")
	}

}

func BroadcastBlock(bl blocks.Block) {
	atm := GenerateBlockMessage(bl)
	nb := atm.GetBytes()
	var ip [4]byte
	var peers = tcpip.GetPeersConnected(tcpip.NonceTopic)
	for topicip, _ := range peers {
		copy(ip[:], topicip[2:])
		SendNonce(ip, nb)
	}
}
