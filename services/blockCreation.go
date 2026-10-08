package services

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
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
	}

	reward := account.GetReward(lastBlock.GetBlockSupply())
	supply := lastBlock.GetBlockSupply() + reward

	// Derive difficulty from the block's own committed timestamp relative to the
	// parent so validators can recompute and verify it (see blocks.ValidDifficulty).
	blockTimeStamp := common.GetCurrentTimeStampInSecond()
	// Validators reject a block not strictly later than its parent
	// (validateBlockTimestamp) and penalise its sender, so a block built in
	// the same second as its parent got honest producers banned (audit
	// F3-04). Wait for the next round instead.
	if lastBlock.GetHeader().Height >= 1 && blockTimeStamp <= lastBlock.GetBlockTimeStamp() {
		return blocks.Block{}, fmt.Errorf("parent block %d is not older than this second - not producing yet", lastBlock.GetHeader().Height)
	}
	ti := blockTimeStamp - lastBlock.GetBlockTimeStamp()
	bblock := lastBlock.GetBaseBlock()
	diff := blocks.AdjustDifficulty(bblock.BaseHeader.Difficulty, ti)
	sendingTimeMessage := common.GetByteInt64(nonceTx[0].GetParam().SendingTime)
	rootMerkleTrie := common.Hash{}
	rootMerkleTrie.Set(merkleTrie.GetRootHash())
	// The body is fixed BEFORE the header is signed: the signature now covers
	// it through BodyHash (S3-04), so the oracle values have to be known first.
	// S4-06: the oracle data is derived from exactly the proofs embedded, so
	// the two always agree, and the values are computed the way validators
	// recompute them.
	oracleProofs := oracles.GenerateOracleProofs(heightTransaction)
	priceOracleData, err := blocks.OracleDataFromProofs(oracleProofs)
	if err != nil {
		return blocks.Block{}, err
	}
	totalStaked := account.GetStakedInAllDelegatedAccounts()
	priceOracle, err := oracles.PriceFromData(priceOracleData, totalStaked)
	if err != nil {
		// S4-06: an unestablished price carries the parent's forward.
		logger.GetLogger().Println("could not establish price oracle, carrying the previous one forward:", err)
		priceOracle = lastBlock.BaseBlock.PriceOracle
	}
	randReveal, randCommit, randMix, randOracle, err := randaoForBlock(myWallet, lastBlock, heightTransaction)
	if err != nil {
		return blocks.Block{}, err
	}
	bb := blocks.BaseBlock{
		BlockTimeStamp:   blockTimeStamp,
		RewardPercentage: common.GetMyRewardPercentage(),
		Supply:           supply,
		PriceOracle:      priceOracle,
		RandOracle:       randOracle,
		PriceOracleData:  priceOracleData,
		OracleProofs:     oracleProofs,
		RandReveal:       randReveal,
		RandCommit:       randCommit,
		RandMix:          randMix,
	}
	bodyHash, err := bb.CalcBodyHash()
	if err != nil {
		return blocks.Block{}, err
	}
	// S3-05: commit to the state this block is built on - ours after
	// lastBlock. Under BlockMutex, so no block is half-applied while hashing.
	common.BlockMutex.Lock()
	if common.GetHeight() != lastBlock.GetHeader().Height {
		common.BlockMutex.Unlock()
		return blocks.Block{}, fmt.Errorf("height moved to %d while building on %d", common.GetHeight(), lastBlock.GetHeader().Height)
	}
	stateRoot, err := blocks.ComputeStateRoot()
	// S4-05: our vote goes into the header only if the proofs in this very
	// block carry enough stake for it; otherwise repeat the parent's config.
	// Validators run the same tally, so a block is never built to be rejected.
	if len(encryption1) == 0 || !blocks.EncryptionChangeAuthorised(bb.OracleProofs, lastBlock, encryption1, true, heightTransaction) {
		encryption1 = lastBlock.GetHeader().Encryption1
	}
	if len(encryption2) == 0 || !blocks.EncryptionChangeAuthorised(bb.OracleProofs, lastBlock, encryption2, false, heightTransaction) {
		encryption2 = lastBlock.GetHeader().Encryption2
	}
	common.BlockMutex.Unlock()
	if err != nil {
		return blocks.Block{}, err
	}
	bh := blocks.BaseHeader{
		PreviousHash:     lastBlock.GetBlockHash(),
		Difficulty:       diff,
		Height:           heightTransaction,
		DelegatedAccount: common.GetDelegatedAccount(),
		OperatorAccount:  myWallet.MainAddress,
		RootMerkleTree:   rootMerkleTrie,
		BodyHash:         bodyHash,
		StateRoot:        stateRoot,
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
	bb.BaseHeader = bh
	bb.BlockHeaderHash = bhHash

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

// randaoForBlock produces this node's RANDAO fields for its block at height on
// top of lastBlock (S4-06): it opens the commitment the chain holds for it, if
// one is due, and commits to the seed of this height. A node that cannot open
// its commitment - its wallet secret changed - cannot produce until the
// commitment lapses; a block without the reveal would be rejected anyway.
func randaoForBlock(w *wallet.Wallet, lastBlock blocks.Block, height int64) (reveal []byte, commit, mix common.Hash, rand int64, err error) {
	n, err := account.IntDelegatedAccountFromAddress(common.GetDelegatedAccount())
	if err != nil || n < 1 || n > 255 {
		return nil, common.Hash{}, common.Hash{}, 0, fmt.Errorf("wrong delegated account for RANDAO")
	}
	held, heldAt := account.GetRandCommit(n, w.MainAddress.ByteValue)
	if blocks.RevealDue(heldAt, height) {
		seed, serr := w.RandaoSeed(heldAt)
		if serr != nil || !bytes.Equal(blocks.RandaoCommitment(seed).GetBytes(), held[:]) {
			return nil, common.Hash{}, common.Hash{}, 0, fmt.Errorf(
				"cannot open this node's RANDAO commitment from height %d (wallet secret changed?): "+
					"it can produce again from height %d", heldAt, heldAt+common.RandaoCommitExpiry+1)
		}
		reveal = seed
	}
	next, err := w.RandaoSeed(height)
	if err != nil {
		return nil, common.Hash{}, common.Hash{}, 0, err
	}
	commit, mix, rand = blocks.RandaoFields(lastBlock, height, reveal, next)
	return reveal, commit, mix, rand, nil
}
