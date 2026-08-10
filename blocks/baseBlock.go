package blocks

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/pubkeys"
	"github.com/qwid-org/qwid-node/wallet"
)

type BaseHeader struct {
	PreviousHash     common.Hash      `json:"previous_hash"`
	Difficulty       int32            `json:"difficulty"`
	Height           int64            `json:"height"`
	DelegatedAccount common.Address   `json:"delegated_account"`
	OperatorAccount  common.Address   `json:"operator_account"`
	RootMerkleTree   common.Hash      `json:"root_merkle_tree"`
	Encryption1      []byte           `json:"encryption_1"`
	Encryption2      []byte           `json:"encryption_2"`
	Signature        common.Signature `json:"signature"`
	SignatureMessage []byte           `json:"signature_message"`
}

type BaseBlock struct {
	BaseHeader       BaseHeader  `json:"header"`
	BlockHeaderHash  common.Hash `json:"block_header_hash"`
	BlockTimeStamp   int64       `json:"block_time_stamp"`
	RewardPercentage int16       `json:"reward_percentage"`
	Supply           int64       `json:"supply"`
	PriceOracle      int64       `json:"price_oracle"`
	RandOracle       int64       `json:"rand_oracle"`
	PriceOracleData  []byte      `json:"price_oracle_data"`
	RandOracleData   []byte      `json:"rand_oracle_data"`
	// OracleProofs carries the signed oracle nonce transactions backing the
	// PriceOracleData/RandOracleData entries, so validators can re-verify their
	// provenance instead of trusting the producer's reconstructed triples.
	OracleProofs [][]byte `json:"oracle_proofs"`
}

const (
	// Consensus upgrades activate at the first height after the currently
	// published network height (23). Blocks below these heights retain their
	// historical encoding and validation rules.
	OracleProofsActivationHeight        int64 = 24
	TimestampDifficultyActivationHeight int64 = 24

	// There are only 255 encodable delegated ids (with zero reserved). Keep
	// parser limits explicit so peer-controlled counts cannot drive allocations.
	MaxOracleProofs     int32 = 255
	MaxOracleProofSize        = 1 << 20
	MaxOracleProofBytes       = 16 << 20
)

// bytesSliceToBytes length-prefixes a slice of byte slices for block encoding.
func bytesSliceToBytes(items [][]byte) []byte {
	out := common.GetByteInt32(int32(len(items)))
	for _, it := range items {
		out = append(out, common.BytesToLenAndBytes(it)...)
	}
	return out
}

// bytesSliceFromBytes reverses bytesSliceToBytes, returning the decoded items
// and the remaining bytes.
func bytesSliceFromBytes(b []byte) ([][]byte, []byte, error) {
	if len(b) < 4 {
		return nil, nil, fmt.Errorf("not enough bytes to decode byte-slice length")
	}
	n := common.GetInt32FromByte(b[:4])
	b = b[4:]
	if n < 0 {
		return nil, nil, fmt.Errorf("negative byte-slice count: %d", n)
	}
	if n > MaxOracleProofs {
		return nil, nil, fmt.Errorf("byte-slice count %d exceeds limit %d", n, MaxOracleProofs)
	}
	// Every item needs at least its four-byte length prefix. Check this before
	// allocating the slice, otherwise a four-byte hostile input can request many
	// gigabytes of capacity.
	if int64(n) > int64(len(b))/4 {
		return nil, nil, fmt.Errorf("byte-slice count %d cannot fit in %d bytes", n, len(b))
	}
	items := make([][]byte, 0, n)
	total := 0
	for i := int32(0); i < n; i++ {
		if len(b) < 4 {
			return nil, nil, fmt.Errorf("not enough bytes for item %d length", i)
		}
		itemLen := int64(binary.BigEndian.Uint32(b[:4]))
		if itemLen > MaxOracleProofSize {
			return nil, nil, fmt.Errorf("byte-slice item %d length %d is invalid", i, itemLen)
		}
		total += int(itemLen)
		if total > MaxOracleProofBytes {
			return nil, nil, fmt.Errorf("byte-slice payload exceeds limit %d", MaxOracleProofBytes)
		}
		var it []byte
		var err error
		it, b, err = common.BytesWithLenToBytes(b)
		if err != nil {
			return nil, nil, err
		}
		items = append(items, it)
	}
	return items, b, nil
}

func FromBytesToEncryptionConfig(bb []byte, primary bool) (oqs.ConfigEnc, error) {
	if len(bb) == 0 {

		if !common.IsPaused() && primary {
			enc := oqs.CreateEncryptionScheme(common.SigName(), common.PubKeyLength(false), common.PrivateKeyLength(), common.SignatureLength(false), common.IsPaused())
			return enc, nil
		} else if !common.IsPaused2() && !primary {
			//TODO maybe one should make it better
			enc := oqs.CreateEncryptionScheme(common.SigName2(), common.PubKeyLength2(false), common.PrivateKeyLength2(), common.SignatureLength2(false), common.IsPaused2())
			return enc, nil
		} else {
			return oqs.ConfigEnc{}, fmt.Errorf("no valid encyption scheme")
		}
	}
	return oqs.FromBytesToEncryptionConfig(bb[:])
}

// GetString returns a string representation of BaseHeader.
func (b *BaseHeader) GetString() string {

	enc1String := ""
	enc1, err := FromBytesToEncryptionConfig(b.Encryption1[:], true)
	if err != nil {
		enc1String = fmt.Sprint(err)
	}
	enc1String = enc1.ToString()
	enc2String := ""
	enc2, err := FromBytesToEncryptionConfig(b.Encryption2[:], false)
	if err != nil {
		enc2String = fmt.Sprint(err)
	}
	enc2String = enc2.ToString()
	return fmt.Sprintf("PreviousHash: %s\nDifficulty: %d\nHeight: %d\nDelegatedAccount: %s\nOperatorAccount: %s\nRootMerkleTree: %s\nEncryption1: %s\nEncryption2: %s\nSignature: %s\nSignatureMessage: %x",
		b.PreviousHash.GetHex(), b.Difficulty, b.Height, b.DelegatedAccount.GetHex(), b.OperatorAccount.GetHex(), b.RootMerkleTree.GetHex(), enc1String, enc2String, b.Signature.GetHex(), b.SignatureMessage)
}

// GetString returns a string representation of BaseBlock.
func (b *BaseBlock) GetString() string {
	return fmt.Sprintf("Header: {%s}\nBlockHeaderHash: %s\nBlockTimeStamp: %d\nRewardPercentage: %d\nSupply: %d\nPriceOracle: %d\nRandOracle: %d\n",
		b.BaseHeader.GetString(), b.BlockHeaderHash.GetHex(), b.BlockTimeStamp, b.RewardPercentage, b.Supply, b.PriceOracle, b.RandOracle)
}

func (b *BaseHeader) GetBytesWithoutSignature() []byte {
	rb := b.PreviousHash.GetBytes()
	rb = append(rb, common.GetByteInt32(b.Difficulty)...)
	rb = append(rb, common.GetByteInt64(b.Height)...)
	rb = append(rb, b.DelegatedAccount.GetBytes()...)
	rb = append(rb, b.OperatorAccount.GetBytesWithPrimary()...)
	rb = append(rb, b.RootMerkleTree.GetBytes()...)
	rb = append(rb, common.BytesToLenAndBytes(b.Encryption1)...)
	rb = append(rb, common.BytesToLenAndBytes(b.Encryption2)...)
	return rb
}

func (b *BaseHeader) GetBytes() []byte {
	rb := b.PreviousHash.GetBytes()
	rb = append(rb, common.GetByteInt32(b.Difficulty)...)
	rb = append(rb, common.GetByteInt64(b.Height)...)
	rb = append(rb, b.DelegatedAccount.GetBytes()...)
	rb = append(rb, b.OperatorAccount.GetBytesWithPrimary()...)
	rb = append(rb, b.RootMerkleTree.GetBytes()...)

	rb = append(rb, common.BytesToLenAndBytes(b.Encryption1)...)
	rb = append(rb, common.BytesToLenAndBytes(b.Encryption2)...)

	rb = append(rb, common.BytesToLenAndBytes(b.SignatureMessage)...)
	rb = append(rb, common.BytesToLenAndBytes(b.Signature.GetBytes())...)
	//logger.GetLogger().Println("block ", b.Height, " len bytes ", len(rb))
	return rb
}

func (bh *BaseHeader) Verify(sigName, sigName2 string, isPaused, isPaused2 bool) bool {
	signatureBlockHeaderMessage := bh.GetBytesWithoutSignature()
	if !bytes.Equal(signatureBlockHeaderMessage, bh.SignatureMessage) {
		logger.GetLogger().Println("signatures are different")
		return false
	}
	calcHash, err := common.CalcHashToByte(signatureBlockHeaderMessage)
	if err != nil {
		logger.GetLogger().Println(err)
		return false
	}
	a := bh.OperatorAccount
	var primary bool
	sig := bh.Signature.GetBytes()
	primary = sig[0] == 0
	//logger.GetLogger().Println("a:", a, "primary:", primary)
	pk, err := pubkeys.LoadPubKeyWithPrimary(a, primary)
	if err != nil {
		logger.GetLogger().Println(err)
		return false
	}
	return wallet.Verify(calcHash, bh.Signature.GetBytes(), pk.GetBytes(), sigName, sigName2, isPaused, isPaused2)
}

func (bh *BaseHeader) Sign(primary bool) (common.Signature, []byte, error) {
	signatureBlockHeaderMessage := bh.GetBytesWithoutSignature()
	calcHash, err := common.CalcHashToByte(signatureBlockHeaderMessage)
	if err != nil {
		return common.Signature{}, nil, err
	}
	w := wallet.GetActiveWallet()
	sign, err := w.Sign(calcHash, primary)
	if err != nil {
		return common.Signature{}, nil, err
	}
	return *sign, signatureBlockHeaderMessage, nil
}

func (bh *BaseHeader) GetFromBytes(b []byte) ([]byte, error) {
	//logger.GetLogger().Println("block decompile len bytes ", len(b))
	if len(b) < 117 {
		return nil, fmt.Errorf("not enough bytes to decode BaseHeader")
	}

	bh.PreviousHash = common.GetHashFromBytes(b[:32])
	bh.Difficulty = common.GetInt32FromByte(b[32:36])
	bh.Height = common.GetInt64FromByte(b[36:44])
	address, err := common.BytesToAddress(b[44:64])
	if err != nil {
		return nil, err
	}
	bh.DelegatedAccount = address
	opAddress, err := common.BytesToAddress(b[64:85])
	if err != nil {
		return nil, err
	}
	bh.OperatorAccount = opAddress
	bh.RootMerkleTree = common.GetHashFromBytes(b[85:117])

	msgb, b, err := common.BytesWithLenToBytes(b[117:])
	if err != nil {
		return nil, err
	}
	bh.Encryption1 = msgb
	msgb, b, err = common.BytesWithLenToBytes(b[:])
	if err != nil {
		return nil, err
	}
	bh.Encryption2 = msgb

	msgb, b, err = common.BytesWithLenToBytes(b[:])
	if err != nil {
		return nil, err
	}
	bh.SignatureMessage = msgb
	sigBytes, b, err := common.BytesWithLenToBytes(b[:])
	if err != nil {
		return nil, err
	}
	sig, err := common.GetSignatureFromBytes(sigBytes, opAddress)
	if err != nil {
		return nil, err
	}
	bh.Signature = sig
	return b, nil
}

func (bb *BaseBlock) GetBytes() []byte {
	b := bb.BaseHeader.GetBytes()
	b = append(b, bb.BlockHeaderHash.GetBytes()...)
	b = append(b, common.GetByteInt64(bb.BlockTimeStamp)...)
	b = append(b, common.GetByteInt16(bb.RewardPercentage)...)
	b = append(b, common.GetByteInt64(bb.Supply)...)
	b = append(b, common.GetByteInt64(bb.PriceOracle)...)
	b = append(b, common.GetByteInt64(bb.RandOracle)...)
	b = append(b, common.BytesToLenAndBytes(bb.PriceOracleData)...)
	b = append(b, common.BytesToLenAndBytes(bb.RandOracleData)...)
	if bb.BaseHeader.Height >= OracleProofsActivationHeight {
		b = append(b, bytesSliceToBytes(bb.OracleProofs)...)
	}
	return b
}

func (bb *BaseBlock) GetFromBytes(b []byte) ([]byte, error) {
	//logger.GetLogger().Println("bytes to decode BaseBlock", len(b))
	if len(b) < 116+44+16 {
		return nil, fmt.Errorf("not enough bytes to decode BaseBlock")
	}
	b, err := bb.BaseHeader.GetFromBytes(b)
	if err != nil {
		return nil, err
	}
	bb.BlockHeaderHash = common.GetHashFromBytes(b[:32])
	bb.BlockTimeStamp = common.GetInt64FromByte(b[32:40])
	bb.RewardPercentage = common.GetInt16FromByte(b[40:42])
	bb.Supply = common.GetInt64FromByte(b[42:50])
	bb.PriceOracle = common.GetInt64FromByte(b[50:58])
	bb.RandOracle = common.GetInt64FromByte(b[58:66])
	bb.PriceOracleData, b, err = common.BytesWithLenToBytes(b[66:])
	if err != nil {
		return nil, err
	}
	bb.RandOracleData, b, err = common.BytesWithLenToBytes(b[:])
	if err != nil {
		return nil, err
	}
	if bb.BaseHeader.Height >= OracleProofsActivationHeight {
		bb.OracleProofs, b, err = bytesSliceFromBytes(b[:])
		if err != nil {
			return nil, err
		}
	} else {
		bb.OracleProofs = nil
	}
	return b[:], nil
}

func (b *BaseHeader) CalcHash() (common.Hash, error) {
	toByte, err := common.CalcHashToByte(b.GetBytes())
	if err != nil {
		return common.Hash{}, err
	}
	hash := common.GetHashFromBytes(toByte)
	return hash, nil
}
