package blocks

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

// signedTestBlock builds a fully valid block at height h on top of parent,
// produced by k: body hash, state root, header signature, header hash.
func signedTestBlock(t *testing.T, k stageBKey, h int64, parent Block, stateRoot common.Hash) Block {
	t.Helper()
	enc1, _ := oqs.GenerateBytesFromParams(common.SigName(), common.PubKeyLength(false), common.PrivateKeyLength(), common.SignatureLength(false), common.IsPaused())
	enc2, _ := oqs.GenerateBytesFromParams(common.SigName2(), common.PubKeyLength2(false), common.PrivateKeyLength2(), common.SignatureLength2(false), common.IsPaused2())
	bl := Block{
		BaseBlock: BaseBlock{
			BaseHeader: BaseHeader{
				PreviousHash:     parent.BlockHash,
				Difficulty:       1,
				Height:           h,
				DelegatedAccount: common.GetDelegatedAccountAddress(1),
				OperatorAccount:  k.addr,
				RootMerkleTree:   common.EmptyHash(),
				Encryption1:      enc1,
				Encryption2:      enc2,
				StateRoot:        stateRoot,
			},
			BlockTimeStamp:   parent.GetBlockTimeStamp() + 10,
			RewardPercentage: 100,
			Supply:           parent.GetBlockSupply() + account.GetReward(parent.GetBlockSupply()),
			PriceOracleData:  []byte{},
			RandOracleData:   []byte{},
		},
		TransactionsHashes: []common.Hash{},
	}
	body, err := bl.BaseBlock.CalcBodyHash()
	if err != nil {
		t.Fatal(err)
	}
	bl.BaseBlock.BaseHeader.BodyHash = body
	msg := bl.BaseBlock.BaseHeader.GetBytesWithoutSignature()
	digest, err := common.CalcHashToByte(msg)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := k.s.Sign(digest)
	if err != nil {
		t.Fatal(err)
	}
	bl.BaseBlock.BaseHeader.Signature, _ = common.GetSignatureFromBytes(append([]byte{0}, raw...), k.addr)
	bl.BaseBlock.BaseHeader.SignatureMessage = msg
	bl.BaseBlock.BlockHeaderHash, err = bl.BaseBlock.BaseHeader.CalcHash()
	if err != nil {
		t.Fatal(err)
	}
	bl.BlockHash, err = bl.CalcBlockHash()
	if err != nil {
		t.Fatal(err)
	}
	return bl
}

func headerTestSetup(t *testing.T) (stageBKey, Block) {
	t.Helper()
	k := registeredStageBKey(t)
	saved := transactionsPool.GlobalMerkleTree
	transactionsPool.InitPermanentTrie()
	t.Cleanup(func() { transactionsPool.GlobalMerkleTree = saved })
	parent := Block{BaseBlock: BaseBlock{BaseHeader: BaseHeader{Height: 9}, BlockTimeStamp: 1_700_000_000, Supply: 1_000_000_000_000}}
	parent.BlockHash, _ = parent.CalcBlockHash()
	return k, parent
}

// The new header fields survive serialization.
func TestHeaderCarriesBodyHashAndStateRoot(t *testing.T) {
	k, parent := headerTestSetup(t)
	root := common.GetHashFromBytes(bytes.Repeat([]byte{0x5A}, 32))
	bl := signedTestBlock(t, k, 10, parent, root)
	got, err := Block{}.GetFromBytes(bl.GetBytes())
	if err != nil {
		t.Fatal(err)
	}
	if got.GetHeader().StateRoot != root || got.GetHeader().BodyHash != bl.GetHeader().BodyHash {
		t.Fatal("BodyHash/StateRoot lost in serialization")
	}
}

func TestValidBlockPassesCheckBaseBlock(t *testing.T) {
	k, parent := headerTestSetup(t)
	bl := signedTestBlock(t, k, 10, parent, common.Hash{})
	if _, err := CheckBaseBlock(bl, parent, false); err != nil {
		t.Fatalf("a valid block was rejected: %v", err)
	}
}

// S3-03: proof-of-synergy is judged on BlockHeaderHash, which must be the
// header's real hash.
func TestCheckBaseBlockRejectsForgedHeaderHash(t *testing.T) {
	k, parent := headerTestSetup(t)
	bl := signedTestBlock(t, k, 10, parent, common.Hash{})
	bl.BaseBlock.BlockHeaderHash = common.Hash{} // wins any difficulty
	bl.BlockHash, _ = bl.CalcBlockHash()
	if _, err := CheckBaseBlock(bl, parent, false); err == nil {
		t.Fatal("a block with a forged BlockHeaderHash was accepted")
	}
}

// S3-04: the producer's signature covers the whole block - a relay that edits
// the body creates an invalid block, not another valid one.
func TestCheckBaseBlockRejectsEditedBody(t *testing.T) {
	k, parent := headerTestSetup(t)
	bl := signedTestBlock(t, k, 10, parent, common.Hash{})
	bl.BaseBlock.RewardPercentage = 500
	bl.BlockHash, _ = bl.CalcBlockHash()
	if _, err := CheckBaseBlock(bl, parent, false); err == nil {
		t.Fatal("a block whose body was edited after signing was accepted")
	}
}

// S3-05: the state root is a deterministic function of the state.
func TestStateRootIsDeterministicAndSensitive(t *testing.T) {
	withBalanceTestDB(t)
	InitStateDB()
	a, b := testAddress(0x01), testAddress(0x02)
	set := func(order []common.Address, balA int64) {
		m := map[[common.AddressLength]byte]account.Account{}
		for _, x := range order {
			bal := int64(7)
			if x == a {
				bal = balA
			}
			m[x.ByteValue] = account.Account{Address: x.ByteValue, Balance: bal}
		}
		account.Accounts = account.AccountsType{AllAccounts: m}
	}
	set([]common.Address{a, b}, 100)
	r1, err := ComputeStateRoot()
	if err != nil {
		t.Fatal(err)
	}
	set([]common.Address{b, a}, 100)
	r2, _ := ComputeStateRoot()
	set([]common.Address{a, b}, 101)
	r3, _ := ComputeStateRoot()
	if r1 != r2 {
		t.Fatal("the state root depends on map order")
	}
	if r1 == r3 {
		t.Fatal("a balance change did not change the state root")
	}
}

// S3-05: a block whose state root is not ours is refused before it is applied.
func TestVerifyStateRootRejectsMismatch(t *testing.T) {
	withBalanceTestDB(t)
	InitStateDB()
	account.Accounts = account.AccountsType{AllAccounts: map[[common.AddressLength]byte]account.Account{}}
	ours, err := ComputeStateRoot()
	if err != nil {
		t.Fatal(err)
	}
	good := Block{BaseBlock: BaseBlock{BaseHeader: BaseHeader{Height: 5, StateRoot: ours}}}
	bad := Block{BaseBlock: BaseBlock{BaseHeader: BaseHeader{Height: 5, StateRoot: common.GetHashFromBytes(bytes.Repeat([]byte{1}, 32))}}}
	if err := VerifyStateRoot(good); err != nil {
		t.Fatalf("matching state root refused: %v", err)
	}
	if err := VerifyStateRoot(bad); err == nil {
		t.Fatal("a mismatching state root was accepted")
	}
}

// S3-07: a negative reward percentage is rejected up front, not after the
// block's transactions have been applied.
func TestCheckBaseBlockRejectsNegativeRewardPercentage(t *testing.T) {
	k, parent := headerTestSetup(t)
	bl := signedTestBlock(t, k, 10, parent, common.Hash{})
	bl.BaseBlock.RewardPercentage = -1
	bl = resealTestBlock(t, k, bl)
	if _, err := CheckBaseBlock(bl, parent, false); err == nil {
		t.Fatal("negative reward percentage accepted")
	}
}

// resealTestBlock recomputes body hash, signature and hashes after an edit.
func resealTestBlock(t *testing.T, k stageBKey, bl Block) Block {
	t.Helper()
	body, err := bl.BaseBlock.CalcBodyHash()
	if err != nil {
		t.Fatal(err)
	}
	bl.BaseBlock.BaseHeader.BodyHash = body
	msg := bl.BaseBlock.BaseHeader.GetBytesWithoutSignature()
	digest, _ := common.CalcHashToByte(msg)
	raw, err := k.s.Sign(digest)
	if err != nil {
		t.Fatal(err)
	}
	bl.BaseBlock.BaseHeader.Signature, _ = common.GetSignatureFromBytes(append([]byte{0}, raw...), k.addr)
	bl.BaseBlock.BaseHeader.SignatureMessage = msg
	bl.BaseBlock.BlockHeaderHash, _ = bl.BaseBlock.BaseHeader.CalcHash()
	bl.BlockHash, _ = bl.CalcBlockHash()
	return bl
}

// Regression (chain stalled at height 0): the body hash covers the oracle
// proofs, so they must survive serialization at EVERY height - the wire
// format used to drop them below an activation height, and every early block
// failed its own body hash at the receiver.
func TestBodyHashSurvivesWireRoundTripWithProofsAtLowHeight(t *testing.T) {
	k, parent := headerTestSetup(t)
	bl := signedTestBlock(t, k, 1, parent, common.Hash{})
	bl.BaseBlock.OracleProofs = [][]byte{{1, 2, 3}, {4, 5}}
	bl = resealTestBlock(t, k, bl)
	got, err := Block{}.GetFromBytes(bl.GetBytes())
	if err != nil {
		t.Fatal(err)
	}
	body, err := got.BaseBlock.CalcBodyHash()
	if err != nil {
		t.Fatal(err)
	}
	if body != got.GetHeader().BodyHash {
		t.Fatal("a received block no longer matches its signed body hash")
	}
}

// Regression: genesis has no parent, so its difficulty cannot be derived
// from one. InitGenesis checks the genesis block against itself; that must
// not trip the parent-difficulty rule.
func TestGenesisPassesCheckBaseBlockAgainstItself(t *testing.T) {
	k, parent := headerTestSetup(t)
	g := signedTestBlock(t, k, 0, parent, common.Hash{})
	// Difficulty 1 against itself with interval 0 would "expect" 1+change.
	if _, err := CheckBaseBlock(g, g, false); err != nil {
		t.Fatalf("genesis rejected: %v", err)
	}
}
