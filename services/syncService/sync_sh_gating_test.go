package syncServices

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"github.com/qwid-org/qwid-node/message"
	"github.com/qwid-org/qwid-node/pubkeys"
	"github.com/qwid-org/qwid-node/services"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

// storeTestChain stores blocks 0..top, each linked to its parent, with
// consistent accounts/staking snapshots so a rewind can land on any height.
func storeTestChain(t *testing.T, top int64) []blocks.Block {
	t.Helper()
	for i := 0; i < 256; i++ {
		account.StakingAccounts[i] = account.StakingAccountsType{
			AllStakingAccounts: map[[common.AddressLength]byte]account.StakingAccount{},
		}
	}
	holder := [common.AddressLength]byte{1, 2, 3}
	const supply, fee = int64(1_000_000_000), int64(150000)
	chain := make([]blocks.Block, 0, top+1)
	prev := common.EmptyHash()
	for h := int64(0); h <= top; h++ {
		account.Accounts = account.AccountsType{AllAccounts: map[[common.AddressLength]byte]account.Account{
			holder: {Address: holder, Balance: supply - h*fee},
		}}
		if err := account.StoreAccounts(h); err != nil {
			t.Fatal(err)
		}
		if err := account.StoreStakingAccounts(h); err != nil {
			t.Fatal(err)
		}
		bl := unsignedTestBlock(t, h, prev, supply, h*fee)
		if err := bl.StoreBlock(); err != nil {
			t.Fatal(err)
		}
		chain = append(chain, bl)
		prev = bl.BlockHash
	}
	return chain
}

func unsignedTestBlock(t *testing.T, h int64, prev common.Hash, supply, fees int64) blocks.Block {
	t.Helper()
	sig, err := common.GetSignatureFromBytes(make([]byte, common.SignatureLength(false)), common.EmptyAddress())
	if err != nil {
		t.Fatal(err)
	}
	bl := blocks.Block{
		BaseBlock: blocks.BaseBlock{
			BaseHeader: blocks.BaseHeader{
				PreviousHash:     prev,
				DelegatedAccount: common.EmptyAddress(),
				OperatorAccount:  common.EmptyAddress(),
				Height:           h,
				Encryption1:      []byte{},
				Encryption2:      []byte{},
				SignatureMessage: []byte{1, 2, 3},
				Signature:        sig,
			},
			Supply:          supply,
			PriceOracleData: []byte{},
			RandOracleData:  []byte{},
		},
		TransactionsHashes: []common.Hash{},
		BlockFee:           fees,
	}
	hash, err := bl.CalcBlockHash()
	if err != nil {
		t.Fatal(err)
	}
	bl.BlockHash = hash
	return bl
}

func shMessage(indices []int64, bls []blocks.Block) []byte {
	m := message.TransactionsMessage{
		BaseMessage:       message.BaseMessage{Head: []byte("sh"), ChainID: common.GetChainID()},
		TransactionsBytes: map[[2]byte][][]byte{},
	}
	for i := range indices {
		m.TransactionsBytes[[2]byte{'I', 'H'}] = append(m.TransactionsBytes[[2]byte{'I', 'H'}], common.GetByteInt64(indices[i]))
		m.TransactionsBytes[[2]byte{'H', 'V'}] = append(m.TransactionsBytes[[2]byte{'H', 'V'}], bls[i].GetBytes())
	}
	return m.GetBytes()
}

// withChainAt30 prepares a 30-block chain at height 30 and restores the
// globals the sync handler mutates.
func withChainAt30(t *testing.T) []blocks.Block {
	t.Helper()
	withTempDB(t)
	blocks.InitStateDB()
	chain := storeTestChain(t, 30)
	savedH, savedMax, savedShift := common.GetHeight(), common.GetHeightMax(), common.ShiftToPastInReset
	t.Cleanup(func() {
		common.SetHeight(savedH)
		common.SetHeightMax(savedMax)
		common.ShiftToPastInReset = savedShift
	})
	common.SetHeight(30)
	common.SetHeightMax(40)
	common.ShiftToPastInReset = 1
	return chain
}

func assertChainIntact(t *testing.T, top int64) {
	t.Helper()
	if h := common.GetHeight(); h != top {
		t.Fatalf("height changed: %d, want %d", h, top)
	}
	for _, h := range []int64{1, top} {
		if _, err := blocks.LoadBlock(h); err != nil {
			t.Fatalf("block %d was removed: %v", h, err)
		}
	}
}

// S2-01: a peer we never asked must not be able to rewind the chain.
func TestUnsolicitedShDoesNotRewind(t *testing.T) {
	withChainAt30(t)
	fake := unsignedTestBlock(t, 1, common.EmptyHash(), 1, 0)
	fake.BlockHash = common.GetHashFromBytes(bytes.Repeat([]byte{0xEE}, 32))
	next := unsignedTestBlock(t, 31, common.EmptyHash(), 1, 0)

	OnMessage([4]byte{203, 0, 113, 66}, shMessage([]int64{1, 31}, []blocks.Block{fake, next}))

	assertChainIntact(t, 30)
}

// signedForkBlock builds a block at height h on top of parent, produced and
// signed by a freshly registered operator key, i.e. a block an honest
// validator on a competing fork could have produced.
func signedForkBlock(t *testing.T, h int64, parent blocks.Block) blocks.Block {
	t.Helper()
	return signedForkBlockWithTxs(t, h, parent, nil)
}

func signedForkBlockWithTxs(t *testing.T, h int64, parent blocks.Block, txs []common.Hash) blocks.Block {
	t.Helper()
	var s oqs.Signature
	if err := s.Init(common.SigName(), nil); err != nil {
		t.Skipf("liboqs unavailable: %v", err)
	}
	pub, err := s.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	op, err := common.PubKeyToAddress(pub, true)
	if err != nil {
		t.Fatal(err)
	}
	var pk common.PubKey
	if err := pk.Init(pub, op); err != nil {
		t.Fatal(err)
	}
	pk.MainAddress = op
	if err := blocks.StorePubKey(pk); err != nil {
		t.Fatal(err)
	}
	if err := blocks.StorePubKeyInPatriciaTrie(pk); err != nil {
		t.Fatal(err)
	}
	bl := unsignedTestBlock(t, h, parent.BlockHash, parent.GetBlockSupply(), 0)
	bl.BaseBlock.BaseHeader.OperatorAccount = op
	bl.BaseBlock.BaseHeader.Difficulty = 7 // differs from the stored chain
	if len(txs) > 0 {
		bl.TransactionsHashes = txs
		bl.BaseBlock.BaseHeader.RootMerkleTree = merkleRootOf(t, txs)
	}
	msg := bl.BaseBlock.BaseHeader.GetBytesWithoutSignature()
	digest, err := common.CalcHashToByte(msg)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.Sign(digest)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := common.GetSignatureFromBytes(append([]byte{0}, raw...), op)
	if err != nil {
		t.Fatal(err)
	}
	bl.BaseBlock.BaseHeader.Signature = sig
	bl.BaseBlock.BaseHeader.SignatureMessage = msg
	hash, err := bl.CalcBlockHash()
	if err != nil {
		t.Fatal(err)
	}
	bl.BlockHash = hash
	return bl
}

func withPubKeyTrie(t *testing.T) {
	t.Helper()
	saved := pubkeys.GlobalMerkleTree
	pubkeys.InitPermanentTrie()
	t.Cleanup(func() { pubkeys.GlobalMerkleTree = saved })
}

var requestedPeer = [4]byte{203, 0, 113, 77}

// S2-01: even a peer we asked must not rewind us with an unauthenticated
// "competing" block.
func TestRequestedShWithUnsignedForkDoesNotRewind(t *testing.T) {
	chain := withChainAt30(t)
	withPubKeyTrie(t)
	fake := unsignedTestBlock(t, 29, chain[28].BlockHash, 1, 0)
	fake.BaseBlock.BaseHeader.Difficulty = 9 // a different block at 29, links to our 28, unsigned
	fake.BlockHash, _ = fake.CalcBlockHash()
	recordHeaderRequest(requestedPeer, 20, 40)

	OnMessage(requestedPeer, shMessage([]int64{29, 31}, []blocks.Block{fake, unsignedTestBlock(t, 31, fake.BlockHash, 1, 0)}))

	assertChainIntact(t, 30)
}

// S2-01: a header whose height disagrees with its index is the peer's fault,
// never a reason to rewind.
func TestRequestedShHeightMismatchDoesNotRewind(t *testing.T) {
	chain := withChainAt30(t)
	withPubKeyTrie(t)
	bogus := unsignedTestBlock(t, 999, chain[30].BlockHash, 1, 0)
	recordHeaderRequest(requestedPeer, 30, 40)

	OnMessage(requestedPeer, shMessage([]int64{31}, []blocks.Block{bogus}))

	assertChainIntact(t, 30)
}

// S2-01: an invalid block on top of our own tip is the peer's fault too.
func TestRequestedShInvalidBlockOnOurTipDoesNotRewind(t *testing.T) {
	chain := withChainAt30(t)
	withPubKeyTrie(t)
	bad := unsignedTestBlock(t, 31, chain[30].BlockHash, 1, 0)
	recordHeaderRequest(requestedPeer, 30, 40)

	OnMessage(requestedPeer, shMessage([]int64{31}, []blocks.Block{bad}))

	assertChainIntact(t, 30)
}

// Fork resolution must keep working: a properly signed competing block that
// links to our parent rewinds us to the common ancestor.
func TestRequestedShWithSignedForkRewindsToAncestor(t *testing.T) {
	chain := withChainAt30(t)
	withPubKeyTrie(t)
	fork := signedForkBlock(t, 29, chain[28])
	recordHeaderRequest(requestedPeer, 20, 40)

	OnMessage(requestedPeer, shMessage([]int64{29, 31}, []blocks.Block{fork, unsignedTestBlock(t, 31, fork.BlockHash, 1, 0)}))

	if h := common.GetHeight(); h > 28 || h < 20 {
		t.Fatalf("height after a verified fork at 29 = %d, want the ancestor 28 (or the nearest snapshot below)", h)
	}
}

// A competing block that does not link to our parent says the fork is deeper:
// ask for earlier headers instead of rewinding blind.
func TestRequestedShWithDeeperForkAsksForEarlierHeaders(t *testing.T) {
	chain := withChainAt30(t)
	withPubKeyTrie(t)
	other := signedForkBlock(t, 29, unsignedTestBlock(t, 28, chain[27].BlockHash, 1, 0)) // parent is NOT our 28
	recordHeaderRequest(requestedPeer, 20, 40)
	lastHeaderRequestMutex.Lock()
	delete(lastHeaderRequest, requestedPeer)
	lastHeaderRequestMutex.Unlock()
	out := withSyncSendChannel(t)

	OnMessage(requestedPeer, shMessage([]int64{29, 31}, []blocks.Block{other, unsignedTestBlock(t, 31, other.BlockHash, 1, 0)}))

	assertChainIntact(t, 30)
	select {
	case sent := <-out:
		ok, amsg := message.CheckValidMessage(sent[4:])
		if !ok || string(amsg.GetHead()) != "gh" {
			t.Fatalf("expected a gh request, got %q", sent)
		}
		from := common.GetInt64FromByte(amsg.GetTransactionsBytes()[[2]byte{'B', 'H'}][0])
		if from >= 29 {
			t.Fatalf("header request starts at %d, want below the fork candidate 29", from)
		}
	default:
		t.Fatal("no header request was sent")
	}
}

// withSyncSendChannel installs a buffered sync send channel and returns it, so
// a test can see what the handler sends.
func withSyncSendChannel(t *testing.T) chan []byte {
	t.Helper()
	services.SendMutexSync.Lock()
	saved := services.SendChanSync
	ch := make(chan []byte, 16)
	services.SendChanSync = ch
	services.SendMutexSync.Unlock()
	t.Cleanup(func() {
		services.SendMutexSync.Lock()
		services.SendChanSync = saved
		services.SendMutexSync.Unlock()
	})
	return ch
}

func bogusHashes(n int, tag byte) []common.Hash {
	out := make([]common.Hash, 0, n)
	for i := 0; i < n; i++ {
		var raw [32]byte
		raw[0], raw[1], raw[2], raw[3] = tag, byte(i>>16), byte(i>>8), byte(i)
		out = append(out, common.GetHashFromBytes(raw[:]))
	}
	return out
}

func merkleRootOf(t *testing.T, hs []common.Hash) common.Hash {
	t.Helper()
	data := make([][]byte, 0, len(hs))
	for _, h := range hs {
		data = append(data, h.GetBytes())
	}
	nodes, err := transactionsPool.NewMerkleTree(data)
	if err != nil || len(nodes) == 0 {
		t.Fatalf("merkle: %v", err)
	}
	return common.GetHashFromBytes(nodes[0].Data)
}

// S2-05: headers that are not authentic must not fill the missing-transaction
// bookkeeping (nor trigger bt requests to peers).
func TestUnverifiedHeaderDoesNotFeedMissingTx(t *testing.T) {
	chain := withChainAt30(t)
	withPubKeyTrie(t)
	withFreshMissingTx(t)
	b := unsignedTestBlock(t, 31, chain[30].BlockHash, 1, 0)
	b.TransactionsHashes = bogusHashes(5000, 0xFA)
	recordHeaderRequest(requestedPeer, 30, 40)

	OnMessage(requestedPeer, shMessage([]int64{31}, []blocks.Block{b}))

	if n := outstandingMissingTxCount(); n != 0 {
		t.Fatalf("an unsigned header put %d hashes into the missing-tx bookkeeping", n)
	}
}

// A signed header whose transaction list does not match its merkle root is
// not authentic either: the signature covers the root, not the list.
func TestSignedHeaderWithSwappedTxListDoesNotFeedMissingTx(t *testing.T) {
	chain := withChainAt30(t)
	withPubKeyTrie(t)
	withFreshMissingTx(t)
	b := signedForkBlockWithTxs(t, 31, chain[30], bogusHashes(3, 0xF1))
	b.TransactionsHashes = bogusHashes(5000, 0xF2) // swapped after signing
	recordHeaderRequest(requestedPeer, 30, 40)

	OnMessage(requestedPeer, shMessage([]int64{31}, []blocks.Block{b}))

	if n := outstandingMissingTxCount(); n != 0 {
		t.Fatalf("a header with a swapped transaction list put %d hashes into the bookkeeping", n)
	}
}

// Authentic headers keep working: their missing transactions are requested.
func TestAuthenticHeaderFeedsMissingTx(t *testing.T) {
	chain := withChainAt30(t)
	withPubKeyTrie(t)
	withFreshMissingTx(t)
	b := signedForkBlockWithTxs(t, 31, chain[30], bogusHashes(3, 0xF3))
	recordHeaderRequest(requestedPeer, 30, 40)

	OnMessage(requestedPeer, shMessage([]int64{31}, []blocks.Block{b}))

	if n := outstandingMissingTxCount(); n != 3 {
		t.Fatalf("missing-tx bookkeeping holds %d hashes, want the block's 3", n)
	}
}

// Audit 2026-10-07 F3-03: the answer to a fork request lies at or below our
// height. It used to be dropped as "shorter other chain" before the fork point
// was looked for, so no fork was ever resolved. As the answer to a fork
// request it must reach the fork point; the same batch answering a routine
// request is still a shorter chain and changes nothing.
func TestForkAnswerBelowTipRewindsToAncestor(t *testing.T) {
	chain := withChainAt30(t)
	withPubKeyTrie(t)
	fork := signedForkBlock(t, 29, chain[28])
	clearHeaderRequests(requestedPeer)
	recordForkHeaderRequest(requestedPeer, 27, 30)

	OnMessage(requestedPeer, shMessage([]int64{27, 28, 29}, []blocks.Block{chain[27], chain[28], fork}))

	if h := common.GetHeight(); h > 28 || h < 20 {
		t.Fatalf("height after a fork answer with a verified fork at 29 = %d, want the ancestor 28 (or the nearest snapshot below)", h)
	}
}

func TestRoutineAnswerBelowTipIsAShorterChain(t *testing.T) {
	chain := withChainAt30(t)
	withPubKeyTrie(t)
	fork := signedForkBlock(t, 29, chain[28])
	clearHeaderRequests(requestedPeer)
	recordHeaderRequest(requestedPeer, 27, 30)

	OnMessage(requestedPeer, shMessage([]int64{27, 28, 29}, []blocks.Block{chain[27], chain[28], fork}))

	assertChainIntact(t, 30)
}

// clearHeaderRequests drops what earlier tests left outstanding for addr, so
// a test sees only the requests it records itself.
func clearHeaderRequests(addr [4]byte) {
	pendingHeaderRequestsMutex.Lock()
	delete(pendingHeaderRequests, addr)
	pendingHeaderRequestsMutex.Unlock()
}
