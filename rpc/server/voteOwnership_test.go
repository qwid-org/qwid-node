package serverrpc

import (
	"strings"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	nonceServices "github.com/qwid-org/qwid-node/services/nonceService"
	"github.com/qwid-org/qwid-node/wallet"
)

// VOTE is the mirror image of the other three operations. There, the node
// answered about ITSELF when the caller meant their own account. Here the node
// ACTS as itself for whoever asked: the vote it casts is the vote of its
// delegated account, weighted by that account's stake, and it rides in the
// nonce transaction the mining wallet signs. There is one per node.
//
// Once any locally-generated wallet could sign a request that names no account,
// any of them could overwrite the node's vote. So VOTE names the account it
// votes for, and the node casts it only for the wallet it actually mines with.
//
// MINE is the same shape — it starts the node's mining services and names no
// account — so it is pinned to the node's own wallet too.

func withActiveWallet(t *testing.T, addr common.Address) {
	t.Helper()
	saved := wallet.GetActiveWallet()
	wallet.SetActiveWallet(&wallet.Wallet{MainAddress: addr})
	t.Cleanup(func() { wallet.SetActiveWallet(saved) })
}

// votePayload is what a wallet sends: its address, then the two length-prefixed
// encryption blobs. Empty blobs are a pause vote, which needs no key material.
func votePayload(voter common.Address) []byte {
	out := append([]byte{}, voter.GetBytes()...)
	out = append(out, common.BytesToLenAndBytes([]byte{})...)
	out = append(out, common.BytesToLenAndBytes([]byte{})...)
	return out
}

func TestVotePayloadNamesTheVoter(t *testing.T) {
	addr, named := requestAccountAddress("VOTE", votePayload(addressEndingIn(41)))

	if !named {
		t.Fatal("a vote carrying an address was treated as anonymous")
	}
	if addr.ByteValue[common.AddressLength-1] != 41 {
		t.Fatalf("read the wrong voter: %x", addr.ByteValue)
	}
}

// A payload too short to hold an address must not be padded into one.
func TestShortVotePayloadNamesNobody(t *testing.T) {
	for _, payload := range [][]byte{nil, {}, make([]byte, common.AddressLength-1)} {
		if _, named := requestAccountAddress("VOTE", payload); named {
			t.Errorf("a %d-byte vote payload was read as an address", len(payload))
		}
	}
}

func TestNodeCastsTheVoteOfItsMiningWallet(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	miner := addressEndingIn(41)
	withActiveWallet(t, miner)

	reply := []byte{}
	handleVOTE(votePayload(miner), &reply)

	if !strings.Contains(string(reply), "successful") {
		t.Fatalf("the node refused its own operator's vote: %q", reply)
	}
}

// The node has one vote and it belongs to the account it stakes with. Another
// wallet on the same machine must not be able to spend it.
func TestVoteFromAnotherWalletIsRefused(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withActiveWallet(t, addressEndingIn(41))

	nonceServices.ResetToDefaultEncryptionOptData()
	before := append([]byte{}, nonceServices.EncryptionOptData...)

	reply := []byte{}
	handleVOTE(votePayload(addressEndingIn(42)), &reply)

	// The reason matters: before the ownership check existed this same payload
	// was refused only because the extra address made the blobs unparseable,
	// which would stop being true the moment the wire format changed.
	if !strings.Contains(string(reply), "only the wallet this node mines with") {
		t.Fatalf("another wallet's vote was not refused as a wrong owner: %q", reply)
	}
	if string(nonceServices.EncryptionOptData) != string(before) {
		t.Error("a refused vote still changed what the node broadcasts")
	}
}

// Fail closed: a payload that does not name a voter is refused rather than
// falling back to "whoever the node is". Anything else leaves the vote castable
// by any wallet that can reach the RPC socket.
func TestVoteWithoutAVoterIsRefused(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withActiveWallet(t, addressEndingIn(41))

	blobs := append(common.BytesToLenAndBytes([]byte{}), common.BytesToLenAndBytes([]byte{})...)

	reply := []byte{}
	handleVOTE(blobs, &reply)

	if strings.Contains(string(reply), "successful") {
		t.Fatalf("an unattributed vote was cast: %q", reply)
	}
}

// A vote that names the node's own wallet must still be checked against a key,
// not waved through: the address alone is a claim, and the signature is what
// backs it. MINE names no account at all, so it can only ever be the node's.
func TestNodeLevelOperationsRefuseOtherLocalWallets(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withStubbedLocalWallets(t, []wallet.WalletPublicKeys{
		{Number: 0, MainAddress: addressEndingIn(41), Primary: []byte{0x01}},
		{Number: 10, MainAddress: addressEndingIn(42), Primary: []byte{0x02}},
	})

	for _, k := range candidateVerificationKeys("MINE", nil, true) {
		if len(k) > 0 && k[0] == 0x02 {
			t.Fatal("a wallet other than the node's own could start mining")
		}
	}
}
