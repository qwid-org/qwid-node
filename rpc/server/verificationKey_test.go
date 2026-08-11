package serverrpc

import (
	"errors"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/wallet"
)

// The RPC signature check verified every request against the NODE's wallet, so
// it proved "you own this node" rather than "you own this account". A wallet
// other than the mining one therefore failed every signed operation with
// "Invalid signature": it could send transactions (TRAN needs no signature) but
// could not read its own balance or history back.
//
// For a request that names an account, the right key is that account's, taken
// from the on-chain registration. That is also stricter than before — holding
// the node key no longer lets you sign a query about somebody else's account.
//
// Requests that name no account (PEND, WALL, MINE, ...) keep the node wallet:
// there is no other identity in them to verify against.

var errNoSuchKey = errors.New("no registered public key")

func withStubbedPubKeyLookup(t *testing.T, key []byte, err error) {
	t.Helper()
	saved := lookupRegisteredPubKey
	lookupRegisteredPubKey = func(common.Address, bool) (common.PubKey, error) {
		if err != nil {
			return common.PubKey{}, err
		}
		pk := common.PubKey{}
		_ = pk.Init(key, common.EmptyAddress())
		return pk, nil
	}
	t.Cleanup(func() { lookupRegisteredPubKey = saved })
}

func TestAccountQueryIsVerifiedAgainstTheAccountsOwnKey(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	registered := make([]byte, common.PubKeyLength(false))
	registered[0] = 0xAB
	withStubbedPubKeyLookup(t, registered, nil)

	got := candidateVerificationKeys("ACCT", addressBytesEndingIn(9), true)

	if len(got) != 1 || got[0][0] != 0xAB {
		t.Fatalf("an account query was verified with %v, want its own key", firstBytes(got))
	}
}

// A wallet that has never had a transaction processed has no key on-chain yet,
// so the registered key cannot authenticate it. The node then accepts the
// operator's own wallet holding EXACTLY that address — and nothing else. A
// blanket fallback here would let any wallet on the machine sign as an
// unregistered account, which matters now that cancelling names an address.
func TestUnregisteredAccountAcceptsOnlyTheWalletHoldingIt(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withStubbedPubKeyLookup(t, nil, errNoSuchKey)

	mine, other := addressEndingIn(10), addressEndingIn(11)
	withStubbedLocalWallets(t, []wallet.WalletPublicKeys{
		{Number: 0, MainAddress: mine, Primary: []byte{0x01}, Secondary: []byte{0x11}},
		{Number: 1, MainAddress: other, Primary: []byte{0x02}, Secondary: []byte{0x12}},
	})

	got := candidateVerificationKeys("ACCT", addressBytesEndingIn(10), true)

	if len(got) != 1 || got[0][0] != 0x01 {
		t.Fatalf("offered %d keys %v, want only the wallet holding the address", len(got), firstBytes(got))
	}
}

func TestUnregisteredAccountNobodyHoldsIsRefused(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withStubbedPubKeyLookup(t, nil, errNoSuchKey)
	withStubbedLocalWallets(t, []wallet.WalletPublicKeys{
		{Number: 0, MainAddress: addressEndingIn(10), Primary: []byte{0x01}},
	})

	got := candidateVerificationKeys("ACCT", addressBytesEndingIn(99), true)

	if len(got) != 0 {
		t.Fatalf("a stranger's unregistered account was offered %v", firstBytes(got))
	}
}

func TestOperationsWithoutAnAccountUseTheNodeWallet(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withStubbedPubKeyLookup(t, []byte{0xCD}, nil)
	withStubbedLocalWallets(t, []wallet.WalletPublicKeys{
		{Number: 0, MainAddress: addressEndingIn(1), Primary: []byte{0x01}},
	})

	// MINE and VOTE are deliberately absent: they change how the node behaves
	// rather than reporting on an account, so they are pinned to the node's own
	// wallet (see voteOwnership_test.go). These only read.
	for _, op := range []string{"WALL", "PEER", "PEND"} {
		got := candidateVerificationKeys(op, nil, true)
		if len(got) != 1 || got[0][0] != 0x01 {
			t.Errorf("%s names no account but was offered %v", op, firstBytes(got))
		}
	}
}

func addressEndingIn(b byte) common.Address {
	addr := common.EmptyAddress()
	addr.ByteValue[common.AddressLength-1] = b
	return addr
}

// addressBytesEndingIn is the wire form of addressEndingIn; GetBytes has a
// pointer receiver, so the address needs a home first.
func addressBytesEndingIn(b byte) []byte {
	addr := addressEndingIn(b)
	return addr.GetBytes()
}

func firstBytes(keys [][]byte) []byte {
	out := make([]byte, 0, len(keys))
	for _, k := range keys {
		if len(k) > 0 {
			out = append(out, k[0])
		}
	}
	return out
}

// A request that names no account carries no identity, so the node accepts a
// signature from ANY wallet the operator generated on this machine — not only
// the mining one. Their public halves sit unencrypted in the wallet files, so
// no password is needed to know them.
func withStubbedLocalWallets(t *testing.T, keys []wallet.WalletPublicKeys) {
	t.Helper()
	saved := loadLocalWalletKeys
	loadLocalWalletKeys = func() ([]wallet.WalletPublicKeys, error) { return keys, nil }
	invalidateLocalWalletKeyCache()
	t.Cleanup(func() {
		loadLocalWalletKeys = saved
		invalidateLocalWalletKeyCache()
	})
}

func TestAnyLocalWalletCanSignAnAccountlessRequest(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withStubbedLocalWallets(t, []wallet.WalletPublicKeys{
		{Number: 0, Primary: []byte{0x01}, Secondary: []byte{0x11}},
		{Number: 10, Primary: []byte{0x02}, Secondary: []byte{0x12}},
		{Number: 255, Primary: []byte{0x03}, Secondary: []byte{0x13}},
	})

	got := candidateVerificationKeys("PEND", nil, true)

	if len(got) < 3 {
		t.Fatalf("offered %d candidate keys, want one per local wallet", len(got))
	}
	found := map[byte]bool{}
	for _, k := range got {
		if len(k) > 0 {
			found[k[0]] = true
		}
	}
	for _, want := range []byte{0x01, 0x02, 0x03} {
		if !found[want] {
			t.Errorf("wallet key %#x was not offered", want)
		}
	}
}

// The scheme selector must pick the matching half, or a wallet signing with the
// second scheme would be checked against first-scheme keys and always rejected.
func TestAccountlessRequestUsesTheMatchingSchemeHalf(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withStubbedLocalWallets(t, []wallet.WalletPublicKeys{
		{Number: 4, Primary: []byte{0xA1}, Secondary: []byte{0xB1}},
	})

	for _, k := range candidateVerificationKeys("PEND", nil, false) {
		if len(k) > 0 && k[0] == 0xA1 {
			t.Fatal("a secondary-scheme request was offered a primary key")
		}
	}
	if got := candidateVerificationKeys("PEND", nil, false); len(got) == 0 {
		t.Fatal("no secondary keys were offered")
	}
}

// A named account is authenticated by that account alone. Falling back to every
// local wallet here would let the operator sign queries about other people's
// accounts, which is exactly what this change removed.
func TestNamedAccountDoesNotFallBackToLocalWallets(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	registered := make([]byte, common.PubKeyLength(false))
	registered[0] = 0x7F
	withStubbedPubKeyLookup(t, registered, nil)
	withStubbedLocalWallets(t, []wallet.WalletPublicKeys{
		{Number: 0, MainAddress: addressEndingIn(1), Primary: []byte{0x01}, Secondary: []byte{0x11}},
	})

	got := candidateVerificationKeys("ACCT", addressBytesEndingIn(12), true)

	if len(got) != 1 || got[0][0] != 0x7F {
		t.Fatalf("a named account was offered %d keys, want only its own", len(got))
	}
}

// A truncated payload must not be read as an address, and must not panic.
func TestShortAccountPayloadFallsBackSafely(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	registered := make([]byte, common.PubKeyLength(false))
	registered[0] = 0xEF
	withStubbedPubKeyLookup(t, registered, nil)
	withStubbedLocalWallets(t, []wallet.WalletPublicKeys{
		{Number: 0, MainAddress: addressEndingIn(1), Primary: []byte{0x01}},
	})

	for _, payload := range [][]byte{nil, {}, make([]byte, common.AddressLength-1)} {
		got := candidateVerificationKeys("ACCT", payload, true)
		for _, k := range got {
			if len(k) > 0 && k[0] == 0xEF {
				t.Errorf("a %d-byte payload was read as an address", len(payload))
			}
		}
	}
}

// The selector byte in the signature picks the scheme, and the key looked up
// must follow it — verifying a secondary signature against the primary key
// would reject every request from a wallet using the second scheme.
func TestSchemeSelectionIsPassedToTheLookup(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	var askedPrimary bool
	saved := lookupRegisteredPubKey
	lookupRegisteredPubKey = func(_ common.Address, primary bool) (common.PubKey, error) {
		askedPrimary = primary
		pk := common.PubKey{}
		_ = pk.Init(make([]byte, common.PubKeyLength(false)), common.EmptyAddress())
		return pk, nil
	}
	t.Cleanup(func() { lookupRegisteredPubKey = saved })

	addr := addressEndingIn(11)

	candidateVerificationKeys("ACCT", addr.GetBytes(), false)
	if askedPrimary {
		t.Error("a secondary-scheme request looked up the primary key")
	}
	candidateVerificationKeys("ACCT", addr.GetBytes(), true)
	if !askedPrimary {
		t.Error("a primary-scheme request looked up the secondary key")
	}
}
