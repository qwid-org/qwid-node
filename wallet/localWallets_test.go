package wallet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// The node verifies signed RPC requests. Until now it only knew its own active
// wallet, so a webui unlocked with any other locally-generated wallet failed
// every signed operation. The operator's other wallets are equally theirs, so
// the node needs their public keys — and only the public halves, which sit in
// the wallet file unencrypted next to the encrypted secret key. No password is
// involved, and none must be: the node has no business holding one.

// writeWalletFile lays out a wallet the way SaveJSON does:
// <dir>/<number>/wallet<number>.json
func writeWalletFile(t *testing.T, dir string, number int, primaryKey, secondaryKey string) {
	t.Helper()
	writeWalletFileWithAddress(t, dir, number, primaryKey, secondaryKey,
		"0x0000000000000000000000000000000000000000")
}

func writeWalletFileWithAddress(t *testing.T, dir string, number int, primaryKey, secondaryKey, mainAddress string) {
	t.Helper()
	sub := filepath.Join(dir, itoa(number))
	if err := os.MkdirAll(sub, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	doc := map[string]any{
		"wallet_number": number,
		"main_address":  mainAddress,
		"account_1": map[string]any{
			"public_key": map[string]any{"byte_value": primaryKey},
		},
		"account_2": map[string]any{
			"public_key": map[string]any{"byte_value": secondaryKey},
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(sub, "wallet"+itoa(number)+".json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

func TestLocalWalletKeysFindsEveryWallet(t *testing.T) {
	dir := t.TempDir()
	writeWalletFile(t, dir, 0, "AAAA", "BBBB")
	writeWalletFile(t, dir, 10, "CCCC", "DDDD")
	writeWalletFile(t, dir, 255, "EEEE", "FFFF")

	keys, err := LocalWalletPublicKeysFromDir(dir)
	if err != nil {
		t.Fatalf("LocalWalletPublicKeysFromDir: %v", err)
	}

	if len(keys) != 3 {
		t.Fatalf("found %d wallets, want 3", len(keys))
	}
	seen := map[uint8]bool{}
	for _, k := range keys {
		seen[k.Number] = true
		if len(k.Primary) == 0 || len(k.Secondary) == 0 {
			t.Errorf("wallet %d has an empty key pair", k.Number)
		}
	}
	for _, n := range []uint8{0, 10, 255} {
		if !seen[n] {
			t.Errorf("wallet %d was not found", n)
		}
	}
}

// The node must be able to tell WHICH local wallet a claimed address belongs
// to, not merely that some local wallet exists. Without the address, a request
// naming an account that has not yet registered a key on-chain could be signed
// by any wallet on the machine, so one wallet could act as another.
func TestLocalWalletKeysCarryTheMainAddress(t *testing.T) {
	dir := t.TempDir()
	const addr = "0xf6cb7a122dcd5a865a41a5140cdbc3a22799efc7"
	writeWalletFileWithAddress(t, dir, 3, "AAAA", "BBBB", addr)

	keys, err := LocalWalletPublicKeysFromDir(dir)
	if err != nil {
		t.Fatalf("LocalWalletPublicKeysFromDir: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("found %d wallets, want 1", len(keys))
	}

	want, err := hex.DecodeString(addr[2:])
	if err != nil {
		t.Fatalf("bad test address: %v", err)
	}
	if !bytes.Equal(keys[0].MainAddress.GetBytes(), want) {
		t.Fatalf("main address = %x, want %x", keys[0].MainAddress.GetBytes(), want)
	}
}

// A wallet file whose address is missing or malformed must still yield its
// public keys: the accountless path only needs the keys, and dropping the
// wallet entirely would lock its owner out of every signed operation.
func TestLocalWalletKeysSurviveAnUnusableAddress(t *testing.T) {
	dir := t.TempDir()
	writeWalletFileWithAddress(t, dir, 5, "AAAA", "BBBB", "not-an-address")

	keys, err := LocalWalletPublicKeysFromDir(dir)
	if err != nil {
		t.Fatalf("LocalWalletPublicKeysFromDir: %v", err)
	}
	if len(keys) != 1 || len(keys[0].Primary) == 0 {
		t.Fatalf("a malformed address dropped the wallet: %+v", keys)
	}
	empty := common.EmptyAddress()
	if !bytes.Equal(keys[0].MainAddress.GetBytes(), empty.GetBytes()) {
		t.Errorf("a malformed address was accepted as %x", keys[0].MainAddress.GetBytes())
	}
}

// A wallet directory that is unreadable or holds a corrupt file must not stop
// the node from starting; the others still have to be usable.
func TestLocalWalletKeysSkipsUnreadableEntries(t *testing.T) {
	dir := t.TempDir()
	writeWalletFile(t, dir, 1, "AAAA", "BBBB")

	broken := filepath.Join(dir, "7")
	if err := os.MkdirAll(broken, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(broken, "wallet7.json"), []byte("{not json"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// A directory that is not a wallet number at all.
	if err := os.MkdirAll(filepath.Join(dir, "notanumber"), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	keys, err := LocalWalletPublicKeysFromDir(dir)
	if err != nil {
		t.Fatalf("a corrupt wallet aborted the scan: %v", err)
	}
	if len(keys) != 1 || keys[0].Number != 1 {
		t.Fatalf("expected only wallet 1, got %+v", keys)
	}
}

func TestLocalWalletKeysOnEmptyDirectory(t *testing.T) {
	keys, err := LocalWalletPublicKeysFromDir(t.TempDir())
	if err != nil {
		t.Fatalf("empty directory returned an error: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("found %d wallets in an empty directory", len(keys))
	}
}

func TestLocalWalletKeysOnMissingDirectory(t *testing.T) {
	keys, err := LocalWalletPublicKeysFromDir(filepath.Join(t.TempDir(), "absent"))
	if err != nil {
		t.Fatalf("a missing wallet directory must not be an error: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("found %d wallets under a missing directory", len(keys))
	}
}
