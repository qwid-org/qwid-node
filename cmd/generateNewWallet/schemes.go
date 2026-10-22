package main

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
	"github.com/qwid-org/qwid-node/tcpip"
	"github.com/qwid-org/qwid-node/wallet"
)

// chainSchemes asks the node at ip which signature schemes are in force and
// installs them as this process's config. The generator used to derive keys
// for the built-in defaults whatever the chain ran: after the chain replaced a
// scheme, a new wallet's address came from a key the chain no longer verifies,
// and the account could never be opened.
func chainSchemes(ip string) (sigName, sigName2 string, primaryPaused bool, err error) {
	address := net.JoinHostPort(ip, strconv.Itoa(tcpip.Ports[tcpip.RPCTopic]))
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return "", "", false, fmt.Errorf("no node RPC at %s: %w", address, err)
	}
	conn.Close()
	go clientrpc.ConnectRPC(ip)
	reply := clientrpc.Call(common.BytesToLenAndBytes([]byte("ENCR")))
	if bytes.Equal(reply, []byte("Timeout")) {
		return "", "", false, fmt.Errorf("node at %s did not answer", address)
	}
	enc1b, left, err := common.BytesWithLenToBytes(reply)
	if err != nil {
		return "", "", false, err
	}
	enc2b, _, err := common.BytesWithLenToBytes(left)
	if err != nil {
		return "", "", false, err
	}
	enc1, err := blocks.FromBytesToEncryptionConfig(enc1b, true)
	if err != nil {
		return "", "", false, err
	}
	enc2, err := blocks.FromBytesToEncryptionConfig(enc2b, false)
	if err != nil {
		return "", "", false, err
	}
	common.SetEncryption(enc1.SigName, enc1.PubKeyLength, enc1.PrivateKeyLength, enc1.SignatureLength, enc1.IsPaused, true)
	common.SetEncryption(enc2.SigName, enc2.PubKeyLength, enc2.PrivateKeyLength, enc2.SignatureLength, enc2.IsPaused, false)
	return enc1.SigName, enc2.SigName, enc1.IsPaused, nil
}

// knownOnChain reports whether any key is registered under identity a.
func knownOnChain(a common.Address) bool {
	keys, err := wallet.ParsePUBA(clientrpc.Call(common.BytesToLenAndBytes(append([]byte("PUBA"), a.GetBytes()...))))
	return err == nil && (keys.AnyPrimary || keys.AnySecondary)
}

// identityCandidate is an address the phrase may own, with where it comes from.
type identityCandidate struct {
	addr  common.Address
	label string
}

func identityCandidates(in []identityCandidate) []identityCandidate {
	out := []identityCandidate{}
	for _, c := range in {
		dup := false
		for _, o := range out {
			if bytes.Equal(o.addr.GetBytes(), c.addr.GetBytes()) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, c)
		}
	}
	return out
}

// chooseRestoredIdentity picks the candidate the chain already knows. Which key
// an identity's address came from depends on the schemes when it was created
// (the defaults, a later primary, or the live spare during a pause), so a
// restore must find it rather than assume the first derived key.
func chooseRestoredIdentity(cands []identityCandidate, known func(common.Address) bool) (identityCandidate, bool) {
	for _, c := range cands {
		if known(c.addr) {
			return c, true
		}
	}
	return identityCandidate{}, false
}

// deriveAddress is the address of the key the phrase yields for one scheme
// and slot - a candidate identity.
func deriveAddress(w *wallet.Wallet, sigName string, primary bool) (common.Address, error) {
	acc, err := wallet.GenerateNewAccountFromSeed(*w, sigName, primary)
	if err != nil {
		return common.Address{}, err
	}
	return acc.Address, nil
}
