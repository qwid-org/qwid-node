package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
	"github.com/qwid-org/qwid-node/wallet"
)

func SignMessage(line []byte) []byte {

	operation := string(line[0:4])
	verificationNeeded := true
	for _, noVerification := range common.ConnectionsWithoutVerification {
		if bytes.Equal([]byte(operation), noVerification) {
			verificationNeeded = false
			break
		}
	}
	if verificationNeeded {
		if NodeWallet == nil || (!NodeWallet.Check() || !NodeWallet.Check2()) {
			logger.GetLogger().Println("wallet not loaded yet")
			return line
		}
		if common.IsPaused() == false {
			// primary encryption used
			line = common.BytesToLenAndBytes(line)
			sign, err := NodeWallet.Sign(line, true)
			if err != nil {
				logger.GetLogger().Println(err)
				return line
			}
			line = append(line, sign.GetBytes()...)

		} else {
			// secondary encryption
			line = common.BytesToLenAndBytes(line)
			sign, err := NodeWallet.Sign(line, false)
			if err != nil {
				logger.GetLogger().Println(err)
				return line
			}
			line = append(line, sign.GetBytes()...)
		}
	} else {
		line = common.BytesToLenAndBytes(line)
	}
	return line
}

func SetCurrentEncryptions() (string, string, error) {
	reply := clientrpc.Call(SignMessage([]byte("ENCR")))
	if bytes.Equal(reply, []byte("Timeout")) {
		return "", "", fmt.Errorf("timout")
	}
	enc1b, left, err := common.BytesWithLenToBytes(reply)
	if err != nil {
		return "", "", err
	}
	enc2b, left, err := common.BytesWithLenToBytes(left)
	if err != nil {
		return "", "", err
	}
	enc1, err := blocks.FromBytesToEncryptionConfig(enc1b, true)
	if err != nil {
		return "", "", err
	}
	common.SetEncryption(enc1.SigName, enc1.PubKeyLength, enc1.PrivateKeyLength, enc1.SignatureLength, enc1.IsPaused, true)
	enc2, err := blocks.FromBytesToEncryptionConfig(enc2b, false)
	if err != nil {
		return "", "", err
	}
	common.SetEncryption(enc2.SigName, enc2.PubKeyLength, enc2.PrivateKeyLength, enc2.SignatureLength, enc2.IsPaused, false)
	return enc1.SigName, enc2.SigName, nil
}

// TestAndSetEncryption sends HELO to the node, which returns "Hi" signed
// with the non-paused encryption. We verify the signature to determine
// which encryption to use.
func TestAndSetEncryption() {

	reply := clientrpc.Call(SignMessage([]byte("HELO")))
	if len(reply) < 3 || string(reply[:2]) != "Hi" {
		logger.GetLogger().Println("HELO test: invalid response")
		return
	}
	usePrimary := reply[2] == 0

	if usePrimary {
		common.SetEncryption(common.SigName(), common.PubKeyLength(false), common.PrivateKeyLength(), common.SignatureLength(false), false, true)
		logger.GetLogger().Println("Encryption test: primary verified")
	} else {
		common.SetEncryption(common.SigName(), common.PubKeyLength(false), common.PrivateKeyLength(), common.SignatureLength(false), true, true)
		logger.GetLogger().Println("Encryption test: secondary verified (primary paused)")
	}

}

// registrationSignPrimaryFor picks which key must SIGN a key-carrying
// registration transaction for the given identity: the enclosed key itself when
// nothing is registered (bootstrap), a REGISTERED key otherwise
// (wallet.RegistrationSigningPrimary; incident 2026-09-08). Falls back to
// defaultPrimary when the node cannot answer the PUBA query.
func registrationSignPrimaryFor(mainAddress common.Address, registerPrimary, defaultPrimary bool) bool {
	reply := clientrpc.Call(SignMessage(append([]byte("PUBA"), mainAddress.GetBytes()...)))
	if bytes.Equal(reply, []byte("Timeout")) {
		logger.GetLogger().Println("could not ask the node which keys are registered; signing registration with the default key")
		return defaultPrimary
	}
	var resp struct {
		HasPrimary   bool `json:"hasPrimary"`
		HasSecondary bool `json:"hasSecondary"`
	}
	if err := json.Unmarshal(reply, &resp); err != nil {
		logger.GetLogger().Println("could not read the registered-key reply; signing registration with the default key:", err)
		return defaultPrimary
	}
	chosen := wallet.RegistrationSigningPrimary(resp.HasPrimary, resp.HasSecondary, registerPrimary, defaultPrimary)
	if chosen != defaultPrimary {
		logger.GetLogger().Printf("registration transaction will be signed with the %s key (registered: primary=%v secondary=%v)",
			map[bool]string{true: "primary", false: "secondary"}[chosen], resp.HasPrimary, resp.HasSecondary)
	}
	return chosen
}
