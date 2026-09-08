package qtwidgets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
	"github.com/qwid-org/qwid-node/wallet"
	"os"
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
		if MainWallet == nil || (!MainWallet.Check() || !MainWallet.Check2()) {
			logger.GetLogger().Println("wallet not loaded yet")
			return line
		}
		if common.IsPaused() == false {
			// primary encryption used
			line = common.BytesToLenAndBytes(line)
			sign, err := MainWallet.Sign(line, true)
			if err != nil {
				logger.GetLogger().Println(err)
				return line
			}
			line = append(line, sign.GetBytes()...)

		} else {
			// secondary encryption
			line = common.BytesToLenAndBytes(line)
			sign, err := MainWallet.Sign(line, false)
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

func StoreWalletNewGenerated(w *wallet.Wallet) error {
	if err != nil {
		logger.GetLogger().Printf("Can not create wallet. Error %v", err)
	}
	folderPath := w.HomePath
	err = os.MkdirAll(w.HomePath, 0700) // CW-H3: owner-only; matches StoreJSON's 0700 (MkdirAll won't chmod an existing dir)
	if err != nil {
		logger.GetLogger().Fatal(err)
	}
	fileInfo, err := os.Stat(folderPath)
	if err != nil {
		return fmt.Errorf("Error getting folder info: %v", err)
	}
	// Get the folder permissions
	permissions := fileInfo.Mode().Perm()
	fmt.Printf("Folder permissions: %v\n", permissions)
	// Check if the current user has read, write, and execute permissions
	hasReadPermission := permissions&0400 != 0
	hasWritePermission := permissions&0200 != 0
	hasExecutePermission := permissions&0100 != 0
	fmt.Printf("Read permission: %v\n", hasReadPermission)
	fmt.Printf("Write permission: %v\n", hasWritePermission)
	fmt.Printf("Execute permission: %v\n", hasExecutePermission)

	err = w.StoreJSON()
	if err != nil {
		return err
	}
	return nil
}

func SetCurrentEncryptions() (string, string, error) {
	clientrpc.InRPC <- SignMessage([]byte("ENCR"))
	var reply []byte
	reply = <-clientrpc.OutRPC
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

// registrationSignPrimaryGUI picks which key must SIGN a key-carrying
// registration transaction: the enclosed key itself when nothing is registered
// (bootstrap), a REGISTERED key otherwise (wallet.RegistrationSigningPrimary;
// incident 2026-09-08). Falls back to defaultPrimary when the node cannot
// answer the PUBA query.
func registrationSignPrimaryGUI(registerPrimary, defaultPrimary bool) bool {
	clientrpc.InRPC <- SignMessage(append([]byte("PUBA"), MainWallet.MainAddress.GetBytes()...))
	reply := <-clientrpc.OutRPC
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
