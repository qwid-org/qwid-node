package handlers

import (
	"bytes"
	"fmt"
	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
)

func SignMessage(line []byte) []byte {
	line = common.BytesToLenAndBytes(line)
	return line
}

// SyncEncryptionFromNode pulls the chain's current signature-scheme
// configuration from the node and applies it to this process.
//
// The explorer runs as its own process with its own copy of common's encryption
// config, and that copy starts at the build's compiled defaults. Nothing ever
// updated it, so after the chain voted in a different scheme the explorer went
// on decoding blocks and transactions with the wrong key and signature lengths
// and simply stopped working — and restarting it did not help, because it never
// asked the node in the first place.
//
// ENCR needs no wallet, which is why the explorer can call it at all.
func SyncEncryptionFromNode() error {
	reply := clientrpc.Call(SignMessage([]byte("ENCR")))
	if bytes.Equal(reply, []byte("Timeout")) {
		return fmt.Errorf("timeout asking the node for the encryption config")
	}
	enc1b, left, err := common.BytesWithLenToBytes(reply)
	if err != nil {
		return fmt.Errorf("cannot read primary encryption config: %w", err)
	}
	enc2b, _, err := common.BytesWithLenToBytes(left)
	if err != nil {
		return fmt.Errorf("cannot read secondary encryption config: %w", err)
	}
	enc1, err := blocks.FromBytesToEncryptionConfig(enc1b, true)
	if err != nil {
		return fmt.Errorf("cannot decode primary encryption config: %w", err)
	}
	enc2, err := blocks.FromBytesToEncryptionConfig(enc2b, false)
	if err != nil {
		return fmt.Errorf("cannot decode secondary encryption config: %w", err)
	}
	if enc1.SigName == common.SigName() && enc2.SigName == common.SigName2() {
		return nil
	}
	logger.GetLogger().Printf("encryption config changed: primary %s -> %s, secondary %s -> %s",
		common.SigName(), enc1.SigName, common.SigName2(), enc2.SigName)
	common.SetEncryption(enc1.SigName, enc1.PubKeyLength, enc1.PrivateKeyLength, enc1.SignatureLength, enc1.IsPaused, true)
	common.SetEncryption(enc2.SigName, enc2.PubKeyLength, enc2.PrivateKeyLength, enc2.SignatureLength, enc2.IsPaused, false)
	return nil
}
