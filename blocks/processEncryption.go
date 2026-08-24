package blocks

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/voting"
	"sync"
)

var VoteChannel chan []byte
var VoteChannelMutex sync.Mutex

func init() {
	VoteChannel = make(chan []byte, 0)
	VoteChannelMutex = sync.Mutex{}
}

// ProcessBlockEncryption : store encryption
//
// The primary and secondary halves are independent and BOTH are always
// attempted: the errors are collected and returned together rather than the
// first one short-circuiting the function. This matters now that a wallet
// without a recovery phrase refuses to adopt a new scheme
// (AddNewEncryptionToActiveWallet). A scheme change the node cannot follow with
// its own key is a wallet problem; it must not stop the node from applying the
// chain's *other* scheme change in the same block, because the encryption change
// is only detected once — by comparing this block's header against the previous
// one — so a skipped SetVoteEncryption is never retried, and the node would keep
// verifying with the wrong scheme configuration forever.
func ProcessBlockEncryption(block Block, lastBlock Block) error {
	if lastBlock.GetHeader().Height < 3 {
		return nil
	}
	var errs []error
	if !bytes.Equal(block.BaseBlock.BaseHeader.Encryption1[:], lastBlock.BaseBlock.BaseHeader.Encryption1[:]) {
		enc1, err := FromBytesToEncryptionConfig(block.BaseBlock.BaseHeader.Encryption1[:], true)
		if err != nil {
			errs = append(errs, err)
		} else {
			logger.GetLogger().Println("new encryption: ", enc1.ToString())
			SetVoteEncryption(block.BaseBlock.BaseHeader.Encryption1[:], true)
			voting.ResetLastVoting()
			if err := AddNewPubKeyToActiveWallet(enc1.SigName, true, block.GetHeader().Height); err != nil {
				errs = append(errs, err)
			}
		}
	}

	if !bytes.Equal(block.BaseBlock.BaseHeader.Encryption2[:], lastBlock.BaseBlock.BaseHeader.Encryption2[:]) {
		enc2, err := FromBytesToEncryptionConfig(block.BaseBlock.BaseHeader.Encryption2[:], false)
		if err != nil {
			errs = append(errs, err)
		} else {
			SetVoteEncryption(block.BaseBlock.BaseHeader.Encryption2[:], false)
			voting.ResetLastVoting()
			if err := AddNewPubKeyToActiveWallet(enc2.SigName, false, block.GetHeader().Height); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func SetVoteEncryption(enc []byte, primary bool) {
	enc1 := append([]byte{1}, enc...)
	if primary {
		enc1 = append([]byte{0}, enc...)
	}
	VoteChannelMutex.Lock()
	defer VoteChannelMutex.Unlock()
	VoteChannel <- enc1
	logger.GetLogger().Println(string(<-VoteChannel))
}

func (bl *Block) GetSigNames() (string, string, bool, bool, error) {
	enc1, err := FromBytesToEncryptionConfig(bl.BaseBlock.BaseHeader.Encryption1[:], true)
	if err != nil {
		return "", "", false, false, err
	}
	enc2, err := FromBytesToEncryptionConfig(bl.BaseBlock.BaseHeader.Encryption2[:], false)
	if err != nil {
		return "", "", false, false, err
	}
	// The spare's liveness is DERIVED from the primary's, exactly as
	// common.IsPaused2 derives it from common.IsPaused: exactly one scheme is
	// usable at any moment, and never zero.
	//
	// The flag stored in the Encryption2 slot is not consulted. Headers written
	// before that invariant existed carry combinations it forbids — [paused,
	// paused] above all, which says nothing may sign and would stall the chain
	// at the first block following it. The slot records WHICH algorithm the
	// spare is; whether it is live follows from the primary.
	return enc1.SigName, enc2.SigName, enc1.IsPaused, !enc1.IsPaused, nil
}

func SetEncryptionFromBlock(height int64) error {
	block, err := LoadBlock(height)
	if err != nil {
		return err
	}
	enc1, err := FromBytesToEncryptionConfig(block.BaseBlock.BaseHeader.Encryption1[:], true)
	if err != nil {
		return err
	}

	common.SetEncryption(enc1.SigName, enc1.PubKeyLength, enc1.PrivateKeyLength, enc1.SignatureLength, enc1.IsPaused, true)

	enc2, err := FromBytesToEncryptionConfig(block.BaseBlock.BaseHeader.Encryption2[:], false)
	if err != nil {
		return err
	}

	common.SetEncryption(enc2.SigName, enc2.PubKeyLength, enc2.PrivateKeyLength, enc2.SignatureLength, enc2.IsPaused, false)
	return nil
}

func SetEncryptionFromBytes(enc []byte, primary bool) error {

	enc1, err := FromBytesToEncryptionConfig(enc, primary)
	if err != nil {
		return err
	}
	logger.GetLogger().Println("set encryption changing. Default paused then true")
	isPause := enc1.IsPaused
	if primary && enc1.SigName != common.SigName() {
		isPause = true
	} else if !primary && enc1.SigName != common.SigName2() {
		isPause = true
	}
	if isPause != enc1.IsPaused {
		return fmt.Errorf("not proper pause set. should be %v", isPause)
	}
	common.SetEncryption(enc1.SigName, enc1.PubKeyLength, enc1.PrivateKeyLength, enc1.SignatureLength, isPause, primary)
	return nil
}
