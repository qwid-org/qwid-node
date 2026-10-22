package transactionsDefinition

import (
	"bytes"
	"fmt"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/pubkeys"
	"github.com/qwid-org/qwid-node/wallet"
)

// IsCommitmentRegistration: a key registration whose Recipient is not the
// sender is a recovery commitment C = H160(S) (CLAUDE.md "Recovery
// commitment"). Reserved, delegated and zero addresses never are.
func (tx *Transaction) IsCommitmentRegistration() bool {
	r := tx.TxData.Recipient
	if len(tx.TxData.Pubkey.GetBytes()) == 0 || !tx.pureShape() {
		return false
	}
	if bytes.Equal(r.GetBytes(), tx.TxParam.Sender.GetBytes()) || common.IsRecoveryAddress(r) {
		return false
	}
	if bytes.Equal(r.GetBytes(), make([]byte, common.AddressLength)) {
		return false
	}
	_, err := account.IntDelegatedAccountFromAddress(r)
	return err != nil
}

func (tx *Transaction) IsRecoveryBind() bool {
	return bytes.Equal(tx.TxData.Recipient.GetBytes(), common.RecoveryBindAddress.GetBytes())
}

func (tx *Transaction) IsRecoveryReveal() bool {
	return bytes.Equal(tx.TxData.Recipient.GetBytes(), common.RecoveryRevealAddress.GetBytes())
}

func BuildRecoveryBindOptData(identity common.Address, tag, payload [32]byte) []byte {
	b := append([]byte{}, identity.GetBytes()...)
	b = append(b, tag[:]...)
	return append(b, payload[:]...)
}

func ParseRecoveryBind(opt []byte) (identity common.Address, tag, payload [32]byte, err error) {
	if len(opt) != common.RecoveryBindOptDataLength {
		return identity, tag, payload, fmt.Errorf("recovery bind data must be %d bytes, got %d", common.RecoveryBindOptDataLength, len(opt))
	}
	if err = identity.Init(opt[:common.AddressLength]); err != nil {
		return
	}
	copy(tag[:], opt[common.AddressLength:common.AddressLength+32])
	copy(payload[:], opt[common.AddressLength+32:])
	return
}

func BuildRecoveryRevealOptData(secret []byte, next common.Address) []byte {
	return append(append([]byte{}, secret...), next.GetBytes()...)
}

func ParseRecoveryReveal(opt []byte) (secret []byte, next common.Address, err error) {
	if len(opt) != common.RecoveryRevealOptDataLength {
		return nil, next, fmt.Errorf("recovery reveal data must be %d bytes, got %d", common.RecoveryRevealOptDataLength, len(opt))
	}
	secret = append([]byte{}, opt[:common.RecoverySecretLength]...)
	err = next.Init(opt[common.RecoverySecretLength:])
	return
}

func noPolicyFields(tx *Transaction) bool {
	d := tx.TxData
	return d.Amount == 0 && d.LockedAmount == 0 && d.EscrowTransactionsDelay == 0 &&
		d.MultiSignNumber == 0 && len(d.MultiSignAddresses) == 0 &&
		bytes.Equal(tx.TxParam.MultiSignTx.GetBytes(), make([]byte, common.HashLength))
}

// verifyRecoveryBindShape: a bind records (identity, tag, payload) and does
// nothing else. It is signed normally by whoever pays for it.
func (tx *Transaction) verifyRecoveryBindShape() error {
	if !noPolicyFields(tx) || len(tx.TxData.Pubkey.GetBytes()) != 0 {
		return fmt.Errorf("recovery bind must carry nothing but its data")
	}
	identity, _, _, err := ParseRecoveryBind(tx.TxData.OptData)
	if err != nil {
		return err
	}
	if bytes.Equal(identity.GetBytes(), make([]byte, common.AddressLength)) {
		return fmt.Errorf("recovery bind names no identity")
	}
	return nil
}

// recoveryHeight is the height a recovery transaction is judged at: the block
// being applied, or the next block for pool admission.
func recoveryHeight(asOf int64) int64 {
	if asOf == pubkeys.NoHeightLimit {
		return common.GetHeight() + 1
	}
	return asOf + 1
}

// verifyRecoveryReveal: phase 2. Authority comes from S opening the identity's
// commitment and from the bind that committed to this exact key before S was
// public - never from a signature scheme the identity held, all of which may
// be broken. The revealed key signs for itself, exempt from pause, for the
// same reason the self-registration of an unpublished key is.
func (tx *Transaction) verifyRecoveryReveal(hash []byte, sigName, sigName2 string, asOf int64) error {
	if !noPolicyFields(tx) {
		return fmt.Errorf("recovery reveal must not move coins or set account policy")
	}
	sender := tx.GetSenderAddress()
	secret, next, err := ParseRecoveryReveal(tx.TxData.OptData)
	if err != nil {
		return err
	}
	pk := tx.TxData.Pubkey
	pkb := pk.GetBytes()
	if len(pkb) == 0 || !keyNamesSender(pk.MainAddress, sender) {
		return fmt.Errorf("recovery reveal must enclose a key naming its sender")
	}
	if !common.IsValidPubKeyLength(len(pkb), pk.Primary) {
		return fmt.Errorf("revealed key length %d matches no active scheme", len(pkb))
	}
	pkAddr, err := common.PubKeyToAddress(pkb, pk.Primary)
	if err != nil {
		return err
	}
	if !bytes.Equal(pk.Address.GetBytes(), pkAddr.GetBytes()) {
		return fmt.Errorf("revealed key's address does not derive from it")
	}
	if _, err := pubkeys.LoadPubKeyAsOf(pkAddr.GetBytes(), asOf); err == nil {
		return fmt.Errorf("revealed key is already registered")
	}
	height := recoveryHeight(asOf)
	acc, ok := account.GetAccountByAddressBytes(sender.GetBytes())
	if !ok {
		return fmt.Errorf("no account for %s", sender.GetHex())
	}
	want := acc.EffectiveRecoveryCommit(height)
	if want == ([common.AddressLength]byte{}) {
		return fmt.Errorf("%s has no effective recovery commitment", sender.GetHex())
	}
	c, err := common.RecoveryCommitment(secret)
	if err != nil {
		return err
	}
	if c.ByteValue != want {
		return fmt.Errorf("secret does not open the recovery commitment")
	}
	tag, err := common.RecoveryTag(secret)
	if err != nil {
		return err
	}
	bind, ok := account.GetRecoveryBind(common.RecoveryBindKey(sender, tag))
	if !ok || bind.Identity != sender.ByteValue {
		return fmt.Errorf("no recovery bind for this secret")
	}
	if height < bind.Height+common.RecoveryBindDelayBlocks {
		return fmt.Errorf("recovery bind from height %d matures at %d", bind.Height, bind.Height+common.RecoveryBindDelayBlocks)
	}
	if height > bind.Height+common.RecoveryBindExpiryBlocks {
		return fmt.Errorf("recovery bind from height %d expired", bind.Height)
	}
	payload, err := common.RecoveryPayload(sender, pkAddr, next, secret)
	if err != nil {
		return err
	}
	if payload != bind.Payload {
		return fmt.Errorf("reveal does not match the first bind of this secret")
	}
	sig := tx.GetSignature().GetBytes()
	if len(sig) < 1 || (sig[0] == 0) != pk.Primary {
		return fmt.Errorf("recovery reveal must be signed by the revealed key")
	}
	if !wallet.Verify(hash, sig, pkb, sigName, sigName2, false, false) {
		return fmt.Errorf("recovery reveal signature does not verify against the revealed key")
	}
	return nil
}
