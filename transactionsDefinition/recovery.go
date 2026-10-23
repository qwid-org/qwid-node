package transactionsDefinition

import (
	"bytes"
	"fmt"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"github.com/qwid-org/qwid-node/pubkeys"
	"github.com/qwid-org/qwid-node/wallet"
)

// IsCommitmentRegistration: a key registration whose Recipient is not the
// sender sets the identity's commitments (CLAUDE.md "Recovery commitment"):
// Recipient is the ADDRESS of the spare key - its public key stays unpublished
// until needed - and OptData, when present, is the recovery commitment
// C = H160(S). Reserved, delegated and zero recipients never are.
func (tx *Transaction) IsCommitmentRegistration() bool {
	r := tx.TxData.Recipient
	if len(tx.TxData.Pubkey.GetBytes()) == 0 || !noPolicyFields(tx) {
		return false
	}
	if n := len(tx.TxData.OptData); n != 0 && n != common.AddressLength {
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

// CommitmentValues are what a commitment registration commits to: the spare
// key's address, and the recovery commitment (zero when absent, meaning
// "leave it as it is").
func (tx *Transaction) CommitmentValues() (spare, recovery [common.AddressLength]byte) {
	spare = tx.TxData.Recipient.ByteValue
	if len(tx.TxData.OptData) == common.AddressLength {
		copy(recovery[:], tx.TxData.OptData)
	}
	return spare, recovery
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

	// The two modes differ only in what opens the bind: the secret behind the
	// recovery commitment, or the key behind the address itself.
	var secret []byte
	var payload [32]byte
	if tx.IsAddressReveal() {
		r, err := ParseAddressReveal(tx.TxData.OptData)
		if err != nil {
			return err
		}
		if err := verifyAddressOpening(sender, pkAddr, r, acc, asOf); err != nil {
			return err
		}
		secret = r.OldPub
		if payload, err = common.AddressOpenPayload(sender, pkAddr, r.Next, r.Spare, r.OldPub); err != nil {
			return err
		}
	} else {
		var next common.Address
		secret, next, err = ParseRecoveryReveal(tx.TxData.OptData)
		if err != nil {
			return err
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
		if payload, err = common.RecoveryPayload(sender, pkAddr, next, secret); err != nil {
			return err
		}
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

// verifyAddressOpening checks the authority of an address opening: the account
// never registered a key nor set a commitment, its address is the hash of the
// revealed old key, and that key signed the opening. The old key's scheme is
// verified by name through liboqs, whether or not the chain still uses it -
// the chain never signs with it again, it only checks this one signature.
func verifyAddressOpening(sender, newKey common.Address, r AddressReveal, acc account.Account, asOf int64) error {
	if _, err := pubkeys.LoadAddressesAsOf(sender, asOf); err == nil {
		return fmt.Errorf("%s has registered keys; it recovers through its commitments", sender.GetHex())
	}
	if acc.HasCommitments() {
		return fmt.Errorf("%s already has commitments", sender.GetHex())
	}
	derived, err := common.PubKeyToAddress(r.OldPub, true)
	if err != nil {
		return err
	}
	if derived.ByteValue != sender.ByteValue {
		return fmt.Errorf("the revealed old key does not hash to %s", sender.GetHex())
	}
	msg, err := common.AddressOpenMessage(sender, newKey, r.Next, r.Spare)
	if err != nil {
		return err
	}
	var v oqs.Signature
	defer v.Clean()
	if err := v.Init(r.OldScheme, nil); err != nil {
		return fmt.Errorf("unknown old signature scheme %q: %w", r.OldScheme, err)
	}
	ok, err := v.Verify(msg, r.OldSig, r.OldPub)
	if err != nil || !ok {
		return fmt.Errorf("the old key's signature over the opening does not verify")
	}
	return nil
}

// hasSpareCover reports whether identity has a way out of a broken scheme: a
// commitment to its spare key's address (in force or pending), or both a
// primary and a spare key registered (validators keep the latter: they must
// sign at once when the primary is paused).
func hasSpareCover(identity common.Address, asOf int64) bool {
	if acc, ok := account.GetAccountByAddressBytes(identity.GetBytes()); ok {
		var zero [common.AddressLength]byte
		if acc.SpareCommit != zero || acc.SparePendingCommit != zero {
			return true
		}
	}
	return pubkeys.HasOperatorKeysAsOf(identity, asOf)
}

// isCommittedSpare reports whether keyAddr is the spare key address identity
// committed to, in force at the height the transaction is judged at.
func isCommittedSpare(identity, keyAddr common.Address, asOf int64) bool {
	acc, ok := account.GetAccountByAddressBytes(identity.GetBytes())
	if !ok {
		return false
	}
	spare := acc.EffectiveSpareCommit(recoveryHeight(asOf))
	var zero [common.AddressLength]byte
	return spare != zero && spare == keyAddr.ByteValue
}

// AddressReveal is the data of a reveal that opens an account which never
// registered a key: the address is the hash of OldPub, a key of a scheme the
// chain may no longer use, and OldSig is that key's signature over
// common.AddressOpenMessage.
type AddressReveal struct {
	Next      common.Address // recovery commitment the account starts with
	Spare     common.Address // spare key address the account starts with
	OldScheme string
	OldPub    []byte
	OldSig    []byte
}

// IsAddressReveal tells the two reveal kinds apart: a commitment reveal is
// exactly secret ‖ next; anything longer is an address opening.
func (tx *Transaction) IsAddressReveal() bool {
	return tx.IsRecoveryReveal() && len(tx.TxData.OptData) != common.RecoveryRevealOptDataLength
}

func BuildAddressRevealOptData(r AddressReveal) []byte {
	b := append(append([]byte{}, r.Next.GetBytes()...), r.Spare.GetBytes()...)
	b = append(b, common.BytesToLenAndBytes([]byte(r.OldScheme))...)
	b = append(b, common.BytesToLenAndBytes(r.OldPub)...)
	return append(b, common.BytesToLenAndBytes(r.OldSig)...)
}

func ParseAddressReveal(opt []byte) (AddressReveal, error) {
	var r AddressReveal
	if len(opt) <= 2*common.AddressLength {
		return r, fmt.Errorf("address reveal data too short")
	}
	if err := r.Next.Init(opt[:common.AddressLength]); err != nil {
		return r, err
	}
	if err := r.Spare.Init(opt[common.AddressLength : 2*common.AddressLength]); err != nil {
		return r, err
	}
	rest := opt[2*common.AddressLength:]
	scheme, rest, err := common.BytesWithLenToBytes(rest)
	if err != nil {
		return r, err
	}
	pub, rest, err := common.BytesWithLenToBytes(rest)
	if err != nil {
		return r, err
	}
	sig, rest, err := common.BytesWithLenToBytes(rest)
	if err != nil {
		return r, err
	}
	if len(rest) != 0 {
		return r, fmt.Errorf("address reveal data has %d trailing bytes", len(rest))
	}
	r.OldScheme, r.OldPub, r.OldSig = string(scheme), pub, sig
	return r, nil
}
