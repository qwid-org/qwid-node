package blocks

// QWID-2026-05: escrow/multisig policy is a self-modification. A transaction
// that names a DIFFERENT account as recipient and carries policy fields must be
// refused at application (ProcessMultiSignAndEscrow), so a third party cannot
// impose a one-week escrow delay or an attacker-controlled multisig policy on a
// victim's account. A sender modifying its OWN account is allowed.

import (
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

func policyTx(sender, recipient common.Address, escrowDelay int64, multisig uint8) transactionsDefinition.Transaction {
	sigBytes := make([]byte, common.SignatureLength(false)+1)
	sig, _ := common.GetSignatureFromBytes(sigBytes, common.EmptyAddress())
	var signers [][common.AddressLength]byte
	for i := 0; i < int(multisig); i++ {
		var a [common.AddressLength]byte
		a[0] = byte(i + 1)
		signers = append(signers, a)
	}
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: sender, SendingTime: 1, Nonce: 1},
		TxData: transactionsDefinition.TxData{
			Recipient:               recipient,
			Amount:                  0,
			EscrowTransactionsDelay: escrowDelay,
			MultiSignNumber:         multisig,
			MultiSignAddresses:      signers,
		},
		Height: 5, GasPrice: 1, GasUsage: 1, Signature: sig,
	}
	_ = tx.CalcHashAndSet()
	return tx
}

func TestQWID05_PolicyOnlyModifiesSendersOwnAccount(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withBalanceTestDB(t)
	initTestAccounts()

	attacker, victim := testAddress(5), testAddress(6)

	// Attacker names the victim as recipient of an escrow-policy transaction.
	if err := ProcessMultiSignAndEscrow(policyTx(attacker, victim, 60480, 0)); err == nil {
		t.Fatal("a third party imposed an escrow delay on another account (QWID-2026-05)")
	}
	if acc, ok := account.GetAccountByAddressBytes(victim.GetBytes()); ok && (acc.TransactionDelay != 0 || acc.MultiSignNumber != 0) {
		t.Fatalf("the victim account was given a policy despite the rejection: delay=%d multisig=%d (QWID-2026-05)",
			acc.TransactionDelay, acc.MultiSignNumber)
	}

	// Attacker names the victim for an attacker-controlled multisig policy.
	if err := ProcessMultiSignAndEscrow(policyTx(attacker, victim, 0, 1)); err == nil {
		t.Fatal("a third party imposed a multisig policy on another account (QWID-2026-05)")
	}

	// A sender modifying its OWN account is allowed.
	if err := ProcessMultiSignAndEscrow(policyTx(attacker, attacker, 60480, 0)); err != nil {
		t.Fatalf("a sender could not set escrow policy on its own account: %v", err)
	}
}
