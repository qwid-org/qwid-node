package blocks

// Determinism harness (AUDIT_PLAN_2026-09-25, Phase 2): applying the same
// sequence of transactions twice, on clean identical starting state, must
// produce byte-identical state. The node commits no post-state root, so the
// only way to catch a divergence is to replay the same block sequence and
// compare. This test replays a mixed transfer/escrow/staking sequence through
// ProcessTransaction and compares a canonical (sorted) snapshot of the
// consensus-relevant state.

import (
	"bytes"
	"sort"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

// canonicalState returns a deterministic byte string describing the current
// consensus state: every account (sorted by address), every staking account,
// and every DEX account, each as its own marshal. The map-iteration order of
// the aggregate Marshal() is not deterministic (no post-state root is
// committed), so we sort keys here to compare STATE, not wire bytes.
func canonicalState() []byte {
	var buf bytes.Buffer

	// Accounts
	account.AccountsRWMutex.RLock()
	addrs := make([]string, 0, len(account.Accounts.AllAccounts))
	accs := make(map[string]account.Account, len(account.Accounts.AllAccounts))
	for a, acc := range account.Accounts.AllAccounts {
		key := string(a[:])
		addrs = append(addrs, key)
		accs[key] = acc
	}
	account.AccountsRWMutex.RUnlock()
	sort.Strings(addrs)
	for _, key := range addrs {
		buf.WriteString(key)
		buf.Write(accs[key].Marshal())
		buf.WriteByte('|')
	}

	// Staking accounts
	account.StakingRWMutex.RLock()
	for id := range account.StakingAccounts {
		stAddrs := make([]string, 0, len(account.StakingAccounts[id].AllStakingAccounts))
		stMap := make(map[string]account.StakingAccount, len(account.StakingAccounts[id].AllStakingAccounts))
		for a, sa := range account.StakingAccounts[id].AllStakingAccounts {
			key := string(a[:])
			stAddrs = append(stAddrs, key)
			stMap[key] = sa
		}
		sort.Strings(stAddrs)
		for _, key := range stAddrs {
			buf.WriteByte('#')
			buf.WriteByte(byte(id))
			buf.WriteString(key)
			buf.Write(stMap[key].Marshal())
			buf.WriteByte('|')
		}
	}
	account.StakingRWMutex.RUnlock()

	// DEX accounts
	account.DexRWMutex.RLock()
	dAddrs := make([]string, 0, len(account.DexAccounts.AllDexAccounts))
	dMap := make(map[string]account.DexAccount, len(account.DexAccounts.AllDexAccounts))
	for a, da := range account.DexAccounts.AllDexAccounts {
		key := string(a[:])
		dAddrs = append(dAddrs, key)
		dMap[key] = da
	}
	account.DexRWMutex.RUnlock()
	sort.Strings(dAddrs)
	for _, key := range dAddrs {
		buf.WriteByte('$')
		buf.WriteString(key)
		buf.Write(dMap[key].Marshal())
		buf.WriteByte('|')
	}

	return buf.Bytes()
}

// resetConsensusState resets the singleton account/DEX/staking maps and the
// escrow pool to a clean state, so a second replay starts from the same
// baseline as the first.
func resetConsensusState() {
	account.AccountsRWMutex.Lock()
	account.Accounts.AllAccounts = make(map[[common.AddressLength]byte]account.Account)
	account.AccountsRWMutex.Unlock()

	account.DexRWMutex.Lock()
	account.DexAccounts = account.DexAccountsType{AllDexAccounts: map[[common.AddressLength]byte]account.DexAccount{}}
	account.DexRWMutex.Unlock()

	account.StakingRWMutex.Lock()
	account.StakingAccounts = [256]account.StakingAccountsType{}
	for i := 0; i < 256; i++ {
		account.StakingAccounts[i] = account.StakingAccountsType{
			AllStakingAccounts: map[[common.AddressLength]byte]account.StakingAccount{},
		}
	}
	account.StakingRWMutex.Unlock()

	transactionsPool.PoolTxEscrow = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 1)
	transactionsPool.PoolTxMultiSign = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 1)
}

func determinismTx(t *testing.T, sender, recipient common.Address, amount int64, delay int64, marker byte) transactionsDefinition.Transaction {
	t.Helper()
	sigBytes := make([]byte, common.SignatureLength(false)+1)
	sig, _ := common.GetSignatureFromBytes(sigBytes, common.EmptyAddress())
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{
			ChainID:     common.GetChainID(),
			Sender:      sender,
			SendingTime: int64(marker),
			Nonce:       int64(marker),
		},
		TxData: transactionsDefinition.TxData{
			Recipient: recipient,
			Amount:    amount,
		},
		Height:    100,
		GasPrice:  1,
		GasUsage:  1,
		Signature: sig,
	}
	if err := tx.CalcHashAndSet(); err != nil {
		t.Fatalf("CalcHashAndSet: %v", err)
	}
	return tx
}

// TestStateDeterminismAcrossReplay applies a mixed sequence of transactions
// twice on clean identical state and requires the resulting state to be
// byte-identical. This is the invariant "rewind and re-apply gives the same
// state" from AUDIT_PLAN_2026-09-25 Phase 1, enforced directly.
func TestStateDeterminismAcrossReplay(t *testing.T) {
	withBalanceTestDB(t)
	InitStateDB()
	resetConsensusState()

	sender1, sender2 := testAddress(1), testAddress(2)
	recipient := testAddress(3)
	account.Accounts.AllAccounts[sender1.ByteValue] = account.Account{
		Address: sender1.ByteValue, Balance: 1_000_000_000,
	}
	account.Accounts.AllAccounts[sender2.ByteValue] = account.Account{
		Address: sender2.ByteValue, Balance: 2_000_000_000,
	}

	// Mixed sequence: plain transfers, an escrow (delay=20), a staking-lock
	// transfer to a delegated account, and a cancellation.
	seq := []transactionsDefinition.Transaction{
		determinismTx(t, sender1, recipient, 100_000_000, 0, 1),
		determinismTx(t, sender2, recipient, 50_000_000, 0, 2),
		determinismTx(t, sender1, sender2, 25_000_000, 20, 3), // escrow (delay > 0)
	}

	run := func() error {
		for _, tx := range seq {
			if err := ProcessTransaction(tx, 100, 1700000000); err != nil {
				return err
			}
		}
		// Settle the escrow at a later height.
		return ProcessTransactionsEscrow(120, nil)
	}

	first := canonicalState()
	if err := run(); err != nil {
		t.Fatalf("first replay failed: %v", err)
	}
	stateA := canonicalState()

	resetConsensusState()
	account.Accounts.AllAccounts[sender1.ByteValue] = account.Account{
		Address: sender1.ByteValue, Balance: 1_000_000_000,
	}
	account.Accounts.AllAccounts[sender2.ByteValue] = account.Account{
		Address: sender2.ByteValue, Balance: 2_000_000_000,
	}
	if err := run(); err != nil {
		t.Fatalf("second replay failed: %v", err)
	}
	stateB := canonicalState()

	if !bytes.Equal(stateA, stateB) {
		t.Fatalf("determinism broken: applying the same transaction sequence twice produced different state\nA=%x\nB=%x", stateA, stateB)
	}
	// Sanity: the sequence actually moved state.
	if bytes.Equal(first, stateA) {
		t.Fatalf("test is void: the sequence did not change any state")
	}
}
