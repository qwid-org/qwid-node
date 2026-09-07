package account

import (
	"fmt"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// runNoPanic calls fn and converts any panic into a test failure. QWID-2026-14
// requires every snapshot decoder to return normally (nil or error) for ANY
// input — a panic on a corrupt snapshot crashes the node at startup/rewind.
func runNoPanic(t *testing.T, name string, fn func() error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: decoder panicked instead of returning an error: %v", name, r)
		}
	}()
	_ = fn()
}

// truncationSweep feeds every prefix of valid (length 0..len) plus a few
// corrupt-count variants and asserts none panic.
func truncationSweep(t *testing.T, name string, valid []byte, decode func([]byte) error) {
	t.Helper()
	for n := 0; n <= len(valid); n++ {
		prefix := append([]byte(nil), valid[:n]...)
		runNoPanic(t, fmt.Sprintf("%s trunc@%d", name, n), func() error { return decode(prefix) })
	}
	// Corrupt the leading 8-byte count (present in every snapshot type) with a
	// negative value (all 0xFF) and a huge value, keeping the rest intact.
	if len(valid) >= 8 {
		for _, corruptName := range []string{"negative-count", "huge-count"} {
			mutated := append([]byte(nil), valid...)
			switch corruptName {
			case "negative-count":
				for i := 0; i < 8; i++ {
					mutated[i] = 0xFF
				}
			case "huge-count":
				mutated[0] = 0xFF
				mutated[1] = 0xFF
				mutated[2] = 0xFF
				mutated[3] = 0x7F
			}
			runNoPanic(t, name+" "+corruptName, func() error { return decode(mutated) })
		}
	}
}

func TestQWID14_SnapshotDecodersNeverPanic(t *testing.T) {
	h := func(b byte) common.Hash {
		var hh common.Hash
		for i := range hh {
			hh[i] = b
		}
		return hh
	}
	var addr [common.AddressLength]byte
	for i := range addr {
		addr[i] = 0xAB
	}

	// --- Account (inner) ---
	acc := Account{
		Balance:               12345,
		Address:               addr,
		TransactionDelay:      7,
		MultiSignNumber:       2,
		MultiSignAddresses:    [][common.AddressLength]byte{addr, addr},
		TransactionsSender:    []common.Hash{h(1), h(2)},
		TransactionsRecipient: []common.Hash{h(3)},
		SentCount:             2,
		ReceivedCount:         1,
	}
	truncationSweep(t, "Account", acc.Marshal(), func(b []byte) error {
		var a Account
		return a.Unmarshal(b)
	})

	// --- StakingAccount (inner) ---
	sa := StakingAccount{
		StakedBalance:    1000,
		StakingRewards:   50,
		LockedAmount:     []int64{10, 20},
		ReleasePerBlock:  []int64{1, 2},
		LockedInitBlock:  []int64{100, 200},
		DelegatedAccount: addr,
		Address:          addr,
		OperationalSince: 5,
		LastStakeHeight:  9,
		StakingDetails: map[int64][]StakingDetail{
			3: {{Amount: 1, Reward: 2, LastUpdated: 3}, {Amount: 4, Reward: 5, LastUpdated: 6}},
		},
	}
	truncationSweep(t, "StakingAccount", sa.Marshal(), func(b []byte) error {
		var s StakingAccount
		return s.Unmarshal(b)
	})

	// --- DexAccount (inner) ---
	da := DexAccount{CoinPool: 100, TokenPool: 200, TokenPrice: 3}
	da.TokenAddress = common.Address{}
	da.Balances = map[[common.AddressLength]byte]CoinTokenDetails{addr: {}}
	truncationSweep(t, "DexAccount", da.Marshal(), func(b []byte) error {
		var d DexAccount
		return d.Unmarshal(b)
	})

	// --- AccountsType (top level) ---
	at := AccountsType{AllAccounts: map[[common.AddressLength]byte]Account{addr: acc}, Height: 42}
	truncationSweep(t, "AccountsType", at.Marshal(), func(b []byte) error {
		var x AccountsType
		return x.Unmarshal(b)
	})

	// --- StakingAccountsType (top level) ---
	sat := StakingAccountsType{
		AllStakingAccounts: map[[common.AddressLength]byte]StakingAccount{addr: sa},
		StakeChangedAt:     11,
	}
	truncationSweep(t, "StakingAccountsType", sat.Marshal(), func(b []byte) error {
		var x StakingAccountsType
		return x.Unmarshal(b)
	})

	// --- DexAccountsType (top level, empty map: exercises count/length guards
	// without depending on the inner-length encoding) ---
	dat := DexAccountsType{AllDexAccounts: map[[common.AddressLength]byte]DexAccount{}}
	truncationSweep(t, "DexAccountsType", dat.Marshal(), func(b []byte) error {
		var x DexAccountsType
		return x.Unmarshal(b)
	})

	// Raw adversarial buffers: a claimed-nonzero count with no following data.
	for _, name := range []string{"AccountsType", "StakingAccountsType", "DexAccountsType"} {
		hugeCount := make([]byte, 8)
		for i := range hugeCount {
			hugeCount[i] = 0xFF
		}
		nm := name
		runNoPanic(t, nm+" bare-count", func() error {
			switch nm {
			case "AccountsType":
				var x AccountsType
				return x.Unmarshal(hugeCount)
			case "StakingAccountsType":
				var x StakingAccountsType
				return x.Unmarshal(hugeCount)
			default:
				var x DexAccountsType
				return x.Unmarshal(hugeCount)
			}
		})
	}
}
