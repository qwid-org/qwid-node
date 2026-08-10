package account

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// DEX state is consensus state: it is snapshotted per height and restored on a
// rewind, so anything the binary encoding loses is value that silently vanishes
// from the pools. These cover the encoding edges and the pool accounting the
// supply invariant depends on.

func withFreshDex(t *testing.T) {
	t.Helper()
	DexRWMutex.Lock()
	saved := DexAccounts
	DexAccounts = DexAccountsType{AllDexAccounts: map[[common.AddressLength]byte]DexAccount{}}
	DexRWMutex.Unlock()
	t.Cleanup(func() {
		DexRWMutex.Lock()
		DexAccounts = saved
		DexRWMutex.Unlock()
	})
}

func dexAddr(marker byte) common.Address {
	a := common.Address{}
	a.ByteValue[common.AddressLength-1] = marker
	return a
}

func TestDexAccountRoundTripWithNoBalances(t *testing.T) {
	original := DexAccount{
		CoinPool:     1_000_000,
		TokenPool:    2_000_000,
		TokenPrice:   500,
		TokenAddress: dexAddr(1),
		Balances:     map[[common.AddressLength]byte]CoinTokenDetails{},
	}

	var restored DexAccount
	if err := restored.Unmarshal(original.Marshal()); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if restored.CoinPool != original.CoinPool || restored.TokenPool != original.TokenPool ||
		restored.TokenPrice != original.TokenPrice {
		t.Errorf("pools/price lost: %+v", restored)
	}
	if restored.TokenAddress != original.TokenAddress {
		t.Errorf("token address lost: %x", restored.TokenAddress.ByteValue)
	}
	if len(restored.Balances) != 0 {
		t.Errorf("balances = %d entries, want none", len(restored.Balances))
	}
}

// Map iteration order is random, so an encoder that writes a map must still
// decode to the same set. This is the property that matters — not the order.
func TestDexAccountRoundTripPreservesEveryBalance(t *testing.T) {
	original := DexAccount{
		CoinPool:     10,
		TokenPool:    20,
		TokenPrice:   2,
		TokenAddress: dexAddr(2),
		Balances:     map[[common.AddressLength]byte]CoinTokenDetails{},
	}
	for i := byte(1); i <= 25; i++ {
		original.Balances[dexAddr(i).ByteValue] = CoinTokenDetails{
			CoinBalance:  int64(i) * 1_000,
			TokenBalance: int64(i) * 7,
		}
	}

	var restored DexAccount
	if err := restored.Unmarshal(original.Marshal()); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(restored.Balances) != len(original.Balances) {
		t.Fatalf("balances = %d entries, want %d", len(restored.Balances), len(original.Balances))
	}
	for addr, want := range original.Balances {
		got, ok := restored.Balances[addr]
		if !ok {
			t.Fatalf("balance for %x disappeared", addr[:4])
		}
		if got != want {
			t.Fatalf("balance for %x = %+v, want %+v", addr[:4], got, want)
		}
	}
}

// Negative balances are representable and must survive: a position can be
// negative in intermediate accounting, and silently clamping it would move value.
func TestDexAccountRoundTripKeepsNegativeAndExtremeValues(t *testing.T) {
	original := DexAccount{
		CoinPool:     -1,
		TokenPool:    9_223_372_036_854_775_807,
		TokenPrice:   -9_223_372_036_854_775_808,
		TokenAddress: dexAddr(3),
		Balances: map[[common.AddressLength]byte]CoinTokenDetails{
			dexAddr(4).ByteValue: {CoinBalance: -5, TokenBalance: 9_223_372_036_854_775_807},
		},
	}

	var restored DexAccount
	if err := restored.Unmarshal(original.Marshal()); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if restored.CoinPool != original.CoinPool || restored.TokenPool != original.TokenPool ||
		restored.TokenPrice != original.TokenPrice {
		t.Errorf("extreme pool values changed: %+v", restored)
	}
	got := restored.Balances[dexAddr(4).ByteValue]
	if got.CoinBalance != -5 || got.TokenBalance != 9_223_372_036_854_775_807 {
		t.Errorf("extreme balance changed: %+v", got)
	}
}

// A truncated snapshot must be reported, not silently decoded into a half
// account that would then be written back as the state of that height.
func TestDexAccountUnmarshalRejectsTruncatedInput(t *testing.T) {
	full := DexAccount{
		CoinPool: 1, TokenPool: 2, TokenPrice: 3,
		TokenAddress: dexAddr(5),
		Balances: map[[common.AddressLength]byte]CoinTokenDetails{
			dexAddr(6).ByteValue: {CoinBalance: 10, TokenBalance: 20},
		},
	}.Marshal()

	for _, cut := range []int{1, 8, 20, len(full) - 1} {
		var da DexAccount
		if err := da.Unmarshal(full[:cut]); err == nil {
			t.Errorf("input truncated to %d bytes was accepted", cut)
		}
	}
}

// ---------------------------------------------------------- pool accounting

// GetCoinLiquidityInDex feeds the supply invariant: coin sitting in DEX pools
// has to be counted somewhere or the chain looks like it lost money.
func TestCoinLiquiditySumsEveryPool(t *testing.T) {
	withFreshDex(t)

	for i, amount := range map[byte]int64{1: 1_000, 2: 2_500, 3: 300} {
		addr := dexAddr(i)
		SetDexAccountByAddressBytes(addr.GetBytes(), DexAccount{
			CoinPool:     amount,
			TokenAddress: addr,
			Balances:     map[[common.AddressLength]byte]CoinTokenDetails{},
		})
	}

	if got := GetCoinLiquidityInDex(); got != 3_800 {
		t.Fatalf("liquidity = %d, want 3800", got)
	}
}

func TestCoinLiquidityIsZeroWithNoPools(t *testing.T) {
	withFreshDex(t)

	if got := GetCoinLiquidityInDex(); got != 0 {
		t.Fatalf("liquidity = %d on an empty DEX, want 0", got)
	}
}

// Reading a token that has no DEX account must give an empty account rather
// than blowing up — callers price against it directly.
func TestUnknownTokenGivesAnEmptyDexAccount(t *testing.T) {
	withFreshDex(t)

	unknown := dexAddr(99)
	acc := GetDexAccountByAddressBytes(unknown.GetBytes())
	if acc.CoinPool != 0 || acc.TokenPool != 0 || acc.TokenPrice != 0 {
		t.Fatalf("unknown token returned a populated account: %+v", acc)
	}
	if len(acc.Balances) != 0 {
		t.Fatalf("unknown token returned %d balances", len(acc.Balances))
	}
}

func TestSetDexAccountReplacesInPlace(t *testing.T) {
	withFreshDex(t)
	addr := dexAddr(7)

	SetDexAccountByAddressBytes(addr.GetBytes(), DexAccount{CoinPool: 100, TokenAddress: addr})
	SetDexAccountByAddressBytes(addr.GetBytes(), DexAccount{CoinPool: 250, TokenAddress: addr})

	if got := GetDexAccountByAddressBytes(addr.GetBytes()).CoinPool; got != 250 {
		t.Fatalf("CoinPool = %d, want the replacement 250", got)
	}
	if got := GetCoinLiquidityInDex(); got != 250 {
		t.Fatalf("liquidity = %d — the replaced account was counted twice", got)
	}
}
