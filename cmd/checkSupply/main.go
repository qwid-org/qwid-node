// Command checkSupply audits the per-height supply invariant that
// CheckBlockAndTransferFunds enforces:
//
//	supplyInAccounts(h) + staked(h) + rewarded(h) + block(h).BlockFee == block(h).Supply
//
// Every height keeps a full accounts/staking snapshot, so when a node refuses to
// sync with "block supply checking fails vs account balances" this walks the
// stored snapshots and reports the FIRST height where the invariant broke - i.e.
// the block that actually corrupted local state, not the block that noticed.
//
// Usage:
//
//	go run cmd/checkSupply/main.go              # binary search for the first bad height
//	go run cmd/checkSupply/main.go 23900 23950  # linear scan of a range
//
// It opens the database read-only (RocksDB secondary instance), so it is safe to
// run while a node is up - though a running node may have unflushed writes the
// secondary cannot see yet, so prefer running it with the node stopped.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/blocks"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/database"
	"github.com/wonabru/qwid-node/transactionsDefinition"
)

type snapshot struct {
	height   int64
	accounts int64
	staked   int64
	rewarded int64
	blockFee int64
	supply   int64
	delta    int64
}

func (s snapshot) String() string {
	return fmt.Sprintf("h=%d accounts=%d staked=%d rewarded=%d blockFee=%d supply=%d delta=%d",
		s.height, s.accounts, s.staked, s.rewarded, s.blockFee, s.supply, s.delta)
}

// at loads the stored state for a height and evaluates the invariant.
func at(height int64) (snapshot, error) {
	s := snapshot{height: height}
	block, err := blocks.LoadBlock(height)
	if err != nil {
		return s, fmt.Errorf("cannot load block %d: %w", height, err)
	}
	if err := account.LoadAccounts(height); err != nil {
		return s, fmt.Errorf("cannot load accounts %d: %w", height, err)
	}
	if err := account.LoadStakingAccounts(height); err != nil {
		return s, fmt.Errorf("cannot load staking accounts %d: %w", height, err)
	}
	s.accounts = blocks.GetSupplyInAccounts()
	s.staked, s.rewarded = blocks.GetSupplyInStakedAccounts()
	s.blockFee = block.BlockFee
	s.supply = block.GetBlockSupply()
	s.delta = s.accounts + s.staked + s.rewarded + s.blockFee - s.supply
	return s, nil
}

// dumpBlock prints the transactions of a block so the culprit can be identified.
func dumpBlock(height int64) {
	block, err := blocks.LoadBlock(height)
	if err != nil {
		fmt.Printf("  cannot load block %d: %v\n", height, err)
		return
	}
	hashes := block.GetBlockTransactionsHashes()
	head := block.GetHeader()
	fmt.Printf("  block %d: %d transactions, delegated=%x operator=%x\n",
		height, len(hashes),
		head.DelegatedAccount.ByteValue[:4],
		head.OperatorAccount.ByteValue[:4])
	for i, h := range hashes {
		tx, err := transactionsDefinition.LoadFromDBPoolTx(common.TransactionDBPrefix[:], h.GetBytes())
		if err != nil {
			tx, err = transactionsDefinition.LoadFromDBPoolTx(common.TransactionPoolHashesDBPrefix[:], h.GetBytes())
		}
		if err != nil {
			fmt.Printf("    tx[%d] %x: NOT IN DB (%v)\n", i, h.GetBytes()[:8], err)
			continue
		}
		fee, _ := tx.CalcFee()
		sender := tx.GetSenderAddress()
		recipient := tx.TxData.Recipient
		n, delErr := account.IntDelegatedAccountFromAddress(recipient)
		kind := "standard"
		if delErr == nil {
			switch {
			case n > 0 && n < 256:
				kind = fmt.Sprintf("staking(n=%d)", n)
			case n >= 256 && n < 512:
				kind = fmt.Sprintf("reward-withdraw(n=%d)", n)
			default:
				kind = fmt.Sprintf("dex(n=%d)", n)
			}
		}
		fmt.Printf("    tx[%d] %x %s sender=%x recipient=%x amount=%d fee=%d locked=%d optData=%dB\n",
			i, h.GetBytes()[:8], kind, sender.GetBytes()[:6], recipient.GetBytes()[:6],
			tx.TxData.Amount, fee, tx.GetLockedAmount(), len(tx.TxData.OptData))
	}
}

// balancesAt returns a copy of the account balances stored for a height.
func balancesAt(height int64) (map[[common.AddressLength]byte]int64, error) {
	if err := account.LoadAccounts(height); err != nil {
		return nil, fmt.Errorf("cannot load accounts %d: %w", height, err)
	}
	out := map[[common.AddressLength]byte]int64{}
	for a, acc := range account.Accounts.AllAccounts {
		out[a] = acc.Balance
	}
	return out, nil
}

// diffHeights prints every account whose balance differs between two snapshots.
func diffHeights(h1, h2 int64) {
	b1, err := balancesAt(h1)
	if err != nil {
		fmt.Println(err)
		return
	}
	b2, err := balancesAt(h2)
	if err != nil {
		fmt.Println(err)
		return
	}
	seen := map[[common.AddressLength]byte]bool{}
	total := int64(0)
	n := 0
	report := func(a [common.AddressLength]byte) {
		if seen[a] {
			return
		}
		seen[a] = true
		if b1[a] == b2[a] {
			return
		}
		n++
		total += b2[a] - b1[a]
		fmt.Printf("  %x: %d -> %d (%+d)\n", a[:8], b1[a], b2[a], b2[a]-b1[a])
	}
	for a := range b1 {
		report(a)
	}
	for a := range b2 {
		report(a)
	}
	fmt.Printf("accounts differing between %d and %d: %d, net change %+d\n", h1, h2, n, total)
}

func main() {
	secondary := filepath.Join(os.TempDir(), "qwid-checksupply-secondary")
	if err := database.InitDBReadOnly(secondary); err != nil {
		fmt.Println("cannot open database:", err)
		os.Exit(1)
	}
	defer database.CloseDB()

	top, err := blocks.LastHeightStoredInBlocks()
	if err != nil || top < 1 {
		fmt.Println("cannot determine last stored block height:", err)
		os.Exit(1)
	}
	fmt.Printf("last stored block height: %d\n", top)

	// Diff mode: which accounts changed between two stored snapshots.
	if len(os.Args) >= 4 && os.Args[1] == "diff" {
		h1, err1 := strconv.ParseInt(os.Args[2], 10, 64)
		h2, err2 := strconv.ParseInt(os.Args[3], 10, 64)
		if err1 != nil || err2 != nil {
			fmt.Println("usage: checkSupply diff <height1> <height2>")
			os.Exit(1)
		}
		diffHeights(h1, h2)
		return
	}

	// Explicit range: linear scan, printing every height.
	if len(os.Args) >= 3 {
		from, err1 := strconv.ParseInt(os.Args[1], 10, 64)
		to, err2 := strconv.ParseInt(os.Args[2], 10, 64)
		if err1 != nil || err2 != nil {
			fmt.Println("usage: checkSupply [fromHeight toHeight]")
			os.Exit(1)
		}
		if to > top {
			to = top
		}
		prev := int64(0)
		for h := from; h <= to; h++ {
			s, err := at(h)
			if err != nil {
				fmt.Println(err)
				continue
			}
			mark := "OK "
			if s.delta != 0 {
				mark = "BAD"
			}
			fmt.Printf("%s %s (change vs previous: %+d)\n", mark, s, s.delta-prev)
			prev = s.delta
		}
		return
	}

	// Binary search for the first height whose invariant is broken. The breakage
	// is cumulative - once state and the fee ledger diverge they stay diverged -
	// so the predicate "delta != 0" is monotone in practice.
	lo, err := at(0)
	if err != nil {
		fmt.Println("cannot evaluate genesis:", err)
		os.Exit(1)
	}
	fmt.Println("genesis:", lo)
	if lo.delta != 0 {
		fmt.Println("invariant already broken at genesis - nothing to bisect")
		return
	}
	hi, err := at(top)
	if err != nil {
		fmt.Println("cannot evaluate top:", err)
		os.Exit(1)
	}
	fmt.Println("top:    ", hi)
	if hi.delta == 0 {
		fmt.Println("invariant holds at the tip - local state is consistent with the stored fee ledger")
		return
	}

	l, h := int64(0), top
	for h-l > 1 {
		mid := l + (h-l)/2
		s, err := at(mid)
		if err != nil {
			fmt.Println(err)
			// Unreadable height: probe upwards so the search can continue.
			l = mid
			continue
		}
		fmt.Printf("probe %s\n", s)
		if s.delta == 0 {
			l = mid
		} else {
			h = mid
		}
	}

	fmt.Printf("\n=== first height with a broken supply invariant: %d ===\n", h)
	for x := h - 2; x <= h+2 && x <= top; x++ {
		if x < 0 {
			continue
		}
		s, err := at(x)
		if err != nil {
			fmt.Println(err)
			continue
		}
		mark := "OK "
		if s.delta != 0 {
			mark = "BAD"
		}
		fmt.Printf("%s %s\n", mark, s)
	}
	fmt.Printf("\ntransactions of block %d (the block that broke it):\n", h)
	dumpBlock(h)
}
