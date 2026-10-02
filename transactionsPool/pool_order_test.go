package transactionsPool

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

func pricedTx(marker byte, gasPrice int64) transactionsDefinition.Transaction {
	tx := transactionsDefinition.Transaction{GasPrice: gasPrice}
	b := make([]byte, common.HashLength)
	b[0], b[1] = marker, byte(gasPrice)
	tx.Hash.Set(b)
	return tx
}

// S4-08: the producer takes the best-paying transactions first - Peek
// returns them in priority order, not in heap-array order.
func TestPeekReturnsBestPayingFirst(t *testing.T) {
	p := NewTransactionPool(100, 0)
	for i, price := range []int64{3, 9, 1, 7, 5, 8, 2, 6, 4, 10} {
		p.AddTransaction(pricedTx(byte(i), price), common.Hash{})
	}
	got := p.PeekTransactions(10, 0)
	for i := 1; i < len(got); i++ {
		if got[i-1].GasPrice < got[i].GasPrice {
			t.Fatalf("not sorted: %d before %d", got[i-1].GasPrice, got[i].GasPrice)
		}
	}
	top := p.PeekTransactions(3, 0)
	if len(top) != 3 || top[0].GasPrice != 10 || top[1].GasPrice != 9 || top[2].GasPrice != 8 {
		t.Fatalf("top 3 = %v", top)
	}
}

// S4-08: a full pool evicts its cheapest entry, kept track of without a
// linear scan of the whole queue.
func TestFullPoolEvictsCheapest(t *testing.T) {
	p := NewTransactionPool(3, 0)
	for i, price := range []int64{5, 1, 9, 7} {
		p.AddTransaction(pricedTx(byte(i), price), common.Hash{})
	}
	got := p.PeekTransactions(10, 0)
	if len(got) != 3 || got[2].GasPrice != 5 {
		t.Fatalf("after eviction: %v", got)
	}
	p.RemoveTransactionByHash(pricedTx(2, 9).Hash.GetBytes())
	p.AddTransaction(pricedTx(9, 2), common.Hash{})
	p.AddTransaction(pricedTx(8, 3), common.Hash{})
	got = p.PeekTransactions(10, 0)
	if len(got) != 3 || got[0].GasPrice != 7 || got[2].GasPrice != 3 {
		t.Fatalf("min-tracking broken after a removal: %v", got)
	}
}
