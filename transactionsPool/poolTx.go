package transactionsPool

import (
	"container/heap"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"sync"
)

var (
	PoolsTx         *TransactionPool
	PoolTxEscrow    *TransactionPool
	PoolTxMultiSign *TransactionPool
)

func init() {
	PoolsTx = NewTransactionPool(common.MaxTransactionInPool, 0)
	PoolTxEscrow = NewTransactionPool(common.MaxTransactionInPool, 1)
	PoolTxMultiSign = NewTransactionPool(common.MaxTransactionInPool, 2)
}

type Item struct {
	transactionsDefinition.Transaction
	value    [common.HashLength]byte
	priority int64
	index    int
}

func NewItem(tx transactionsDefinition.Transaction, priority int64) *Item {
	hash := [common.HashLength]byte{}
	calcHash := tx.GetHash()
	copy(hash[:], calcHash.GetBytes())
	return &Item{
		Transaction: tx,
		value:       hash,
		priority:    priority,
	}
}

type TransactionPool struct {
	transactions       map[[common.HashLength]byte]transactionsDefinition.Transaction
	transactionIndices map[[common.HashLength]byte]int // New map for tracking indices
	bannedTransactions map[[common.HashLength]byte]int
	priorityQueue      PriorityQueue
	maxTransactions    int
	typePool           uint8 // 0 - standard Tx, 1 - Escrow/delayed, 2 - MultiSign
	rwmutex            sync.RWMutex
}

// Modify AddTransaction to update transactionIndices
// Modify RemoveTransactionByHash and PopTransactionByHash to use transactionIndices for direct access

func (tp *TransactionPool) updateIndices() {
	// Call this method after any operation that might change the indices of items in the priorityQueue
	tp.rwmutex.Lock()
	defer tp.rwmutex.Unlock()
	for i := range tp.priorityQueue {
		txHash := tp.priorityQueue[i].GetHash().GetBytes()
		var hash [common.HashLength]byte
		copy(hash[:], txHash)
		tp.transactionIndices[hash] = i
	}
}

// Ensure heap operations (push, pop, remove) call updateIndices to keep the map accurate

func NewTransactionPool(maxTransactions int, typePool uint8) *TransactionPool {
	return &TransactionPool{
		transactions:       make(map[[common.HashLength]byte]transactionsDefinition.Transaction),
		bannedTransactions: make(map[[common.HashLength]byte]int),
		priorityQueue:      make(PriorityQueue, 0),
		transactionIndices: map[[common.HashLength]byte]int{},
		typePool:           typePool,
		maxTransactions:    maxTransactions,
	}
}
func (tp *TransactionPool) AddTransaction(tx transactionsDefinition.Transaction, hash2check common.Hash) bool {
	var hash [common.HashLength]byte
	copy(hash[:], tx.GetHash().GetBytes())
	tp.rwmutex.Lock()
	if numBans, exists := tp.bannedTransactions[hash]; exists {
		if numBans > common.NumberWhenWillBan {
			tp.rwmutex.Unlock()
			logger.GetLogger().Println("transaction not added. banned")
			tp.BanTransactionByHash(hash[:])
			return false
		}
	}
	if _, exists := tp.transactions[hash]; !exists {
		tp.transactions[hash] = tx
		item := &Item{}
		if tp.typePool == uint8(0) {
			item = NewItem(tx, tx.GetGasPrice())
		} else if tp.typePool == uint8(1) {
			item = NewItem(tx, tx.GetHeight()+tx.TxData.EscrowTransactionsDelay)
		} else if tp.typePool == uint8(2) {
			item = NewItem(tx, common.GetInt64FromByte(hash2check.GetBytes()))
		} else {
			logger.GetLogger().Println("not implemented, AddTransaction")
			return false
		}

		heap.Push(&tp.priorityQueue, item)
		if tp.priorityQueue.Len() > tp.maxTransactions {
			removed := heap.Pop(&tp.priorityQueue).(*Item)
			delete(tp.transactions, removed.value)
		}
	}
	tp.rwmutex.Unlock()
	tp.updateIndices()
	return true
}
func (tp *TransactionPool) HasTransaction(hash []byte) bool {
	var h [common.HashLength]byte
	copy(h[:], hash)
	tp.rwmutex.RLock()
	defer tp.rwmutex.RUnlock()
	_, exists := tp.transactions[h]
	return exists
}

func (tp *TransactionPool) PeekTransactions(n int, heightOrHash int64) []transactionsDefinition.Transaction {

	hash := [common.HashLength]byte{}
	topTransactions := []transactionsDefinition.Transaction{}
	tp.rwmutex.RLock()
	defer tp.rwmutex.RUnlock()
	if n > len(tp.transactions) {
		n = len(tp.transactions)
	}

	for i := 0; i < n; i++ {
		if len(tp.priorityQueue) > i {
			transaction := *tp.priorityQueue[i]
			if tp.typePool == 0 {
				copy(hash[:], transaction.GetHash().GetBytes())
				topTransactions = append(topTransactions, tp.transactions[hash])
			} else if tp.typePool == 1 {
				if heightOrHash >= transaction.priority {
					copy(hash[:], transaction.GetHash().GetBytes())
					topTransactions = append(topTransactions, tp.transactions[hash])
				}
			} else if tp.typePool == 2 {
				if heightOrHash == transaction.priority {
					copy(hash[:], transaction.GetHash().GetBytes())
					topTransactions = append(topTransactions, tp.transactions[hash])
				}
			} else {
				logger.GetLogger().Println("not implemented, PeekTransactions")
			}

		}
	}

	return topTransactions
}

func (tp *TransactionPool) RemoveTransactionByHash(hash []byte) {
	h := [common.HashLength]byte{}
	copy(h[:], hash)
	tp.rwmutex.Lock()
	if index, exists := tp.transactionIndices[h]; exists {
		heap.Remove(&tp.priorityQueue, index)
		delete(tp.transactions, h)
		delete(tp.transactionIndices, h) // Don't forget to clean up the indices map
	}
	tp.rwmutex.Unlock()
	tp.updateIndices()
}

func (tp *TransactionPool) BanTransactionByHash(hash []byte) {
	h := [common.HashLength]byte{}
	copy(h[:], hash)
	tp.rwmutex.Lock()
	defer tp.rwmutex.Unlock()
	tp.bannedTransactions[h]++
	if tp.bannedTransactions[h] > common.MaxNumberOfTxBans {
		delete(tp.bannedTransactions, h)
	}
}

func (tp *TransactionPool) TransactionExists(hash []byte) bool {
	h := [common.HashLength]byte{}
	copy(h[:], hash)
	tp.rwmutex.RLock()
	defer tp.rwmutex.RUnlock()
	_, exists := tp.transactions[h]
	return exists
}

func (tp *TransactionPool) GetTransactionByHash(hash []byte) (transactionsDefinition.Transaction, bool) {
	h := [common.HashLength]byte{}
	copy(h[:], hash)
	tp.rwmutex.RLock()
	defer tp.rwmutex.RUnlock()
	tx, exists := tp.transactions[h]
	return tx, exists
}

func (tp *TransactionPool) PopTransactionByHash(hash []byte) transactionsDefinition.Transaction {
	h := [common.HashLength]byte{}
	copy(h[:], hash)
	tp.rwmutex.Lock()
	var tx transactionsDefinition.Transaction
	if index, exists := tp.transactionIndices[h]; exists {
		tx = tp.transactions[h]
		heap.Remove(&tp.priorityQueue, index)
		delete(tp.transactions, h)
		delete(tp.transactionIndices, h)
	}
	tp.rwmutex.Unlock()
	tp.updateIndices()
	return tx
}

func (tp *TransactionPool) NumberOfTransactions() int {
	tp.rwmutex.RLock()
	defer tp.rwmutex.RUnlock()
	return len(tp.transactions)
}
