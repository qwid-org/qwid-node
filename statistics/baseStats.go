package statistics

import (
	"encoding/json"
	"github.com/qwid-org/qwid-node/logger"
	"sync"

	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

// Stats represents the main statistics structure
type Stats struct {
	Height                  int64   `json:"height"`
	HeightMax               int64   `json:"heightMax"`
	TimeInterval            int64   `json:"timeInterval"`
	Transactions            int     `json:"transactions"`
	TransactionsPending     int     `json:"transactionsPending"`
	TransactionsSize        int     `json:"transactionSize"`
	TransactionsPendingSize int     `json:"transactionsPendingSize"`
	Tps                     float32 `json:"tps"`
	Syncing                 bool    `json:"syncing"`
	Difficulty              int32   `json:"difficulty"`
	PriceOracle             float32 `json:"priceOracle"`
	RandOracle              int64   `json:"randOracle"`
	db                      *database.BlockchainDB
}

// StatsManager handles the statistics operations
type StatsManager struct {
	Stats *Stats
	Mu    sync.Mutex
}

var statsManager *StatsManager

// InitStatsManager initializes the statistics manager
func InitStatsManager() {
	if database.MainDB == nil {
		logger.GetLogger().Println("WARNING: MainDB is not initialized")
	}
	statsManager = &StatsManager{
		Stats: &Stats{
			Height:                  0,
			HeightMax:               0,
			TimeInterval:            0,
			Transactions:            0,
			TransactionsSize:        0,
			TransactionsPending:     0,
			TransactionsPendingSize: 0,
			Tps:                     0,
			Syncing:                 true,
			Difficulty:              0,
			PriceOracle:             1,
			RandOracle:              0,
			db:                      database.MainDB,
		},
	}
}

// GetStatsManager returns the singleton statistics manager
func GetStatsManager() *StatsManager {
	return statsManager
}

// Save saves the statistics to the database
func (sm *StatsManager) Save() error {
	sm.Mu.Lock()
	defer sm.Mu.Unlock()
	data, err := json.Marshal(sm.Stats)
	if err != nil {
		return err
	}
	return sm.Stats.db.Put(common.StatDBPrefix[:], data)
}

// Load loads the statistics from the database
func (sm *StatsManager) Load() error {
	sm.Mu.Lock()
	defer sm.Mu.Unlock()
	data, err := sm.Stats.db.Get(common.StatDBPrefix[:])
	if err != nil {
		return err
	}
	return json.Unmarshal(data, sm.Stats)
}

// UpdateStatistics updates the statistics with the given block data
func (sm *StatsManager) UpdateStatistics(newBlock blocks.Block, lastBlock blocks.Block) {
	h := common.GetHeight()
	hMax := common.GetHeightMax()
	syn := common.IsSyncing.Load()
	nt := transactionsPool.PoolsTx.NumberOfTransactions()
	sm.Mu.Lock()

	sm.Stats.Height = h
	sm.Stats.HeightMax = hMax
	sm.Stats.Difficulty = newBlock.BaseBlock.BaseHeader.Difficulty
	sm.Stats.PriceOracle = float32(newBlock.BaseBlock.PriceOracle) / 100000000.0
	sm.Stats.RandOracle = newBlock.BaseBlock.RandOracle
	sm.Stats.Syncing = syn
	sm.Stats.TimeInterval = newBlock.BaseBlock.BlockTimeStamp - lastBlock.BaseBlock.BlockTimeStamp
	empt := transactionsDefinition.EmptyTransaction()
	hs, _ := newBlock.GetTransactionsHashes(newBlock.GetHeader().Height)
	sm.Stats.Transactions = len(hs)
	sm.Stats.TransactionsSize = len(hs) * len(empt.GetBytes())
	ntxs := len(hs)
	sm.Stats.Tps = float32(ntxs) / float32(sm.Stats.TimeInterval)
	sm.Stats.TransactionsPending = nt
	sm.Stats.TransactionsPendingSize = nt * len(empt.GetBytes())
	sm.Mu.Unlock()
	if err := sm.Save(); err != nil {
		logger.GetLogger().Println(err)
	}
}
