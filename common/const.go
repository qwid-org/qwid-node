package common

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"sync"

	"github.com/joho/godotenv"
	"github.com/wonabru/qwid-node/crypto/oqs"
	"github.com/wonabru/qwid-node/logger"
)

var (
	Decimals                       uint8   = 8
	MaxTotalSupply                 int64   = 230000000000000000
	InitSupply                     int64   = 23000000000000000
	RewardRatio                            = 2e-8
	ValidationTag                          = "validationTag"
	DifficultyMultiplier           int32   = 10
	BlockTimeInterval              float32 = 10 // 10 sec.
	MaxBlockTimeInterval           int64   = 2000
	MinNumberOfBlocksInStake       int64   = 36
	MaxBlockForwardInTime          int64   = 60
	DifficultyChange               float32 = 10
	MaxGasUsage                    int64   = 13700000 // circa 6.5k transactions in block
	MaxGasPrice                    int64   = 100000
	MaxTransactionsPerBlock        int16   = 5000 // on average 500 TPS
	MaxTransactionInPool                   = 50000
	MaxPeersConnected              int     = 6
	NumberOfHashesInBucket         int64   = 20
	NumberOfBlocksInBucket         int64   = 20
	MaxNumberOfTxBans              int     = 50 // number of bans
	NumberWhenWillBan                      = 100
	MinStakingForNode              int64   = 100000000000000
	MinStakingUser                 int64   = 100000000000 // should be 100000000000
	OraclesHeightDistance          int64   = 6            // one minute on average
	VotingHeightDistance           int64   = 60           // 60 => ten minute on average
	MaxTransactionDelay            int64   = 60480        // one week
	MaxTransactionInMultiSigPool   int64   = 60480        //one week
	MaxNumberTransactionInChunk            = 100
	ConnectionMaxTries                     = 10
	BannedTimeSeconds              int64   = 60                  // DoS hardening: was 2s; ~6 block intervals
	MessageInitialization                  = [4]byte{2, 0, 2, 9} // will be overwrite in init() by MaxMessageSizeBytes
	MaxMessageSizeBytes            int32   = 151126018           // should be adjusted to maximal message sent
	DefaultWalletHomePath                  = "/.qwid/wallet/"
	DefaultBlockchainHomePath              = "/.qwid/db/blockchain/"
	ConnectionsWithoutVerification         = [][]byte{[]byte("TRAN"), []byte("STAT"), []byte("ENCR"), []byte("DETS"), []byte("STAK"), []byte("ADEX"), []byte("PUBA"), []byte("HELO"), []byte("VALS")}
	CurrentHeightOfNetwork         int64   = 23

	// Per-topic inbound message-size caps (bytes) — DoS hardening (sub-project A).
	// Replace the single 151MB MaxMessageSizeBytes ENFORCEMENT (the wire marker
	// MessageInitialization/MaxMessageSizeBytes are unchanged). Sized generously
	// per topic so no legit traffic breaks. TransactionTopic intentionally keeps
	// the full MaxMessageSizeBytes cap (see MaxMessageSizeForTopic in
	// tcpip/helper.go): tx-gossip (up to MaxTransactionsPerBlock txs) and sync
	// "bx" recovery (up to MaxNumberTransactionInChunk txs) are sent as
	// un-chunked batches, so a tighter per-message cap would reject legitimate
	// batches and get honest peers banned. Tightening it requires chunking
	// those send paths (documented follow-up).
	MaxMsgSizeSmall int32 = 65536    // 64KB  — Nonce/SelfNonce (tiny fixed messages)
	MaxMsgSizeSync  int32 = 16777216 // 16MB  — Sync (block-header batches, ~3.2MB real max)
	MaxMsgSizeRPC   int32 = 1048576  // 1MB   — RPC (localhost-bound)

	// Per-IP rate limits — DoS hardening.
	MessageRateLimit            int   = 100 // max messages per window per IP
	MessageRateWindowSeconds    int64 = 10
	ConnectionRateLimit         int   = 20 // max connection attempts per window per IP; 20 tolerates a legit multi-topic (tx/nonce/self-nonce/sync) restart+retry
	ConnectionRateWindowSeconds int64 = 60

	MaxInboundConnectionsPerTopic int = 64 // NP-H2: cap concurrent inbound conns per topic (~10x the ~6 legit peers) to bound fd exhaustion / slow-loris
	MaxConcurrentRPCConnections   int = 64 // NP-H6: cap concurrent RPC conns (HTTP servers hold ~1 persistent conn each) to bound fd exhaustion
)

// db prefixes
var (
	BlocksDBPrefix                     = [2]byte{'B', 'I'}
	StatDBPrefix                       = [2]byte{'M', 'S'}
	BlockHeaderDBPrefix                = [2]byte{'H', 'B'}
	WalletDBPrefix                     = [2]byte{'W', '0'}
	PubKeyDBPrefix                     = [2]byte{'P', 'K'}
	PubKeyMarshalDBPrefix              = [2]byte{'P', 'M'}
	PubKeyMerkleTrieDBPrefix           = [2]byte{'M', 'K'}
	PubKeyRootHashMerkleTreeDBPrefix   = [2]byte{'R', 'K'}
	PubKeyBytesMerkleTrieDBPrefix      = [2]byte{'B', 'K'}
	BlockByHeightDBPrefix              = [2]byte{'B', 'H'}
	TransactionsHashesByHeightDBPrefix = [2]byte{'R', 'H'}
	MerkleTreeDBPrefix                 = [2]byte{'M', 'M'}
	MerkleNodeDBPrefix                 = [2]byte{'N', 'N'}
	RootHashMerkleTreeDBPrefix         = [2]byte{'R', 'R'}
	TransactionDBPrefix                = [2]byte{'T', 'T'}
	//StakingDBPrefix                    = [2]byte{'S', 'S'}
	TransactionPoolHashesDBPrefix    = [2]byte{'D', '0'}
	TransactionToSendHashesDBPrefix  = [2]byte{'E', '0'}
	TransactionSyncingHashesDBPrefix = [2]byte{'S', '0'}
	AccountsDBPrefix                 = [2]byte{'A', 'C'}
	StakingAccountsDBPrefix          = [2]byte{'S', 'A'}
	OutputLogsHashesDBPrefix         = [2]byte{'O', '0'}
	OutputLogDBPrefix                = [2]byte{'Z', '0'}
	OutputAddressesHashesDBPrefix    = [2]byte{'C', '0'}
	EVMStateDBPrefix                 = [2]byte{'E', 'V'}
	TokenDetailsDBPrefix             = [2]byte{'T', 'D'}
	DexAccountsDBPrefix              = [2]byte{'D', 'A'}
	BadTransactionDBPrefix           = [2]byte{'B', 'T'}
)

var chainID = int16(23)
var chainIDMutex = sync.Mutex{}
var nodeSignPrimary = false
var delegatedAccount Address
var rewardPercentage int16
var ShiftToPastInReset int64
var ShiftToPastMutex sync.RWMutex

func GetChainID() int16 {
	chainIDMutex.Lock()
	defer chainIDMutex.Unlock()
	return chainID
}

func SetChainID(chainid int16) {
	chainIDMutex.Lock()
	defer chainIDMutex.Unlock()
	chainID = chainid
}

func SetNodeSignPrimary(primary bool) {
	nodeSignPrimary = primary
}

func GetNodeSignPrimary(height int64) bool {
	if height == 0 {
		return true
	}
	if IsPaused() == false && IsPaused2() == false {
		if rand.Intn(2) == 0 {
			return true
		} else {
			return false
		}
	}
	//if nodeSignPrimary && (IsPaused() == false) {
	//	return true
	//}
	//if (nodeSignPrimary == false) && (IsPaused2() == false) {
	//	return false
	//}
	if IsPaused() == false {
		return true
	}
	if IsPaused2() == false {
		return false
	}
	return true
}

func GetDelegatedAccount() Address {
	return delegatedAccount
}

func GetMyRewardPercentage() int16 {
	return rewardPercentage
}

func init() {

	if !bytes.Equal(MessageInitialization[:], GetByteInt32(MaxMessageSizeBytes)) {
		logger.GetLogger().Fatal("set proper MessageInitialization that fit to MaxMessageSizeBytes. Must be: common.MessageInitialization == GetByteInt32(common.MaxMessageSizeBytes)", GetInt32FromByte(MessageInitialization[:]), GetByteInt32(MaxMessageSizeBytes))
	}
	enc1 := oqs.NewConfigEnc1()
	fmt.Print(enc1.ToString())
	enc2 := oqs.NewConfigEnc2()
	fmt.Print(enc2.ToString())

	SetEncryption(enc1.SigName, enc1.PubKeyLength, enc1.PrivateKeyLength, enc1.SignatureLength, enc1.IsPaused, true)
	SetEncryption(enc2.SigName, enc2.PubKeyLength, enc2.PrivateKeyLength, enc2.SignatureLength, enc2.IsPaused, false)

	//log.SetOutput(io.Discard)
	ShiftToPastInReset = 1
	homePath, err := os.UserHomeDir()
	if err != nil {
		logger.GetLogger().Fatal(err)
	}
	err = godotenv.Load(homePath + "/.qwid/.env")
	if err != nil {
		logger.GetLogger().Fatal("Error loading .env file", err)
	}
	da, err := strconv.Atoi(os.Getenv("DELEGATED_ACCOUNT"))
	if err != nil {
		logger.GetLogger().Fatal("Error getting DELEGATED_ACCOUNT")
	}
	delegatedAccount = GetDelegatedAccountAddress(int16(da))

	//DefaultPercentageReward int16 = 500 // 50 %
	v, err := strconv.Atoi(os.Getenv("REWARD_PERCENTAGE"))
	if err != nil {
		logger.GetLogger().Fatal("Error getting REWARD_PERCENTAGE")
	}
	rewardPercentage = int16(v)
	if rewardPercentage > 500 {
		logger.GetLogger().Fatal("reward for operational account has to be less than 50%")
	}
	ch, err := strconv.Atoi(os.Getenv("HEIGHT_OF_NETWORK"))
	if err != nil {
		logger.GetLogger().Panicln("Warning no declaration of HEIGHT_OF_NETWORK")
	} else {
		CurrentHeightOfNetwork = int64(ch)
	}
}
