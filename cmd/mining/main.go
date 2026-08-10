package main

import (
	"fmt"
	_ "net/http/pprof"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/pubkeys"
	"github.com/qwid-org/qwid-node/services"
	"github.com/qwid-org/qwid-node/statistics"
	"github.com/qwid-org/qwid-node/transactionsPool"
	"github.com/qwid-org/qwid-node/wallet"
	"golang.org/x/term"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/genesis"
	serverrpc "github.com/qwid-org/qwid-node/rpc/server"
	nonceService "github.com/qwid-org/qwid-node/services/nonceService"
	syncServices "github.com/qwid-org/qwid-node/services/syncService"
	"github.com/qwid-org/qwid-node/services/transactionServices"
	"github.com/qwid-org/qwid-node/tcpip"
)

// shutdownLockWait bounds how long a shutdown store waits for the block lock.
const shutdownLockWait = 3 * time.Second

// lockBlocksForShutdown takes common.BlockMutex for a shutdown store, but only
// if it becomes free quickly. The lock matters because Store*(-1) writes the
// live state under common.GetHeight(): running it while a block is being applied
// would persist a half-applied state as that height's snapshot, and the node
// would then reject every following block on the supply invariant. Waiting for
// it unconditionally is just as wrong - a sync batch holds the lock for its
// whole run, so Ctrl-C would appear to hang. Skipping the store is safe: every
// applied block already wrote its own snapshot.
func lockBlocksForShutdown(what string) bool {
	deadline := time.Now().Add(shutdownLockWait)
	for {
		if common.BlockMutex.TryLock() {
			return true
		}
		if time.Now().After(deadline) {
			logger.GetLogger().Println("a block is still being applied - skipping the shutdown store of",
				what, "; the snapshot of the last applied block stands")
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func main() {
	var err error
	// Check for -log flag to enable logging
	logger.LoggingEnabled = false
	for _, arg := range os.Args[1:] {
		if arg == "-log" || arg == "--log" {
			logger.LoggingEnabled = true
			break
		}
	}
	logger.InitLogger()
	defer logger.CloseLogger()
	database.InitDB()
	defer database.CloseDB()
	pubkeys.InitTrie()
	// Now you can use log functions as usual
	logger.GetLogger().Println("Application started")
	logger.GetLogger().Println("Password:")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		logger.GetLogger().Fatal(err)
	}
	// Initialize wallet
	logger.GetLogger().Println("Initializing wallet...")
	wallet.InitActiveWallet(0, string(password), common.SigName(), common.SigName2())

	// Initialize genesis block
	logger.GetLogger().Println("Initializing genesis block for setting init params...")
	genesis.InitGenesis(false)

	// Load accounts
	logger.GetLogger().Println("Loading accounts...")
	err = account.LoadAccounts(-1)
	if err != nil {
		addrbytes := [common.AddressLength]byte{}
		copy(addrbytes[:], wallet.GetActiveWallet().Account1.Address.GetBytes())
		// Initialize accounts
		a := account.Account{
			Balance:               0,
			Address:               addrbytes,
			TransactionDelay:      0,
			MultiSignNumber:       0,
			MultiSignAddresses:    make([][20]byte, 0),
			TransactionsSender:    make([]common.Hash, 0),
			TransactionsRecipient: make([]common.Hash, 0),
		}
		allAccounts := map[[20]byte]account.Account{}
		allAccounts[addrbytes] = a
		account.Accounts = account.AccountsType{AllAccounts: allAccounts}
		err = account.StoreAccounts(0)
		if err != nil {
			logger.GetLogger().Fatal("Failed to store accounts:", err)
		}

		// Initialize DEX accounts
		logger.GetLogger().Println("Initializing DEX accounts...")
		allDexAccounts := map[[20]byte]account.DexAccount{}
		account.DexAccounts = account.DexAccountsType{AllDexAccounts: allDexAccounts}
		err = account.StoreDexAccounts(0)
		if err != nil {
			logger.GetLogger().Fatal("Failed to store DEX accounts:", err)
		}

		// Initialize staking accounts
		logger.GetLogger().Println("Setting up staking accounts...")
		for i := 1; i < 256; i++ {
			del := common.GetDelegatedAccountAddress(int16(i))
			delbytes := [common.AddressLength]byte{}
			copy(delbytes[:], del.GetBytes())
			sa := account.StakingAccount{
				StakedBalance:    0,
				StakingRewards:   0,
				DelegatedAccount: delbytes,
				StakingDetails:   nil,
			}
			allStakingAccounts := map[[20]byte]account.StakingAccount{}
			allStakingAccounts[addrbytes] = sa
			account.StakingAccounts[i] = account.StakingAccountsType{AllStakingAccounts: allStakingAccounts}
		}
		err = account.StoreStakingAccounts(0)
		if err != nil {
			logger.GetLogger().Fatal("Failed to store staking accounts:", err)
		}
	}

	// Load accounts
	logger.GetLogger().Println("Loading accounts...")
	err = account.LoadAccounts(-1)
	if err != nil {
		logger.GetLogger().Fatal("Failed to load accounts:", err)
	}
	defer func() {
		common.IsSyncing.Store(true)
		logger.GetLogger().Println("Storing accounts...")
		if !lockBlocksForShutdown("accounts") {
			return
		}
		defer common.BlockMutex.Unlock()
		account.StoreAccounts(-1)
	}()

	// Load DEX accounts
	logger.GetLogger().Println("Loading DEX accounts...")
	err = account.LoadDexAccounts(-1)
	if err != nil {
		logger.GetLogger().Fatal("Failed to load DEX accounts:", err)
	}
	defer func() {
		common.IsSyncing.Store(true)
		logger.GetLogger().Println("Storing DEX accounts...")
		if !lockBlocksForShutdown("DEX accounts") {
			return
		}
		defer common.BlockMutex.Unlock()
		account.StoreDexAccounts(-1)
	}()

	// Load staking accounts
	logger.GetLogger().Println("Loading staking accounts...")
	err = account.LoadStakingAccounts(-1)
	if err != nil {
		logger.GetLogger().Fatal("Failed to load staking accounts:", err)
	}
	defer func() {
		common.IsSyncing.Store(true)
		logger.GetLogger().Println("Storing staking accounts...")
		if !lockBlocksForShutdown("staking accounts") {
			return
		}
		defer common.BlockMutex.Unlock()
		account.StoreStakingAccounts(-1)
	}()

	// Initialize state database
	logger.GetLogger().Println("Initializing state database...")
	blocks.InitStateDB()

	// Initialize transaction pool and merkle tree
	logger.GetLogger().Println("Initializing transaction pool and merkle tree...")
	transactionsPool.InitPermanentTrie()
	defer transactionsPool.GlobalMerkleTree.Destroy()

	// Initialize statistics
	statistics.InitStatsManager()

	// Restore pending escrow transactions so a restart between an escrow's
	// acceptance and its maturity still settles it (avoids consensus divergence).
	if err := transactionsPool.LoadEscrowPoolFromDB(); err != nil {
		logger.GetLogger().Println("could not load persisted escrow pool", err)
	}
	// Same for pending multisig transfers: the pool accumulates the main tx and
	// its confirmations across an arbitrary number of blocks, and a restart
	// that emptied it made any later confirmation-carrying block unappliable
	// ("no main transaction in multi signature pool").
	if err := transactionsPool.LoadMultiSignPoolFromDB(); err != nil {
		logger.GetLogger().Println("could not load persisted multisig pool", err)
	}

	//Load Main Blockchain
	services.SetBlockHeightAfterCheck()

	if common.GetHeight() < 0 {
		// Initialize genesis block
		logger.GetLogger().Println("Initializing genesis block with processing transactions...")
		genesis.InitGenesis(true)
	}

	// Initialize services
	logger.GetLogger().Println("Initializing transaction service...")
	transactionServices.InitTransactionService()

	logger.GetLogger().Println("Initializing sync service...")
	syncServices.InitSyncService()

	logger.GetLogger().Println("Starting RPC server...")
	go serverrpc.ListenRPC()

	logger.GetLogger().Println("Initializing nonce service...")
	nonceService.InitNonceService()
	go nonceService.StartSubscribingNonceMsgSelf()
	go nonceService.StartSubscribingNonceMsg(tcpip.MyIP)

	go transactionServices.StartSubscribingTransactionMsg(tcpip.MyIP)
	go syncServices.StartSubscribingSyncMsg(tcpip.MyIP)

	time.Sleep(time.Second)

	// Bootstrap peers from the command line (flags like -log are skipped).
	bootstrapPeers, err := parsePeerIPs(os.Args[1:])
	if err != nil {
		logger.GetLogger().Println(err)
		return
	}
	bootstrapDialer := newDialer()

	if len(bootstrapPeers) > 0 {
		logger.GetLogger().Println("Connecting to bootstrap peers:", bootstrapPeers)
		for _, ip := range bootstrapPeers {
			bootstrapDialer.connectToPeer(ip)
		}
	}

	// Keep re-dialling them for as long as the node runs. Peer discovery travels
	// inside 'hi' messages, which need a live connection to arrive, so once every
	// connection drops nothing reconnects on its own.
	go keepBootstrapPeersConnected(bootstrapPeers, bootstrapDialer)

	time.Sleep(time.Second)

	logger.GetLogger().Println("Starting peer discovery...")
	go tcpip.LookUpForNewPeersToConnect(tcpip.ChanPeer)
	topic := [2]byte{}
	ip := [4]byte{}
	lastReconnect := make(map[[6]byte]time.Time)
	reconnectCooldown := 10 * time.Second

	logger.GetLogger().Println("Entering main loop...")
QF:
	for {
		select {

		case topicip := <-tcpip.ChanPeer:
			copy(topic[:], topicip[:2])
			copy(ip[:], topicip[2:])
			var key [6]byte
			copy(key[:], topicip[:6])
			if time.Since(lastReconnect[key]) < reconnectCooldown {
				logger.GetLogger().Printf("Reconnect cooldown for %c%c %v, skipping", topic[0], topic[1], ip)
				continue
			}
			lastReconnect[key] = time.Now()
			if topic[0] == 'T' {
				go transactionServices.StartSubscribingTransactionMsg(ip)
			}
			if topic[0] == 'N' {
				go nonceService.StartSubscribingNonceMsg(ip)
			}
			if topic[0] == 'S' {
				go nonceService.StartSubscribingNonceMsgSelf()
			}
			if topic[0] == 'B' {
				go syncServices.StartSubscribingSyncMsg(ip)
			}

		case <-tcpip.Quit:
			logger.GetLogger().Println("Received quit signal, shutting down...")
			break QF
		}
	}

}

// bootstrapRetryInterval is how often the node checks whether it still has a way
// into the network.
const bootstrapRetryInterval = 15 * time.Second

// parsePeerIPs extracts bootstrap peer addresses from the command line. Flags
// (anything starting with "-") are skipped; every remaining argument may hold one
// address or a comma-separated list, so both of these work:
//
//	mining 1.2.3.4
//	mining 1.2.3.4,5.6.7.8 9.10.11.12
//
// An unparsable address is an error rather than a silent skip: a typo in the only
// way back into the network should not look like success.
func parsePeerIPs(args []string) ([][4]byte, error) {
	var out [][4]byte
	seen := map[[4]byte]bool{}

	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		for _, field := range strings.Split(arg, ",") {
			field = strings.TrimSpace(field)
			if field == "" {
				continue
			}
			ip, err := parseIPv4(field)
			if err != nil {
				return nil, err
			}
			if seen[ip] {
				continue
			}
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out, nil
}

func parseIPv4(s string) ([4]byte, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return [4]byte{}, fmt.Errorf("nieprawidłowy adres IP %q: oczekiwano czterech części", s)
	}
	var ip [4]byte
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return [4]byte{}, fmt.Errorf("nieprawidłowa część adresu IP %q w %q", p, s)
		}
		ip[i] = byte(n)
	}
	return ip, nil
}

// dialer serializes redial attempts so a peer that is slow or unreachable does
// not accumulate one blocked goroutine per retry interval. Each
// StartSubscribing* call runs until its connection ends, so without this a peer
// that never answers would leak goroutines for as long as the node runs.
type dialer struct {
	mu       sync.Mutex
	inFlight map[string]bool
}

func newDialer() *dialer {
	return &dialer{inFlight: map[string]bool{}}
}

// run starts fn in the background unless a call with the same key is still
// running. Reports whether it started one.
func (d *dialer) run(key string, fn func()) bool {
	d.mu.Lock()
	if d.inFlight[key] {
		d.mu.Unlock()
		return false
	}
	d.inFlight[key] = true
	d.mu.Unlock()

	go func() {
		defer func() {
			d.mu.Lock()
			delete(d.inFlight, key)
			d.mu.Unlock()
		}()
		fn()
	}()
	return true
}

// connectToPeer opens the nonce, sync and transaction subscriptions to one peer.
func (d *dialer) connectToPeer(ip [4]byte) {
	if tcpip.IsIPBanned(ip) {
		logger.GetLogger().Printf("bootstrap peer %v is banned, skipping", ip)
		return
	}
	d.run(fmt.Sprintf("N%v", ip), func() { nonceService.StartSubscribingNonceMsg(ip) })
	d.run(fmt.Sprintf("B%v", ip), func() { syncServices.StartSubscribingSyncMsg(ip) })
	d.run(fmt.Sprintf("T%v", ip), func() { transactionServices.StartSubscribingTransactionMsg(ip) })
}

// needsBootstrap reports whether the node has lost its way into the network.
// Peer discovery travels inside 'hi' messages, which need a live connection to
// arrive — so once every connection drops, nothing reconnects on its own and the
// command-line peers are the only route back.
//
// The self-connection does not count. It is present on the sync topic even on a
// node that is completely alone, and counting it made this check answer "we are
// connected" while the only chain data reaching us was our own.
func needsBootstrap() bool {
	return tcpip.GetPeersCount() == 0 || tcpip.CountPeersOnTopic(tcpip.SyncTopic) == 0
}

// keepBootstrapPeersConnected re-dials the command-line peers whenever the node
// has no usable connection left. It never gives up: a node that is down for an
// hour must rejoin by itself when the link comes back.
func keepBootstrapPeersConnected(peers [][4]byte, d *dialer) {
	if len(peers) == 0 {
		logger.GetLogger().Println("no bootstrap peers given on the command line - " +
			"this node cannot rejoin the network on its own if every connection drops")
		return
	}
	for {
		time.Sleep(bootstrapRetryInterval)
		if !needsBootstrap() {
			continue
		}
		logger.GetLogger().Printf("no usable peer connection - re-dialling %d bootstrap peer(s) from the command line", len(peers))
		for _, ip := range peers {
			d.connectToPeer(ip)
		}
	}
}
