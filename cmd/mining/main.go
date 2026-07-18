package main

import (
	_ "net/http/pprof"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/wonabru/qwid-node/blocks"
	"github.com/wonabru/qwid-node/database"
	"github.com/wonabru/qwid-node/logger"
	"github.com/wonabru/qwid-node/pubkeys"
	"github.com/wonabru/qwid-node/services"
	"github.com/wonabru/qwid-node/statistics"
	"github.com/wonabru/qwid-node/transactionsPool"
	"github.com/wonabru/qwid-node/wallet"
	"golang.org/x/term"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/genesis"
	serverrpc "github.com/wonabru/qwid-node/rpc/server"
	nonceService "github.com/wonabru/qwid-node/services/nonceService"
	syncServices "github.com/wonabru/qwid-node/services/syncService"
	"github.com/wonabru/qwid-node/services/transactionServices"
	"github.com/wonabru/qwid-node/tcpip"
)

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

	// Find peer IP argument (skip flags like -log)
	var peerIPArg string
	for _, arg := range os.Args[1:] {
		if !strings.HasPrefix(arg, "-") {
			peerIPArg = arg
			break
		}
	}

	if peerIPArg != "" {
		logger.GetLogger().Println("Processing command line arguments...")
		ips := strings.Split(peerIPArg, ".")
		if len(ips) != 4 {
			logger.GetLogger().Println("Invalid IP address format")
			return
		}
		var ip [4]byte
		for i := 0; i < 4; i++ {
			num, err := strconv.Atoi(ips[i])
			if err != nil {
				logger.GetLogger().Println("Invalid IP address segment:", ips[i])
				return
			}
			ip[i] = byte(num)
		}

		logger.GetLogger().Println("Connecting to peer:", ip)
		go nonceService.StartSubscribingNonceMsg(ip)
		go syncServices.StartSubscribingSyncMsg(ip)
		go transactionServices.StartSubscribingTransactionMsg(ip)
	}

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
