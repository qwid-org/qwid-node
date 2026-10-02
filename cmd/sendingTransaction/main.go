package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	rand2 "math/rand"
	"os/signal"
	"sync"
	"syscall"

	"github.com/qwid-org/qwid-node/cmd/gui/qtwidgets"
	"github.com/therecipe/qt/widgets"
	"golang.org/x/crypto/ssh/terminal"

	"os"
	"time"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
	"github.com/qwid-org/qwid-node/services/transactionServices"
	"github.com/qwid-org/qwid-node/statistics"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/wallet"
)

var mutex sync.Mutex
var MainWallet *wallet.Wallet

var cfg loadConfig

func main() {
	var err error
	cfg, err = parseLoadArgs(os.Args[1:])
	if err != nil {
		fmt.Println(err)
		fmt.Println("usage: sendingTransaction -testnet -to <recipient hex> [-count N] [-workers N] [-node IP]")
		os.Exit(2)
	}
	ip := cfg.node
	go clientrpc.ConnectRPC(ip)
	fmt.Print("Enter password: ")
	password, err := terminal.ReadPassword(0)
	if err != nil {
		logger.GetLogger().Fatal(err)
	}
	sigName, sigName2, err := qtwidgets.SetCurrentEncryptions()
	if err != nil {
		widgets.QMessageBox_Information(nil, "Warning", "error with retrieving current encryption", widgets.QMessageBox__Ok, widgets.QMessageBox__Ok)
	}
	wallet.InitActiveWallet(0, string(password), sigName, sigName2)
	MainWallet = wallet.GetActiveWallet()

	var wg sync.WaitGroup
	for range cfg.workers {
		wg.Add(1)
		go func() { defer wg.Done(); sendTransactions(MainWallet, cfg.count) }()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	// Handle Ctrl+C gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigChan:
		fmt.Println("\nShutting down...")
	case <-done:
		fmt.Println("all transactions sent")
	}
}

func SignMessage(line []byte) []byte {

	operation := string(line[0:4])
	verificationNeeded := true
	for _, noVerification := range common.ConnectionsWithoutVerification {
		if bytes.Equal([]byte(operation), noVerification) {
			verificationNeeded = false
			break
		}
	}
	if verificationNeeded {
		if MainWallet == nil || (!MainWallet.Check() || !MainWallet.Check2()) {
			logger.GetLogger().Println("wallet not loaded yet")
			return line
		}
		if common.IsPaused() == false {
			// primary encryption used
			line = common.BytesToLenAndBytes(line)
			sign, err := MainWallet.Sign(line, true)
			if err != nil {
				logger.GetLogger().Println(err)
				return line
			}
			line = append(line, sign.GetBytes()...)

		} else {
			// secondary encryption
			line = common.BytesToLenAndBytes(line)
			sign, err := MainWallet.Sign(line, false)
			if err != nil {
				logger.GetLogger().Println(err)
				return line
			}
			line = append(line, sign.GetBytes()...)
		}
	} else {
		line = common.BytesToLenAndBytes(line)
	}
	return line
}

func SampleTransaction(w *wallet.Wallet) transactionsDefinition.Transaction {
	mutex.Lock()
	defer mutex.Unlock()
	sender := w.MainAddress
	recv := cfg.recipient
	var err error
	amount := int64(rand2.Intn(1000000000))
	txdata := transactionsDefinition.TxData{
		Recipient: recv,
		Amount:    amount,
		OptData:   nil,
		Pubkey:    common.PubKey{}, //w.Account1.PublicKey,
	}
	txParam := transactionsDefinition.TxParam{
		ChainID:     common.GetChainID(),
		Sender:      sender,
		SendingTime: common.GetCurrentTimeStampInSecond(),
		Nonce:       int64(rand2.Intn(65000)),
	}
	t := transactionsDefinition.Transaction{
		TxData:    txdata,
		TxParam:   txParam,
		Hash:      common.Hash{},
		Signature: common.Signature{},
		Height:    0,
		GasPrice:  int64(rand2.Intn(0x0000000f) + 1),
		GasUsage:  0,
	}
	t.GasUsage = t.GasUsageEstimate()

	clientrpc.InRPC <- SignMessage([]byte("STAT"))
	var reply []byte
	reply = <-clientrpc.OutRPC
	st := statistics.Stats{}
	err = common.Unmarshal(reply, common.StatDBPrefix, &st)
	if err != nil {
		return transactionsDefinition.Transaction{}
	}
	t.Height = st.Height

	err = t.CalcHashAndSet()
	if err != nil {
		logger.GetLogger().Println("calc hash error", err)
	}
	// Sign with the scheme that is LIVE, not always the primary. A hardcoded
	// "true" produced transactions signed with a paused algorithm the moment the
	// chain paused its primary scheme — every one of them rejected, with nothing
	// in this tool's output to say why.
	err = t.Sign(w, !common.IsPaused())
	if err != nil {
		logger.GetLogger().Println("Signing error", err)
	}
	//s := rand.RandomBytes(common.SignatureLength)
	//sig := common.Signature{}
	//err = sig.Init(s, w.Address)
	//if err != nil {
	//	return transactionsDefinition.Transaction{}
	//}
	//t.Signature = sig
	return t
}

func sendTransactions(w *wallet.Wallet, total int64) {

	batchSize := 1
	count := int64(0)
	start := common.GetCurrentTimeStampInSecond()
	for range time.Tick(time.Millisecond * 100) {
		if count >= total {
			return
		}
		// Re-read the chain's schemes each cycle: this tool runs for a long time
		// and the chain can pause or replace a scheme underneath it, after which
		// everything it signs would be rejected.
		if _, _, err := qtwidgets.SetCurrentEncryptions(); err != nil {
			logger.GetLogger().Println("could not refresh encryption config:", err)
		}
		var txs []transactionsDefinition.Transaction
		for i := 0; i < batchSize; i++ {
			tx := SampleTransaction(w)
			txs = append(txs, tx)
			end := common.GetCurrentTimeStampInSecond()
			count++
			if count%1 == 0 && (end-start) > 0 {
				fmt.Println("tps=", count/(end-start), " count: ", count)
			}
		}
		m, err := transactionServices.GenerateTransactionMsg(txs, []byte("tx"), [2]byte{'T', 'T'})
		if err != nil {
			return
		}
		tmm := m.GetBytes()
		//count += int64(batchSize)
		clientrpc.InRPC <- SignMessage(append([]byte("TRAN"), tmm...))
		//logger.GetLogger().Printf("send batch %d transactions", batchSize)
		<-clientrpc.OutRPC
		//logger.GetLogger().Println("transactions sent")
	}
}

// loadConfig is the load tool's run: it spends the node wallet's funds, so
// the recipient, a finite count and a typed testnet acknowledgement are all
// required (S10-03) - it used to send to a hardcoded address forever.
type loadConfig struct {
	recipient common.Address
	count     int64
	workers   int
	node      string
}

func parseLoadArgs(args []string) (loadConfig, error) {
	fs := flag.NewFlagSet("sendingTransaction", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	to := fs.String("to", "", "recipient address (hex, 20 bytes)")
	count := fs.Int64("count", 100, "transactions per worker")
	workers := fs.Int("workers", 1, "parallel workers")
	node := fs.String("node", "127.0.0.1", "node RPC address")
	testnet := fs.Bool("testnet", false, "acknowledge this spends wallet 0 funds on a test network")
	if err := fs.Parse(args); err != nil {
		return loadConfig{}, err
	}
	if !*testnet {
		return loadConfig{}, fmt.Errorf("refusing to run without -testnet: this tool spends wallet 0's funds")
	}
	b, err := hex.DecodeString(*to)
	if err != nil || len(b) != common.AddressLength {
		return loadConfig{}, fmt.Errorf("-to must be a %d-byte hex address", common.AddressLength)
	}
	if *count <= 0 || *workers <= 0 {
		return loadConfig{}, fmt.Errorf("-count and -workers must be positive")
	}
	recv, err := common.BytesToAddress(b)
	if err != nil {
		return loadConfig{}, err
	}
	return loadConfig{recipient: recv, count: *count, workers: *workers, node: *node}, nil
}
