package main

import (
	"bytes"
	"fmt"
	rand2 "math/rand"
	"os/signal"
	"strconv"
	"sync"
	"syscall"

	"github.com/therecipe/qt/widgets"
	"github.com/qwid-org/qwid-node/cmd/gui/qtwidgets"
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

func main() {
	var num int
	var err error
	var ip string
	if len(os.Args) > 1 {
		num, err = strconv.Atoi(os.Args[1])
		if err != nil {
			logger.GetLogger().Fatalln("Argument need to be int")
		}
	} else {
		num = 1
	}
	if len(os.Args) > 2 {
		ip = os.Args[2]
	} else {
		ip = "127.0.0.1"
	}
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

	for range num {
		go sendTransactions(MainWallet)
		//time.Sleep(time.Millisecond * 1)
	}

	// Handle Ctrl+C gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	fmt.Println("\nShutting down...")
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
	recv := common.Address{}
	br := common.Hex2Bytes("5b21c69aaea1ddd18bd17ad6f23f109479cca304")
	//br := rand.RandomBytes(20)
	err := recv.Init(append([]byte{0}, br...))
	if err != nil {
		return transactionsDefinition.Transaction{}
	}
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

func sendTransactions(w *wallet.Wallet) {

	batchSize := 1
	count := int64(0)
	start := common.GetCurrentTimeStampInSecond()
	for range time.Tick(time.Millisecond * 1) {
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
