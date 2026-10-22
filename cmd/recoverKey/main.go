// recoverKey runs hash-only key recovery (CLAUDE.md "Recovery commitment"):
//
//	recoverKey prepare -wallet N [-node IP]          print bind data for identity wallet N
//	recoverKey bind -wallet P -data HEX [-node IP]   send the bind from payer wallet P
//	recoverKey reveal -wallet N [-node IP]           send the reveal (after the bind matured)
package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
	"github.com/qwid-org/qwid-node/services/transactionServices"
	"github.com/qwid-org/qwid-node/statistics"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/wallet"
)

func main() {
	logger.InitLogger()
	defer logger.CloseLogger()
	if len(os.Args) < 2 {
		usage()
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	num := fs.Int("wallet", -1, "wallet number")
	data := fs.String("data", "", "bind data hex (bind only)")
	node := fs.String("node", "127.0.0.1", "node IP")
	_ = fs.Parse(os.Args[2:])
	if *num < 0 || *num > 255 {
		usage()
	}
	go clientrpc.ConnectRPC(*node)
	time.Sleep(time.Second)
	w := loadWallet(uint8(*num))
	var err error
	switch os.Args[1] {
	case "prepare":
		err = prepare(w)
	case "bind":
		err = bind(w, *data)
	case "reveal":
		err = reveal(w)
	default:
		usage()
	}
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println("usage: recoverKey prepare|bind|reveal -wallet N [-data HEX] [-node IP]")
	os.Exit(2)
}

func noWallet(cmd string, arg []byte) []byte {
	return clientrpc.Call(common.BytesToLenAndBytes(append([]byte(cmd), arg...)))
}

func loadWallet(n uint8) *wallet.Wallet {
	reply := noWallet("ENCR", nil)
	enc1b, left, err := common.BytesWithLenToBytes(reply)
	if err != nil {
		logger.GetLogger().Fatal("cannot read encryption from node: ", err)
	}
	enc2b, _, err := common.BytesWithLenToBytes(left)
	if err != nil {
		logger.GetLogger().Fatal(err)
	}
	enc1, err := blocks.FromBytesToEncryptionConfig(enc1b, true)
	if err != nil {
		logger.GetLogger().Fatal(err)
	}
	enc2, err := blocks.FromBytesToEncryptionConfig(enc2b, false)
	if err != nil {
		logger.GetLogger().Fatal(err)
	}
	common.SetEncryption(enc1.SigName, enc1.PubKeyLength, enc1.PrivateKeyLength, enc1.SignatureLength, enc1.IsPaused, true)
	common.SetEncryption(enc2.SigName, enc2.PubKeyLength, enc2.PrivateKeyLength, enc2.SignatureLength, enc2.IsPaused, false)
	fmt.Printf("Password for wallet %d: ", n)
	pass, err := terminal.ReadPassword(0)
	fmt.Println()
	if err != nil {
		logger.GetLogger().Fatal(err)
	}
	wallet.InitActiveWallet(n, string(pass), enc1.SigName, enc2.SigName)
	return wallet.GetActiveWallet()
}

func keysOf(w *wallet.Wallet) (wallet.RegisteredKeys, error) {
	return wallet.ParsePUBA(noWallet("PUBA", w.MainAddress.GetBytes()))
}

func prepare(w *wallet.Wallet) error {
	keys, err := keysOf(w)
	if err != nil {
		return err
	}
	p, err := planRecovery(w, keys)
	if err != nil {
		return err
	}
	fmt.Println("identity:", w.MainAddress.GetHex())
	fmt.Println("bind data (pass to 'bind' with a funded payer wallet):")
	fmt.Println(hex.EncodeToString(p.bindData))
	fmt.Printf("then wait %d blocks after the bind is included and run 'reveal'\n", common.RecoveryBindDelayBlocks)
	return nil
}

func bind(payer *wallet.Wallet, dataHex string) error {
	opt, err := hex.DecodeString(dataHex)
	if err != nil {
		return err
	}
	if _, _, _, err := transactionsDefinition.ParseRecoveryBind(opt); err != nil {
		return err
	}
	tx := newTx(payer.MainAddress, common.RecoveryBindAddress, opt, common.PubKey{})
	return signAndSend(payer, &tx, !common.IsPaused())
}

func reveal(w *wallet.Wallet) error {
	keys, err := keysOf(w)
	if err != nil {
		return err
	}
	p, err := planRecovery(w, keys)
	if err != nil {
		return err
	}
	tx := newTx(w.MainAddress, common.RecoveryRevealAddress,
		transactionsDefinition.BuildRecoveryRevealOptData(p.secret, p.next), p.newKey)
	return signAndSend(w, &tx, p.slotPrimary)
}

func newTx(sender, recipient common.Address, opt []byte, pk common.PubKey) transactionsDefinition.Transaction {
	return transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: sender,
			SendingTime: common.GetCurrentTimeStampInSecond(), Nonce: common.RandomNonce()},
		TxData:   transactionsDefinition.TxData{Recipient: recipient, OptData: opt, Pubkey: pk},
		GasPrice: 1,
	}
}

func signAndSend(w *wallet.Wallet, tx *transactionsDefinition.Transaction, primary bool) error {
	st := statistics.GetStatsManager().Stats
	if err := common.Unmarshal(noWallet("STAT", nil), common.StatDBPrefix, &st); err != nil {
		return fmt.Errorf("cannot read node height: %w", err)
	}
	tx.Height = st.Height
	tx.GasUsage = tx.GasUsageEstimate()
	if err := tx.CalcHashAndSet(); err != nil {
		return err
	}
	if err := tx.Sign(w, primary); err != nil {
		return err
	}
	msg, err := transactionServices.GenerateTransactionMsg([]transactionsDefinition.Transaction{*tx}, []byte("tx"), [2]byte{'T', 'T'})
	if err != nil {
		return err
	}
	reply := noWallet("TRAN", msg.GetBytes())
	if !bytes.Equal(reply, []byte("transaction sent")) {
		return fmt.Errorf("node refused: %s", reply)
	}
	fmt.Println("sent:", tx.Hash.GetHex())
	return nil
}
