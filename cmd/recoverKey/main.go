// recoverKey runs hash-only key recovery (CLAUDE.md "Recovery commitment"):
//
//	recoverKey prepare -wallet N [-node IP]          print bind data for identity wallet N
//	recoverKey bind -wallet P -data HEX [-node IP]   send the bind from payer wallet P
//	recoverKey reveal -wallet N [-node IP]           send the reveal (after the bind matured)
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
	"github.com/qwid-org/qwid-node/services/transactionServices"
	"github.com/qwid-org/qwid-node/statistics"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/wallet"
	"golang.org/x/crypto/ssh/terminal"
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
	pass, err := readPassword()
	fmt.Println()
	if err != nil {
		logger.GetLogger().Fatal(err)
	}
	wallet.InitActiveWallet(n, string(pass), enc1.SigName, enc2.SigName)
	return wallet.GetActiveWallet()
}

// readPassword reads without echo from a terminal, or one line from a pipe
// (scripted runs, where there is no terminal to read from).
func readPassword() ([]byte, error) {
	if terminal.IsTerminal(0) {
		return terminal.ReadPassword(0)
	}
	line, err := bufio.NewReader(os.Stdin).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, err
	}
	return bytes.TrimRight(line, "\r\n"), nil
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
	st := &statistics.Stats{} // only the node's reply is read; no stats manager runs here
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

const maxRecoveryIndex = 1000

type recovery struct {
	slotPrimary bool
	newKey      common.PubKey
	secret      []byte
	next        common.Address
	bindData    []byte
}

// planRecovery works out everything both phases need, from the phrase and the
// node's PUBA answer only: which slot lacks a key of the current scheme, the
// wallet's key for it, the secret opening the effective commitment, and the
// commitment that replaces it.
func planRecovery(w *wallet.Wallet, keys wallet.RegisteredKeys) (recovery, error) {
	var r recovery
	switch {
	case !keys.HasPrimary:
		r.slotPrimary = true
		r.newKey = w.Account1.PublicKey
	case !keys.HasSecondary:
		r.newKey = w.Account2.PublicKey
	default:
		return r, fmt.Errorf("both slots already hold a key of the current scheme: nothing to recover")
	}
	if len(r.newKey.GetBytes()) == 0 {
		return r, fmt.Errorf("the wallet has no key for the slot to recover; load it with the current schemes")
	}
	var zero common.Address
	if keys.RecoveryCommit == zero {
		return r, fmt.Errorf("the identity has no effective recovery commitment")
	}
	n, err := w.FindRecoveryIndex(keys.RecoveryCommit, maxRecoveryIndex)
	if err != nil {
		return r, err
	}
	if r.secret, err = w.RecoverySecret(n); err != nil {
		return r, err
	}
	if r.next, err = w.RecoveryCommitmentAddress(n + 1); err != nil {
		return r, err
	}
	r.newKey.MainAddress = w.MainAddress
	tag, err := common.RecoveryTag(r.secret)
	if err != nil {
		return r, err
	}
	payload, err := common.RecoveryPayload(w.MainAddress, r.newKey.Address, r.next, r.secret)
	if err != nil {
		return r, err
	}
	r.bindData = transactionsDefinition.BuildRecoveryBindOptData(w.MainAddress, tag, payload)
	return r, nil
}
