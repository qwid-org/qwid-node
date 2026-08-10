package qtwidgets

import (
	"encoding/hex"
	"fmt"
	"github.com/wonabru/qwid-node/common"
	clientrpc "github.com/wonabru/qwid-node/rpc/client"
	"github.com/wonabru/qwid-node/services/transactionServices"
	"github.com/wonabru/qwid-node/statistics"
	"github.com/wonabru/qwid-node/transactionsDefinition"
	"github.com/therecipe/qt/widgets"
	"golang.org/x/exp/rand"
	"math"
	"strconv"
)

var ChainID = int16(23)
var SmartContractData *widgets.QTextEdit
var Recipient *widgets.QLineEdit
var Amount *widgets.QLineEdit
var LockedAmount *widgets.QLineEdit
var ReleasePerBlock *widgets.QLineEdit
var DelegatedAccountForLocking *widgets.QLineEdit
var hashMultiSigTx *widgets.QLineEdit
var hashTx *widgets.QLineEdit

func ShowSendPage() *widgets.QTabWidget {

	// create a regular widget
	// give it a QVBoxLayout
	// and make it the central widget of the window
	widget := widgets.NewQTabWidget(nil)
	widget.SetLayout(widgets.NewQVBoxLayout())

	// create a line edit
	// with a custom placeholder text
	// and add it to the central widgets layout
	Recipient = widgets.NewQLineEdit(nil)
	Recipient.SetPlaceholderText("Address")
	widget.Layout().AddWidget(Recipient)

	Amount = widgets.NewQLineEdit(nil)
	Amount.SetPlaceholderText("Amount")
	widget.Layout().AddWidget(Amount)

	LockedAmount = widgets.NewQLineEdit(nil)
	LockedAmount.SetPlaceholderText("Locked Amount")
	LockedAmount.SetText("0")
	widget.Layout().AddWidget(LockedAmount)

	ReleasePerBlock = widgets.NewQLineEdit(nil)
	ReleasePerBlock.SetPlaceholderText("Released amount per Block")
	ReleasePerBlock.SetText("0")
	widget.Layout().AddWidget(ReleasePerBlock)

	DelegatedAccountForLocking = widgets.NewQLineEdit(nil)
	DelegatedAccountForLocking.SetPlaceholderText("Delegated Account For Locking")
	DelegatedAccountForLocking.SetText("1")
	widget.Layout().AddWidget(DelegatedAccountForLocking)

	hashMultiSigTx = widgets.NewQLineEdit(nil)
	hashMultiSigTx.SetPlaceholderText("Hash transaction to multi signature confirmation")
	widget.Layout().AddWidget(hashMultiSigTx)

	SmartContractData = widgets.NewQTextEdit(nil)
	SmartContractData.SetPlaceholderText("Smart Contract Data")
	widget.Layout().AddWidget(SmartContractData)

	pubkeyInclude := widgets.NewQCheckBox(nil)
	pubkeyInclude.SetText("Public key include in transaction")
	widget.Layout().AddWidget(pubkeyInclude)
	primaryChb := widgets.NewQCheckBox(nil)
	primaryChb.SetText("Use primary encryption")
	primaryChb.SetChecked(true)
	widget.Layout().AddWidget(primaryChb)
	// connect the clicked signal
	// and add it to the central widgets layout
	button := widgets.NewQPushButton2("Send", nil)
	button.ConnectClicked(func(bool) {
		var info *string
		v := "Transaction sent"
		info = &v
		defer func(nfo *string) {
			widgets.QMessageBox_Information(nil, "Info", *nfo, widgets.QMessageBox__Ok, widgets.QMessageBox__Ok)
		}(info)

		if !MainWallet.Check() {
			v = fmt.Sprint("Load wallet first")
			info = &v
			return
		}
		ar := common.Address{}
		if len(Recipient.Text()) < 20 {
			i, err := strconv.Atoi(Recipient.Text())
			if err != nil || i > 255 {
				v = fmt.Sprint(err)
				info = &v
				return
			}
			ar = common.GetDelegatedAccountAddress(int16(i))
		} else {

			bar, err := hex.DecodeString(Recipient.Text())
			if err != nil {
				v = fmt.Sprint(err)
				info = &v
				return
			}
			err = ar.Init(bar)
			if err != nil {
				v = fmt.Sprint(err)
				info = &v
				return
			}
		}
		af, err := strconv.ParseFloat(Amount.Text(), 64)
		if err != nil {
			v = fmt.Sprint(err)
			info = &v
			return
		}
		if af < 0 {
			v = fmt.Sprint("Send Amount cannot be negative")
			info = &v
			return
		}
		am := int64(af * math.Pow10(int(common.Decimals)))
		if float64(am) != af*math.Pow10(int(common.Decimals)) {
			v = fmt.Sprint("Precision for amount needs to be not larger than", common.Decimals, " digits")
			info = &v
			return
		}

		laf, err := strconv.ParseFloat(LockedAmount.Text(), 64)
		if err != nil {
			v = fmt.Sprint(err)
			info = &v
			return
		}
		if laf < 0 {
			v = fmt.Sprint("Locked Amount cannot be negative")
			info = &v
			return
		}
		if laf > af {
			v = fmt.Sprint("Locked Amount cannot be larger than Amount")
			info = &v
			return
		}
		lam := int64(laf * math.Pow10(int(common.Decimals)))
		if float64(lam) != laf*math.Pow10(int(common.Decimals)) {
			v = fmt.Sprint("Precision for locked amount needs to be not larger than", common.Decimals, " digits")
			info = &v
			return
		}

		rlaf, err := strconv.ParseFloat(ReleasePerBlock.Text(), 64)
		if err != nil {
			v = fmt.Sprint(err)
			info = &v
			return
		}
		if rlaf < 0 {
			v = fmt.Sprint("Release per block of locked amount cannot be negative")
			info = &v
			return
		}
		if rlaf > laf {
			v = fmt.Sprint("Released per block cannot be larger than locked Amount")
			info = &v
			return
		}
		rlam := int64(rlaf * math.Pow10(int(common.Decimals)))
		if float64(rlam) != rlaf*math.Pow10(int(common.Decimals)) {
			v = fmt.Sprint("Precision for release per block needs to be not larger than", common.Decimals, " digits")
			info = &v
			return
		}

		lar := common.Address{}
		if len(DelegatedAccountForLocking.Text()) < 20 {
			i, err := strconv.Atoi(DelegatedAccountForLocking.Text())
			if err != nil || i > 255 {
				v = fmt.Sprint(err)
				info = &v
				return
			}
			lar = common.GetDelegatedAccountAddress(int16(i))
		} else {

			bar, err := hex.DecodeString(DelegatedAccountForLocking.Text())
			if err != nil {
				v = fmt.Sprint(err)
				info = &v
				return
			}
			err = lar.Init(bar)
			if err != nil {
				v = fmt.Sprint(err)
				info = &v
				return
			}
		}

		hashms := common.Hash{}
		if hashMultiSigTx.Text() != "" {
			har, err := hex.DecodeString(hashMultiSigTx.Text())
			if err != nil {
				v = fmt.Sprint(err)
				info = &v
				return
			}
			if len(har) != common.HashLength {
				v = fmt.Sprint("hash should be 32 bytes, so 64 letters in Hex format")
				info = &v
				return
			}
			hashms.Set(har)
		}
		optData := SmartContractData.ToPlainText()

		scData := []byte{}
		if len(optData) > 0 {
			scData, err = hex.DecodeString(optData)
			if err != nil {
				scData = []byte{}
			}
		}

		pk := common.PubKey{}
		if pubkeyInclude.IsChecked() {
			if primaryChb.IsChecked() {
				pk = MainWallet.Account1.PublicKey
				primary = true
			} else {
				pk = MainWallet.Account2.PublicKey
				primary = false
			}
		} else {
			if primaryChb.IsChecked() {
				primary = true
			} else {
				primary = false
			}
		}

		txd := transactionsDefinition.TxData{
			Recipient:                  ar,
			Amount:                     am,
			OptData:                    scData,
			Pubkey:                     pk,
			LockedAmount:               lam,
			ReleasePerBlock:            rlam,
			DelegatedAccountForLocking: lar,
		}
		par := transactionsDefinition.TxParam{
			ChainID:     ChainID,
			Sender:      MainWallet.MainAddress,
			SendingTime: common.GetCurrentTimeStampInSecond(),
			Nonce:       int64(rand.Intn(0xffff)),
		}
		if len(hashms.GetHex()) > 0 {
			par.MultiSignTx = hashms
		}
		tx := transactionsDefinition.Transaction{
			TxData:    txd,
			TxParam:   par,
			Hash:      common.Hash{},
			Signature: common.Signature{},
			Height:    0,
			GasPrice:  int64(rand.Intn(0x0000000f)),
			GasUsage:  0,
		}
		clientrpc.InRPC <- SignMessage([]byte("STAT"))
		var reply []byte
		reply = <-clientrpc.OutRPC
		sm := statistics.GetStatsManager()
		st := sm.Stats
		err = common.Unmarshal(reply, common.StatDBPrefix, &st)
		if err != nil {
			v = fmt.Sprint("Can not unmarshal statistics: ", err)
			info = &v
			return
		}
		tx.GasUsage = tx.GasUsageEstimate()
		tx.Height = st.Height
		err = tx.CalcHashAndSet()
		if err != nil {
			v = fmt.Sprint("can not generate hash transaction: ", err)
			info = &v
			return
		}
		err = tx.Sign(MainWallet, primary)
		if err != nil {
			v = fmt.Sprint(err)
			info = &v
			return
		}
		msg, err := transactionServices.GenerateTransactionMsg([]transactionsDefinition.Transaction{tx}, []byte("tx"), [2]byte{'T', 'T'})
		if err != nil {
			v = fmt.Sprint(err)
			info = &v
			return
		}
		tmm := msg.GetBytes()
		clientrpc.InRPC <- SignMessage(append([]byte("TRAN"), tmm...))
		<-clientrpc.OutRPC
		v = "Tx Hash: " + tx.Hash.GetHex()
		info = &v
	})
	widget.Layout().AddWidget(button)

	hashTx = widgets.NewQLineEdit(nil)
	hashTx.SetPlaceholderText("Hash transaction to cancel")
	widget.Layout().AddWidget(hashTx)

	buttonCancel := widgets.NewQPushButton2("Cancel tx with Hash", nil)
	buttonCancel.ConnectClicked(func(bool) {
		var info *string
		v := "Transaction sent"
		info = &v
		defer func(nfo *string) {
			widgets.QMessageBox_Information(nil, "Info", *nfo, widgets.QMessageBox__Ok, widgets.QMessageBox__Ok)
		}(info)

		if !MainWallet.Check() {
			v = fmt.Sprint("Load wallet first")
			info = &v
			return
		}

		tmm, err := hex.DecodeString(hashTx.Text())
		if err != nil {
			v = fmt.Sprint(err.Error())
			info = &v
			return
		}

		clientrpc.InRPC <- SignMessage(append([]byte("CNCL"), tmm...))
		reply := <-clientrpc.OutRPC
		v = string(reply)
		info = &v
	})
	widget.Layout().AddWidget(buttonCancel)

	return widget
}
