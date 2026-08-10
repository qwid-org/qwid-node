package qtwidgets

import (
	"encoding/hex"
	"fmt"
	"github.com/wonabru/qwid-node/account"
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

func ShowStakingPage() *widgets.QTabWidget {

	var amount *widgets.QLineEdit
	var operator *widgets.QCheckBox
	var button *widgets.QPushButton
	// create a regular widget
	// give it a QVBoxLayout
	// and make it the central widget of the window
	widget := widgets.NewQTabWidget(nil)
	widget.SetLayout(widgets.NewQVBoxLayout())

	stakeButton := widgets.NewQRadioButton2("STAKE", nil)

	widget.Layout().AddWidget(stakeButton)
	stakeButton.ConnectClicked(func(bool) {
		amount.SetPlaceholderText("TransactionsStaking amount")
		button.SetText("STAKE")
		//operator.SetEnabled(true)
	})
	unstakeButton := widgets.NewQRadioButton2("UNSTAKE", nil)
	widget.Layout().AddWidget(unstakeButton)
	unstakeButton.ConnectClicked(func(bool) {
		amount.SetPlaceholderText("Unstaking amount")
		button.SetText("UNSTAKE")
		//operator.SetEnabled(false)
	})

	withdrawButton := widgets.NewQRadioButton2("WITHDRAW REWARDS", nil)
	widget.Layout().AddWidget(withdrawButton)
	withdrawButton.ConnectClicked(func(bool) {
		amount.SetPlaceholderText("Withdraw rewards amount")
		button.SetText("WITHDRAW REWARDS")
		//operator.SetEnabled(false)
	})
	stakeButton.SetChecked(true)

	primaryChb := widgets.NewQCheckBox(nil)
	primaryChb.SetText("Use primary encryption")
	primaryChb.SetChecked(true)
	widget.Layout().AddWidget(primaryChb)

	// create a line edit
	// with a custom placeholder text
	// and add it to the central widgets layout
	delegatedEdit := widgets.NewQLineEdit(nil)
	delegatedEdit.SetPlaceholderText("Delegated account")
	widget.Layout().AddWidget(delegatedEdit)

	amount = widgets.NewQLineEdit(nil)
	amount.SetPlaceholderText("TransactionsStaking amount")
	widget.Layout().AddWidget(amount)

	operator = widgets.NewQCheckBox2("Intend to be an Operator", nil)
	operator.SetChecked(false)
	widget.Layout().AddWidget(operator)

	pubkeyInclude := widgets.NewQCheckBox(nil)
	pubkeyInclude.SetText("Public key include in transaction")
	widget.Layout().AddWidget(pubkeyInclude)

	// connect the clicked signal
	// and add it to the central widgets layout
	button = widgets.NewQPushButton2("STAKE", nil)
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
		var bar []byte
		ar := common.Address{}
		di, err := strconv.ParseInt(delegatedEdit.Text(), 10, 16)
		if err != nil {
			bar, err = hex.DecodeString(delegatedEdit.Text())
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
		} else {
			if withdrawButton.IsChecked() {
				ar = common.GetDelegatedAccountAddress(int16(di + 256))
			} else {
				ar = common.GetDelegatedAccountAddress(int16(di))
			}
		}

		if _, err := account.IntDelegatedAccountFromAddress(ar); err != nil {
			v = fmt.Sprint("This is not a valid delegated account:", ar.GetHex())
			info = &v
			return
		}

		af, err := strconv.ParseFloat(amount.Text(), 64)
		if err != nil {
			v = fmt.Sprint(err)
			info = &v
			return
		}
		withdrawMin := common.MinStakingUser
		if withdrawButton.IsChecked() {
			withdrawMin = 0
		}
		if int64(af*math.Pow10(int(common.Decimals))) < withdrawMin {
			if withdrawButton.IsChecked() {
				if af >= 0 {
					v = fmt.Sprint("Withdraw amount cannot less or equal than:", 0)
					info = &v
					return
				}
			} else {
				v = fmt.Sprint("Staked amount cannot less than:", float64(common.MinStakingUser)/math.Pow10(int(common.Decimals)))
				info = &v
				return
			}
		}
		am := int64(af * math.Pow10(int(common.Decimals)))
		if float64(am) != af*math.Pow10(int(common.Decimals)) {
			v = fmt.Sprint("Precision needs to be not larger than", common.Decimals, " digits")
			info = &v
			return
		}
		if unstakeButton.IsChecked() {
			am *= -1
		} else if withdrawButton.IsChecked() {
			am *= -1
		}
		isoperator := []byte{}
		if operator.IsChecked() {
			isoperator = []byte{1}
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
			OptData:                    isoperator,
			Pubkey:                     pk,
			LockedAmount:               0,
			ReleasePerBlock:            0,
			DelegatedAccountForLocking: common.GetDelegatedAccountAddress(1),
		}
		par := transactionsDefinition.TxParam{
			ChainID:     ChainID,
			Sender:      MainWallet.MainAddress,
			SendingTime: common.GetCurrentTimeStampInSecond(),
			Nonce:       int64(rand.Intn(0xffff)),
		}
		tx := transactionsDefinition.Transaction{
			TxData:    txd,
			TxParam:   par,
			Hash:      common.Hash{},
			Signature: common.Signature{},
			Height:    0,
			GasPrice:  int64(rand.Intn(0xefffffff)),
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
		tx.Height = st.Height
		err = tx.CalcHashAndSet()
		if err != nil {
			v = fmt.Sprint("can not generate hash transaction: ", err)
			info = &v
			return
		}
		err = tx.Sign(MainWallet, primaryChb.IsChecked())
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
		v = string(reply)
		info = &v

	})
	widget.Layout().AddWidget(button)

	return widget
}
