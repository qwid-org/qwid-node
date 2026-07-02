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
	"math/rand"
	"strconv"
	"strings"
)

func ShowEscrowPage() *widgets.QTabWidget {
	// create a regular widget
	// give it a QVBoxLayout
	// and make it the central widget of the window
	widget := widgets.NewQTabWidget(nil)
	widget.SetLayout(widgets.NewQVBoxLayout())

	pubkeyInclude := widgets.NewQCheckBox(nil)
	pubkeyInclude.SetText("Public key include in transaction")
	widget.Layout().AddWidget(pubkeyInclude)
	primaryChb := widgets.NewQCheckBox(nil)
	primaryChb.SetText("Use primary encryption")
	primaryChb.SetChecked(true)
	widget.Layout().AddWidget(primaryChb)

	delayEscrow1 := widgets.NewQLineEdit(nil)
	delayEscrow1.SetPlaceholderText("Primary account to set Escrow: set delay transaction in blocks number > 0 (default 0)")
	widget.Layout().AddWidget(delayEscrow1)
	numMulti1 := widgets.NewQLineEdit(nil)
	numMulti1.SetPlaceholderText("Primary account to set MultiSignature: set number of Approvals > 0 (default 0)")
	widget.Layout().AddWidget(numMulti1)
	addressesMulti1 := widgets.NewQLineEdit(nil)
	addressesMulti1.SetPlaceholderText("Primary account to set MultiSignature: set addresses seperated with comma , (default empty)")
	widget.Layout().AddWidget(addressesMulti1)
	buttonChangePrimary := widgets.NewQPushButton2("Modify account", nil)
	buttonChangePrimary.ConnectClicked(func(bool) {
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

		escrowDelay, err := strconv.ParseInt(delayEscrow1.Text(), 10, 64)
		if err != nil {
			v = fmt.Sprint("cannot parse int from escrow delay %v", err.Error())
			info = &v
			return
		}
		if numMulti1.Text() == "" {
			numMulti1.SetText("0")
		}
		numMulti, err := strconv.ParseInt(numMulti1.Text(), 10, 64)
		if err != nil {
			v = fmt.Sprint("cannot parse int from num multi %v", err.Error())
			info = &v
			return
		}
		if numMulti > 255 || numMulti < 0 {
			v = fmt.Sprint("number of multisign approvals must be less than 256 and more or equal than 0, currently %v", numMulti)
			info = &v
			return
		}

		multiAddresses := strings.Split(addressesMulti1.Text(), ",")
		multiAddresses_mod := [][common.AddressLength]byte{}
		if addressesMulti1.Text() != "" {
			for _, addr := range multiAddresses {
				addr = strings.Trim(addr, " ")
				addrb, err := hex.DecodeString(addr)
				if err != nil {
					v = fmt.Sprint(err.Error())
					info = &v
					return
				}
				if len(addrb) != common.AddressLength {
					v = fmt.Sprint("adddresses in multisignature must be of length 20, currently %v", len(addrb))
					info = &v
					return
				}
				ab := [20]byte{}
				copy(ab[:], addrb)
				multiAddresses_mod = append(multiAddresses_mod, ab)
			}
		}
		if len(multiAddresses_mod) < int(numMulti) {
			v = fmt.Sprint("number of adddresses in multisignature must be more or equal to %v, currently %v", numMulti, len(multiAddresses_mod))
			info = &v
			return
		}

		txd := transactionsDefinition.TxData{
			Recipient:               MainWallet.MainAddress,
			Amount:                  int64(0),
			OptData:                 []byte{},
			Pubkey:                  pk,
			EscrowTransactionsDelay: escrowDelay,
			MultiSignNumber:         uint8(numMulti),
			MultiSignAddresses:      multiAddresses_mod,
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
		v = string(reply)
		info = &v
	})
	widget.Layout().AddWidget(buttonChangePrimary)

	//delayEscrow2 := widgets.NewQLineEdit(nil)
	//delayEscrow2.SetPlaceholderText("Secondary account to set Escrow: set delay transaction in blocks number > 0 (default 0)")
	//widget.Layout().AddWidget(delayEscrow2)
	//numMulti2 := widgets.NewQLineEdit(nil)
	//numMulti2.SetPlaceholderText("Secondary account to set MultiSignature: set number of Approvals > 0 (default 0)")
	//widget.Layout().AddWidget(numMulti2)
	//addressesMulti2 := widgets.NewQLineEdit(nil)
	//addressesMulti2.SetPlaceholderText("Secondary account to set MultiSignature: set addresses seperated with comma , (default empty)")
	//widget.Layout().AddWidget(addressesMulti2)
	//buttonChangeSecondary := widgets.NewQPushButton2("Modify secondary account", nil)
	//buttonChangeSecondary.ConnectClicked(func(bool) {
	//	var info *string
	//	v := "Transaction sent"
	//	info = &v
	//	defer func(nfo *string) {
	//		widgets.QMessageBox_Information(nil, "Info", *nfo, widgets.QMessageBox__Ok, widgets.QMessageBox__Ok)
	//	}(info)
	//
	//	if !MainWallet.Check() {
	//		v = fmt.Sprint("Load wallet first")
	//		info = &v
	//		return
	//	}
	//
	//	pk := common.PubKey{}
	//	if pubkeyInclude.IsChecked() {
	//		if primaryChb.IsChecked() {
	//			pk = MainWallet.PublicKey
	//			primary = true
	//		} else {
	//			pk = MainWallet.PublicKey2
	//			primary = false
	//		}
	//	} else {
	//		if primaryChb.IsChecked() {
	//			primary = true
	//		} else {
	//			primary = false
	//		}
	//	}
	//
	//	escrowDelay, err := strconv.ParseInt(delayEscrow2.Text(), 10, 64)
	//	if err != nil {
	//		v = fmt.Sprint("cannot parse int from escrow delay %v", err.Error())
	//		info = &v
	//		return
	//	}
	//	if numMulti2.Text() == "" {
	//		numMulti2.SetText("0")
	//	}
	//	numMulti, err := strconv.ParseInt(numMulti2.Text(), 10, 64)
	//	if err != nil {
	//		v = fmt.Sprint("cannot parse int from num multi %v", err.Error())
	//		info = &v
	//		return
	//	}
	//	if numMulti > 255 || numMulti < 0 {
	//		v = fmt.Sprint("number of multisign approvals must be less than 256 and more or equal than 0, currently %v", numMulti)
	//		info = &v
	//		return
	//	}
	//
	//	multiAddresses := strings.Split(addressesMulti2.Text(), ",")
	//	multiAddresses_mod := [][common.AddressLength]byte{}
	//	if addressesMulti2.Text() != "" {
	//		for _, addr := range multiAddresses {
	//			addr = strings.Trim(addr, " ")
	//			addrb, err := hex.DecodeString(addr)
	//			if err != nil {
	//				v = fmt.Sprint(err.Error())
	//				info = &v
	//				return
	//			}
	//			if len(addrb) != common.AddressLength {
	//				v = fmt.Sprint("adddresses in multisignature must be of length 20, currently %v", len(addrb))
	//				info = &v
	//				return
	//			}
	//			ab := [20]byte{}
	//			copy(ab[:], addrb)
	//			multiAddresses_mod = append(multiAddresses_mod, ab)
	//		}
	//	}
	//	if len(multiAddresses_mod) < int(numMulti) {
	//		v = fmt.Sprint("number of adddresses in multisignature must be more or equal to %v, currently %v", numMulti, len(multiAddresses_mod))
	//		info = &v
	//		return
	//	}
	//
	//	txd := transactionsDefinition.TxData{
	//		Recipient:               MainWallet.MainAddress,
	//		Amount:                  int64(0),
	//		OptData:                 []byte{},
	//		Pubkey:                  pk,
	//		EscrowTransactionsDelay: escrowDelay,
	//		MultiSignNumber:         uint8(numMulti),
	//		MultiSignAddresses:      multiAddresses_mod,
	//	}
	//	par := transactionsDefinition.TxParam{
	//		ChainID:     ChainID,
	//		Sender:      MainWallet.MainAddress,
	//		SendingTime: common.GetCurrentTimeStampInSecond(),
	//		Nonce:       int64(rand.Intn(0xffff)),
	//	}
	//	tx := transactionsDefinition.Transaction{
	//		TxData:    txd,
	//		TxParam:   par,
	//		Hash:      common.Hash{},
	//		Signature: common.Signature{},
	//		Height:    0,
	//		GasPrice:  int64(rand.Intn(0x0000000f)),
	//		GasUsage:  0,
	//	}
	//	clientrpc.InRPC <- SignMessage([]byte("STAT"))
	//	var reply []byte
	//	reply = <-clientrpc.OutRPC
	//	sm := statistics.GetStatsManager()
	//	st := sm.Stats
	//	err = common.Unmarshal(reply, common.StatDBPrefix, &st)
	//	if err != nil {
	//		v = fmt.Sprint("Can not unmarshal statistics: ", err)
	//		info = &v
	//		return
	//	}
	//	tx.GasUsage = tx.GasUsageEstimate()
	//	tx.Height = st.Height
	//	err = tx.CalcHashAndSet()
	//	if err != nil {
	//		v = fmt.Sprint("can not generate hash transaction: ", err)
	//		info = &v
	//		return
	//	}
	//	err = tx.Sign(MainWallet, primary)
	//	if err != nil {
	//		v = fmt.Sprint(err)
	//		info = &v
	//		return
	//	}
	//	msg, err := transactionServices.GenerateTransactionMsg([]transactionsDefinition.Transaction{tx}, []byte("tx"), [2]byte{'T', 'T'})
	//	if err != nil {
	//		v = fmt.Sprint(err)
	//		info = &v
	//		return
	//	}
	//	tmm := msg.GetBytes()
	//	clientrpc.InRPC <- SignMessage(append([]byte("TRAN"), tmm...))
	//	<-clientrpc.OutRPC
	//	v = string(reply)
	//	info = &v
	//})
	//widget.Layout().AddWidget(buttonChangeSecondary)
	return widget
}
