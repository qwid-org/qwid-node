package qtwidgets

import (
	"encoding/hex"
	"fmt"
	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/therecipe/qt/widgets"
	"strconv"
	"strings"
)

var codeData *widgets.QTextEdit
var numberLinesDetails = 2000
var textHistoryDetails string

func AddNewHistoryItemDetails(item string) string {
	if item == "" || item == "\n" {
		return ""
	}
	t := item + "\n"
	t += textHistoryDetails

	if strings.Count(t, "\n") > numberLinesDetails {
		tl := strings.Split(t, "\n")
		t = strings.Join(tl[:numberLinesDetails], "\n")
	}
	textHistoryDetails = t
	return textHistoryDetails
}

func AccountDetailsToString(acc account.Account) string {
	//clientrpc.InRPC <- []byte("STAT")
	//var reply []byte
	//reply = <-clientrpc.OutRPC
	//if string(reply) == "Timeout" {
	//	return string(reply)
	//}
	//st := statistics.MainStats{}
	//err := json.Unmarshal(reply, &st)
	//if err != nil {
	//	return fmt.Sprintln("Can not unmarshal statistics")
	//}
	conf := acc.GetBalanceConfirmedFloat()

	//stake := 0.0  // acc.GetStakeConfirmedFloat(st.Heights)

	txt := fmt.Sprintln("\n\nAccount:\n", acc.GetString())
	//txt += fmt.Sprintf("Holdings: %18.8f QWD\n", conf)
	txt += fmt.Sprintf("Balance: %18.8f QWD\n", conf)
	//txt += fmt.Sprintf("Transactions unconfirmed balance: %18.8f QWD\n", uncTx)
	//txt += fmt.Sprintf("Staked amount: %18.8f QWD\n", stake)
	//txt += fmt.Sprintf("Unconfirmed staked amount: %18.8f QWD\n", uncStake)
	//txt += fmt.Sprintf("\nStaking details:\n")
	//for k, v := range acc.StakingAddresses {
	//	if v == 0 {
	//		continue
	//	}
	//	ab, _ := hex.DecodeString(k)
	//	a := common.Address{}
	//	a.Init(ab[:])
	//	if n := common.NumericalDelegatedAccountAddress(a); n > 0 {
	//
	//		txt += fmt.Sprintf("Delegated Address: %v\n", a.GetHex())
	//		txt += fmt.Sprintf("Delegated Account Number: %v = %v\n", n, account.Int64toFloat64(v))
	//
	//	}
	//}
	//txt += "\n\n"
	//lastSt.Heights = 0
	//
	//histState := acc.GetHistoryState(lastSt.Heights, st.Heights)
	//histRewards := acc.GetHistoryUnconfirmedRewards(lastSt.Heights, st.Heights)
	//histConfirmed := acc.GetHistoryConfirmedTransaction(lastSt.Heights, st.Heights)
	//
	//histStake := acc.GetHistoryStake(lastSt.Heights, st.Heights)
	//for i := st.Heights - 1; i >= lastSt.Heights; i-- {
	//	txt += fmt.Sprintln(i, "/", st.Heights, ":")
	//	txt += fmt.Sprintln("Balance:", account.Int64toFloat64(histState[i]))
	//	txt += fmt.Sprintln("Staked:", account.Int64toFloat64(histStake[i]))
	//	txt += fmt.Sprintln("Unconfirmed reward Main Chain:", account.Int64toFloat64(histRewards[i]))
	//
	//	for k, v := range histConfirmed[i] {
	//		if v != 0 {
	//			txt += fmt.Sprintln("Confirmed", k, account.Int64toFloat64(v))
	//		}
	//	}
	//}
	textHistoryDetails = ""
	return AddNewHistoryItemDetails(txt)
}

func GetDetails(h string) string {

	var b []byte
	var err error
	if len(h) < 16 {
		height, err := strconv.Atoi(h)
		if err != nil {
			return "Cannot decode string. Is it really integer?"
		}
		b = common.GetByteInt64(int64(height))
	} else {
		b, err = hex.DecodeString(h)
		if err != nil {
			return "Cannot decode string. Is it in hexadecimal format?"
		}
	}

	clientrpc.InRPC <- SignMessage(append([]byte("DETS"), b...))
	var reply []byte
	reply = <-clientrpc.OutRPC
	if len(reply) <= 2 {
		return "reply from server is invalid"
	}
	switch string(reply[:2]) {
	case "TX":
		tx := transactionsDefinition.Transaction{}
		tx, _, err := tx.GetFromBytes(reply[2:])
		if err != nil {
			logger.GetLogger().Println(err)
			return ""
		}
		return tx.GetString()
	case "AC":
		acc := account.Account{
			Balance:               0,
			Address:               [20]byte{},
			TransactionDelay:      0,
			MultiSignNumber:       0,
			MultiSignAddresses:    make([][20]byte, 0),
			TransactionsSender:    make([]common.Hash, 0),
			TransactionsRecipient: make([]common.Hash, 0),
		}
		err = (&acc).Unmarshal(reply[2:])
		if err != nil {
			logger.GetLogger().Println(err)
			return ""
		}
		return AccountDetailsToString(acc)
	case "BL":
		bb := blocks.Block{}
		bb, err = bb.GetFromBytes(reply[2:])
		if err != nil {
			logger.GetLogger().Println(err)
			return ""
		}
		return bb.GetString()
	default:

	}
	logger.GetLogger().Println("Can not unmarshal transaction")
	return string(reply)
}

func ShowDetailsPage() *widgets.QTabWidget {
	// create a regular widget
	// give it a QVBoxLayout
	// and make it the central widget of the window
	widget := widgets.NewQTabWidget(nil)
	widget.SetLayout(widgets.NewQVBoxLayout())

	hash := widgets.NewQLineEdit(nil)
	hash.SetPlaceholderText("Tx Hash/Address/Block Height")
	widget.Layout().AddWidget(hash)

	UpdateTextButton := widgets.NewQPushButton2("Get details", nil)
	UpdateTextButton.ConnectClicked(func(bool) {
		codeData.SetPlainText(GetDetails(hash.Text()))
	})
	widget.Layout().AddWidget(UpdateTextButton)
	codeData = widgets.NewQTextEdit(nil)
	//codeData.SetAcceptRichText(true)
	widget.Layout().AddWidget(codeData)

	return widget
}
