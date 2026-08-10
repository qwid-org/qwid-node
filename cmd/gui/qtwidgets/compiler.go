package qtwidgets

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto"
	"github.com/qwid-org/qwid-node/logger"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
	"github.com/qwid-org/qwid-node/statistics"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/widgets"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func SendPasiveFunctionQuery(pf blocks.PasiveFunction) string {
	clientrpc.InRPC <- SignMessage([]byte("STAT"))
	var reply []byte
	reply = <-clientrpc.OutRPC
	sm := statistics.GetStatsManager()
	st := sm.Stats
	err = common.Unmarshal(reply, common.StatDBPrefix, &st)
	if err != nil {
		return fmt.Sprint("Can not unmarshal statistics", err)
	}
	pf.Height = st.Height
	b, _ := json.Marshal(pf)
	clientrpc.InRPC <- SignMessage(append([]byte("VIEW"), b...))
	reply = <-clientrpc.OutRPC
	return hex.EncodeToString(reply)
}

func ShowSmartContractPage() *widgets.QTabWidget {
	// create a regular widget
	// give it a QVBoxLayout
	// and make it the central widget of the window
	var outputData *widgets.QTextEdit
	var functionABI string

	widget := widgets.NewQTabWidget(nil)
	widget.SetLayout(widgets.NewQVBoxLayout())

	addressData := widgets.NewQLineEdit(nil)
	addressData.SetPlaceholderText("Smart Contract Address")
	widget.Layout().AddWidget(addressData)

	inputLine := widgets.NewQLineEdit(nil)
	inputLine.SetPlaceholderText("Smart Contract Input Data")
	widget.Layout().AddWidget(inputLine)

	inputData := widgets.NewQTextEdit(nil)
	inputData.SetPlaceholderText("Smart Contract Input Data")
	widget.Layout().AddWidget(inputData)

	listFunctionsABI := widgets.NewQComboBox(nil)
	widget.Layout().AddWidget(listFunctionsABI)
	listFunctionsABI.ConnectEnterEvent(func(event *core.QEvent) {
		logger.GetLogger().Println("Event type:", event.Type())
		if event.IsAccepted() {
			item := listFunctionsABI.CurrentText()
			if item != "" {
				ind := strings.Split(item, "=")[0]
				functionABI = common.Bytes2Hex(crypto.Keccak256([]byte(ind))[:4])
				var ins []string
				if inputLine.Text() != "" {
					ins = strings.Split(inputLine.Text(), ",")
				}
				if len(strings.Split(ind, "(")) > 1 {
					indi := strings.Split(ind, "(")[1]
					indi = strings.Split(indi, ")")[0]
					inputLine.SetPlaceholderText(indi)
				}
				hv := ""
				var b []byte
				for _, s := range ins {
					if common.IsHexVMAddress(s) { // address
						a := common.HexToVMAddress(s)
						b = common.LeftPadBytes(a.GetBytes(), 32)
					} else if common.Has0xPrefix(s) { // hex number
						b = common.FromHex(s)
						b = common.LeftPadBytes(b, 32)
					} else if substr, ok := common.CheckQuotationAndRetainString(s); ok { //string
						ns := len(substr)/32 + 1
						b = common.LeftPadBytes(common.GetByteInt64(int64(ns)), 32)
						b = append(b, common.LeftPadBytes(common.GetByteInt64(0), 32)...)
						b = append(b, common.RightPadBytes([]byte(substr), ns*32)...)
					} else { // decimal number
						bi, err := strconv.ParseInt(s, 10, 64)
						if err != nil {
							logger.GetLogger().Println("error in number conversion", err, "Type of ", s, "Currently not implemented")
							break
						}
						b = common.LeftPadBytes(common.GetInt64ToBytesSC(bi), 32)
					}

					hv += common.Bytes2Hex(b)
				}

				inputData.SetText(functionABI + hv)
			}
		}

	})
	UpdateCallTextButton := widgets.NewQPushButton2("Update ABI", nil)
	UpdateCallTextButton.ConnectClicked(func(bool) {
		js, _ := os.ReadFile("smartContracts/contract.abi")
		var funcs []map[string]any
		json.Unmarshal(js, &funcs)
		logger.GetLogger().Printf("%+v", funcs)
		ls := []string{}
		for _, v := range funcs {
			if v["name"] != nil {
				typ := v["type"].(string)
				if typ != "function" {
					continue
				}
				name := v["name"].(string)
				inputs := ""
				ii := -1
				var nn any
				for ii, nn = range v["inputs"].([]any) {
					intyp := nn.(map[string]any)["type"].(string)
					inputs += intyp + ","
				}

				if ii == -1 {
					inputs = "()"
				} else if ii == 0 {
					inputs = inputs[:len(inputs)-1]
					if typ == "function" {
						inputs = "(" + inputs + ")"
					} else {
						inputs = "[" + inputs + "]"
					}
				} else {
					inputs = inputs[:len(inputs)-1]
					if typ == "function" {
						inputs = "(" + inputs + ")"
					}
				}

				outputs := ""
				ii = -1
				for ii, nn = range v["outputs"].([]any) {
					intyp := nn.(map[string]any)["type"].(string)
					outputs += intyp + ","
				}
				if ii == -1 {
				} else if ii == 0 {
					outputs = outputs[:len(outputs)-1]
				} else {
					outputs = outputs[:len(outputs)-1]
					outputs = "(" + outputs + ")"
				}

				ls = append(ls, name+inputs+"="+outputs)
			}
		}
		listFunctionsABI.Clear()
		listFunctionsABI.AddItems(ls)
		listFunctionsABI.SetAcceptDrops(true)
	})
	widget.Layout().AddWidget(UpdateCallTextButton)
	CallTextButton := widgets.NewQPushButton2("Call Smart Contract", nil)
	CallTextButton.ConnectClicked(func(bool) {
		var info *string
		v := "Compiled successful"
		info = &v
		defer func(nfo *string) {
			widgets.QMessageBox_Information(nil, "Info", *nfo, widgets.QMessageBox__Ok, widgets.QMessageBox__Ok)
		}(info)
		address := common.Address{}
		ba, _ := hex.DecodeString(addressData.Text())
		address.Init(ba)
		od, _ := hex.DecodeString(inputData.ToPlainText())
		pf := blocks.PasiveFunction{Height: 0,
			OptData: od,
			Address: address,
		}
		ret := SendPasiveFunctionQuery(pf)
		v = fmt.Sprint(ret)
		info = &v
		outputData.SetText(ret)
		SmartContractData.SetText(inputData.ToPlainText())
		Recipient.SetText(addressData.Text())
	})
	widget.Layout().AddWidget(CallTextButton)

	codeData := widgets.NewQTextEdit(nil)
	codeData.SetPlaceholderText("Smart Contract Code")
	widget.Layout().AddWidget(codeData)

	UpdateTextButton := widgets.NewQPushButton2("Compile Smart Contract Creation", nil)
	UpdateTextButton.ConnectClicked(func(bool) {
		var info *string
		v := "Compiled successful"
		info = &v
		defer func(nfo *string) {
			widgets.QMessageBox_Information(nil, "Info", *nfo, widgets.QMessageBox__Ok, widgets.QMessageBox__Ok)
		}(info)

		code := codeData.ToPlainText()

		fo, err := os.Create("smartContracts/contract.sol")
		if err != nil {
			v = fmt.Sprint("file open error: ", err)
			info = &v
			return
		}
		var b []byte
		reader := strings.NewReader(code)

		b = make([]byte, len(code))
		_, err = reader.Read(b)
		if err != nil {
			v = fmt.Sprint("code read error: ", err)
			info = &v
			return
		}
		if _, err := fo.Write(b); err != nil {
			v = fmt.Sprint("code write to file error: ", err)
			info = &v
			return
		}
		err = fo.Close()
		if err != nil {
			v = fmt.Sprint("file close error: ", err)
			info = &v
			return
		}
		cmd := exec.Command("solc", "--evm-version", "paris", "--bin", "smartContracts/contract.sol") //
		var out bytes.Buffer
		cmd.Stdout = &out
		err = cmd.Run()
		if err != nil {
			v = fmt.Sprint("Solidity compiler error: ", err)
			info = &v
			return
		}
		fmt.Printf("The date is %s\n", out.Bytes())
		binary := strings.Split(out.String(), "\n")
		outputData.SetText(binary[len(binary)-2])
		SmartContractData.SetText(outputData.ToPlainText())
		Recipient.SetText("0")
		Amount.SetText("0")
		cmd = exec.Command("solc", "--evm-version", "paris", "--abi", "smartContracts/contract.sol") //
		cmd.Stdout = &out
		err = cmd.Run()
		if err != nil {
			v = fmt.Sprint("Solidity compiler ABI error: ", err)
			info = &v
			return
		}
		fo, _ = os.Create("smartContracts/contract.abi")
		defer fo.Close()
		abi := strings.Split(out.String(), "\n")
		fo.Write([]byte(abi[len(abi)-2]))

	})
	widget.Layout().AddWidget(UpdateTextButton)

	outputData = widgets.NewQTextEdit(nil)
	outputData.SetPlaceholderText("Smart Contract Output Data")

	widget.Layout().AddWidget(outputData)
	codeTmp, _ := os.ReadFile("smartContracts/contract.sol")
	codeData.SetText(string(codeTmp))
	return widget
}
