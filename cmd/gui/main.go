package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/qwid-org/qwid-node/cmd/gui/qtwidgets"
	"github.com/qwid-org/qwid-node/common"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
	"github.com/qwid-org/qwid-node/statistics"
	"github.com/qwid-org/qwid-node/tcpip"
	"github.com/qwid-org/qwid-node/wallet"
	"github.com/therecipe/qt/widgets"
)

func main() {

	var ip string
	if len(os.Args) > 1 {
		ip = os.Args[1]
	} else {
		ip = "127.0.0.1"
	}
	statistics.InitStatsManager()
	go clientrpc.ConnectRPC(ip)
	time.Sleep(time.Second)
	fmt.Println(os.Args)

	ip_this := tcpip.MyIP
	ip_str := net.IPv4(ip_this[0], ip_this[1], ip_this[2], ip_this[3])
	// needs to be called once before you can start using the QWidgets
	app := widgets.NewQApplication(len(os.Args), os.Args)
	// create a window
	window := widgets.NewQTabWidget(nil)
	window.SetMinimumSize2(900, 700)
	window.SetWindowTitle("QWID Wallet - " + ip_str.String() +
		" Node Account: " +
		strconv.Itoa(int(common.NumericalDelegatedAccountAddress(common.GetDelegatedAccount()))))
	sigName, sigName2, err := qtwidgets.SetCurrentEncryptions()
	if err != nil {
		widgets.QMessageBox_Information(nil, "Warning", "error with retrieving current encryption", widgets.QMessageBox__Ok, widgets.QMessageBox__Ok)
	}
	w := wallet.EmptyWallet(0, sigName, sigName2)

	qtwidgets.MainWallet = &w

	walletWidget := qtwidgets.ShowWalletPage()
	escrowWidget := qtwidgets.ShowEscrowPage()
	accountWidget := qtwidgets.ShowAccountPage()
	sendWidget := qtwidgets.ShowSendPage()
	historyWidget := qtwidgets.ShowHistoryPage()
	detailsWidget := qtwidgets.ShowDetailsPage()
	stakingWidget := qtwidgets.ShowStakingPage()
	smartContractWidget := qtwidgets.ShowSmartContractPage()
	dexWidget := qtwidgets.ShowDexPage()
	voteWidget := qtwidgets.ShowVotingPage()
	window.AddTab(walletWidget, "Wallet")
	window.AddTab(accountWidget, "Account")
	window.AddTab(sendWidget, "Send/Register")
	window.AddTab(stakingWidget, "Staking/Rewards")
	window.AddTab(historyWidget, "Transactions history")
	window.AddTab(detailsWidget, "Details")
	window.AddTab(smartContractWidget, "Smart Contract")
	window.AddTab(dexWidget, "DEX")
	window.AddTab(escrowWidget, "Escrow/Multi")
	window.AddTab(voteWidget, "Vote")
	// make the window visible
	window.Show()

	go func() {
		for range time.Tick(time.Second * 1) {
			qtwidgets.UpdateAccountStats()
		}
	}()

	// start the main Qt event loop
	// and block until app.Exit() is called
	// or the window is closed by the user
	app.Exec()
}
