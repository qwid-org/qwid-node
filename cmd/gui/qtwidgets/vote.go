package qtwidgets

import (
	"fmt"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
	"github.com/therecipe/qt/widgets"
)

func ShowVotingPage() *widgets.QTabWidget {

	// create a regular widget
	// give it a QVBoxLayout
	// and make it the central widget of the window
	widget := widgets.NewQTabWidget(nil)
	widget.SetLayout(widgets.NewQVBoxLayout())

	pausePrimary := widgets.NewQRadioButton(nil)
	pausePrimary.SetText("Pause Primary Encryption")
	widget.Layout().AddWidget(pausePrimary)

	unpausePrimary := widgets.NewQRadioButton(nil)
	unpausePrimary.SetText("Unpause Primary Encryption")
	widget.Layout().AddWidget(unpausePrimary)

	invalidatePrimary := widgets.NewQRadioButton(nil)
	invalidatePrimary.SetText("Replace Primary Encryption")
	widget.Layout().AddWidget(invalidatePrimary)

	newEncryption1 := widgets.NewQLineEdit(nil)
	newEncryption1.SetPlaceholderText("Name of new primary encryption")
	widget.Layout().AddWidget(newEncryption1)

	pauseSecondary := widgets.NewQRadioButton(nil)
	pauseSecondary.SetText("Pause Secondary Encryption")
	widget.Layout().AddWidget(pauseSecondary)

	unpauseSecondary := widgets.NewQRadioButton(nil)
	unpauseSecondary.SetText("Unpause Secondary Encryption")
	widget.Layout().AddWidget(unpauseSecondary)

	invalidateSecondary := widgets.NewQRadioButton(nil)
	invalidateSecondary.SetText("Replace Secondary Encryption")
	widget.Layout().AddWidget(invalidateSecondary)

	newEncryption2 := widgets.NewQLineEdit(nil)
	newEncryption2.SetPlaceholderText("Name of new secondary encryption")
	widget.Layout().AddWidget(newEncryption2)

	// connect the clicked signal
	// and add it to the central widgets layout
	button := widgets.NewQPushButton2("Vote", nil)
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
		enb := []byte{}
		if pausePrimary.IsChecked() || unpausePrimary.IsChecked() || invalidatePrimary.IsChecked() {
			en1Name := newEncryption1.Text()
			if en1Name == "" {
				en1Name = common.SigName()
				newEncryption1.SetText(en1Name)
			}
			config, err := oqs.GenerateEncConfig(en1Name)
			if err != nil {
				v = err.Error()
				info = &v
				return
			}
			isPaused := pausePrimary.IsChecked()
			if unpausePrimary.IsChecked() {
				isPaused = false
			}
			if invalidatePrimary.IsChecked() {
				isPaused = true
			}
			enb1, err := oqs.GenerateBytesFromParams(config.SigName, config.PubKeyLength, config.PrivateKeyLength, config.SignatureLength, isPaused)
			if err != nil {
				v = err.Error()
				info = &v
				return
			}
			enb = common.BytesToLenAndBytes(enb1)
			enb = append(enb, common.BytesToLenAndBytes([]byte{})...)
		} else if pauseSecondary.IsChecked() || unpauseSecondary.IsChecked() || invalidateSecondary.IsChecked() {
			en2Name := newEncryption2.Text()
			if en2Name == "" {
				en2Name = common.SigName2()
				newEncryption2.SetText(en2Name)
			}
			config, err := oqs.GenerateEncConfig(en2Name)
			if err != nil {
				v = err.Error()
				info = &v
				return
			}
			isPaused := pauseSecondary.IsChecked()
			if unpauseSecondary.IsChecked() {
				isPaused = false
			}
			if invalidateSecondary.IsChecked() {
				isPaused = true
			}
			enb2, err := oqs.GenerateBytesFromParams(config.SigName, config.PubKeyLength, config.PrivateKeyLength, config.SignatureLength, isPaused)
			if err != nil {
				v = err.Error()
				info = &v
				return
			}
			enb = common.BytesToLenAndBytes([]byte{})
			enb = append(enb, common.BytesToLenAndBytes(enb2)...)
		} else {
			v = fmt.Sprint("you need to fulfill form")
			info = &v
			return
		}

		clientrpc.InRPC <- SignMessage(append([]byte("VOTE"), enb...))
		reply := <-clientrpc.OutRPC
		v = string(reply)
		info = &v
	})
	widget.Layout().AddWidget(button)

	return widget
}
