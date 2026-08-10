package wallet

import "github.com/qwid-org/qwid-node/common"

// PublicWalletView is the RPC-safe projection of a Wallet: identity/public fields
// only. It deliberately omits KdfSalt, EncryptedSecretKey, Iv, HomePath, and the
// Accounts map — everything an attacker would need for an offline password-cracking
// attack — so the WALL RPC cannot leak encryption material (NP-C5). The plaintext
// secret key, password, and signer are already unexported and never serialized.
type PublicWalletView struct {
	WalletNumber uint8             `json:"wallet_number"`
	MainAddress  common.Address    `json:"main_address"`
	SigName      string            `json:"sig_name"`
	SigName2     string            `json:"sig_name_2"`
	Account1     PublicAccountView `json:"account_1"`
	Account2     PublicAccountView `json:"account_2"`
}

type PublicAccountView struct {
	PublicKey common.PubKey  `json:"public_key"`
	Address   common.Address `json:"address"`
}

// PublicView returns the RPC-safe projection of w. Nil-safe.
func (w *Wallet) PublicView() PublicWalletView {
	if w == nil {
		return PublicWalletView{}
	}
	return PublicWalletView{
		WalletNumber: w.WalletNumber,
		MainAddress:  w.MainAddress,
		SigName:      w.SigName,
		SigName2:     w.SigName2,
		Account1:     PublicAccountView{PublicKey: w.Account1.PublicKey, Address: w.Account1.Address},
		Account2:     PublicAccountView{PublicKey: w.Account2.PublicKey, Address: w.Account2.Address},
	}
}
