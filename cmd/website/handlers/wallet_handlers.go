package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/common"
	clientrpc "github.com/wonabru/qwid-node/rpc/client"
)

type WalletInfoResponse struct {
	Loaded    bool   `json:"loaded"`
	Address   string `json:"address"`
	PubKeyHex string `json:"pubKeyHex"`
	SigName   string `json:"sigName"`
	SigName2  string `json:"sigName2"`
}

type AccountResponse struct {
	Address        string          `json:"address"`
	Balance        float64         `json:"balance"`
	StakedAmount   float64         `json:"stakedAmount"`
	LockedAmount   float64         `json:"lockedAmount"`
	RewardsAmount  float64         `json:"rewardsAmount"`
	TotalHoldings  float64         `json:"totalHoldings"`
	StakingDetails []StakingDetail `json:"stakingDetails"`
	EscrowDelay    int64           `json:"escrowDelay"`
	SentCount      int             `json:"sentCount"`
	ReceivedCount  int             `json:"receivedCount"`
}

type StakingDetail struct {
	DelegatedAddress string  `json:"delegatedAddress"`
	Staked           float64 `json:"staked"`
	Rewards          float64 `json:"rewards"`
}

func GetWalletInfo(w http.ResponseWriter, r *http.Request) {
	sess := GetSession(r.Context())
	if sess == nil || sess.Wallet == nil {
		JsonResponse(w, WalletInfoResponse{Loaded: false})
		return
	}

	wl := sess.Wallet
	JsonResponse(w, WalletInfoResponse{
		Loaded:    true,
		Address:   wl.MainAddress.GetHex(),
		PubKeyHex: wl.Account1.PublicKey.GetHex()[:64] + "...",
		SigName:   wl.GetSigName(true),
		SigName2:  wl.GetSigName(false),
	})
}

func GetAccount(w http.ResponseWriter, r *http.Request) {
	sess := GetSession(r.Context())
	if sess == nil || sess.Wallet == nil {
		JsonError(w, "Wallet not loaded", http.StatusBadRequest)
		return
	}

	wl := sess.Wallet
	inb := append([]byte("ACCT"), wl.MainAddress.GetBytes()...)
	re := clientrpc.Call(SignMessage(inb))
	if bytes.Equal(re, []byte("Timeout")) {
		JsonError(w, "Timeout", http.StatusGatewayTimeout)
		return
	}

	var acc account.Account
	if err := acc.Unmarshal(re); err != nil {
		JsonError(w, "Failed to unmarshal account", http.StatusInternalServerError)
		return
	}

	conf := acc.GetBalanceConfirmedFloat()
	stake := 0.0
	rewards := 0.0
	locks := 0.0
	stakingDetails := []StakingDetail{}

	for i := 1; i < 256; i++ {
		inb = append([]byte("STAK"), wl.MainAddress.GetBytes()...)
		inb = append(inb, byte(i))
		re = clientrpc.Call(SignMessage(inb))
		if bytes.Equal(re, []byte("Timeout")) {
			continue
		}

		var stakeAcc account.StakingAccount
		if err := stakeAcc.Unmarshal(re[:len(re)-8]); err != nil {
			continue
		}

		stakedAmount := account.Int64toFloat64(stakeAcc.StakedBalance)
		rewardsAmount := account.Int64toFloat64(stakeAcc.StakingRewards)
		lockedAmount := account.Int64toFloat64(common.GetInt64FromByte(re[len(re)-8:]))

		stake += stakedAmount
		rewards += rewardsAmount
		locks += lockedAmount

		if stakeAcc.StakedBalance > 0 || stakeAcc.StakingRewards > 0 {
			a := common.Address{}
			a.Init(stakeAcc.DelegatedAccount[:])
			stakingDetails = append(stakingDetails, StakingDetail{
				DelegatedAddress: a.GetHex(),
				Staked:           stakedAmount,
				Rewards:          rewardsAmount,
			})
		}
	}

	resp := AccountResponse{
		Address:        wl.MainAddress.GetHex(),
		Balance:        conf,
		StakedAmount:   stake,
		LockedAmount:   locks,
		RewardsAmount:  rewards,
		TotalHoldings:  conf + stake + rewards,
		StakingDetails: stakingDetails,
		EscrowDelay:    acc.TransactionDelay,
		SentCount:      len(acc.TransactionsSender),
		ReceivedCount:  len(acc.TransactionsRecipient),
	}
	JsonResponse(w, resp)
}

func GetMnemonic(w http.ResponseWriter, r *http.Request) {
	sess := GetSession(r.Context())
	if sess == nil || sess.Wallet == nil {
		JsonError(w, "Wallet not loaded", http.StatusBadRequest)
		return
	}

	wl := sess.Wallet
	// WH-C5: require password re-entry before revealing the recovery phrase,
	// so a stolen/left-open session cannot exfiltrate keys.
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JsonError(w, "Password required", http.StatusBadRequest)
		return
	}
	if !wl.VerifyPassword(req.Password) {
		JsonError(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	mnemonic1, err1 := wl.GetMnemonicWords(true)
	mnemonic2, err2 := wl.GetMnemonicWords(false)

	resp := map[string]interface{}{
		"primaryMnemonic":   mnemonic1,
		"primaryError":      "",
		"secondaryMnemonic": mnemonic2,
		"secondaryError":    "",
	}
	if err1 != nil {
		resp["primaryError"] = err1.Error()
	}
	if err2 != nil {
		resp["secondaryError"] = err2.Error()
	}
	JsonResponse(w, resp)
}

func ChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		JsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sess := GetSession(r.Context())
	if sess == nil || sess.Wallet == nil {
		JsonError(w, "Wallet not loaded", http.StatusBadRequest)
		return
	}

	var req struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if len(req.NewPassword) < 6 {
		JsonError(w, "New password must be at least 6 characters", http.StatusBadRequest)
		return
	}

	wl := sess.Wallet
	if err := wl.ChangePasswordInPlace(req.CurrentPassword, req.NewPassword); err != nil {
		JsonError(w, "Wrong current password", http.StatusBadRequest)
		return
	}

	// Update user registry password hash
	if Users != nil {
		Users.mu.Lock()
		entry, ok := Users.users[sess.Username]
		if ok {
			hash, err := bcryptHash(req.NewPassword)
			if err == nil {
				entry.PasswordHash = hash
				Users.save()
			}
		}
		Users.mu.Unlock()
	}

	JsonResponse(w, map[string]string{"success": "Password changed"})
}
