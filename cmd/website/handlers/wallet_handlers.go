package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
	"github.com/qwid-org/qwid-node/wallet"
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
		PubKeyHex: common.HexPrefix(wl.Account1.PublicKey.GetHex(), 64),
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

	// One ACCS call returns the stake across all delegated accounts at once.
	inb = append([]byte("ACCS"), wl.MainAddress.GetBytes()...)
	re = clientrpc.Call(SignMessage(inb))
	if !bytes.Equal(re, []byte("Timeout")) && len(re) >= 4 {
		count := int(common.GetInt32FromByte(re[:4]))
		b := re[4:]
		for j := 0; j < count; j++ {
			blob, rest, err := common.BytesWithLenToBytes(b)
			if err != nil {
				break
			}
			b = rest
			if len(blob) < 8 {
				continue
			}
			var stakeAcc account.StakingAccount
			if err := stakeAcc.Unmarshal(blob[:len(blob)-8]); err != nil {
				continue
			}
			stakedAmount := account.Int64toFloat64(stakeAcc.StakedBalance)
			rewardsAmount := account.Int64toFloat64(stakeAcc.StakingRewards)
			lockedAmount := account.Int64toFloat64(common.GetInt64FromByte(blob[len(blob)-8:]))

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
		SentCount:      int(acc.SentCount),
		ReceivedCount:  int(acc.ReceivedCount),
	}
	JsonResponse(w, resp)
}

// GetMnemonic is permanently disabled — see the note on the webui handler. This
// server is multi-user and remote, so serving recovery phrases would put every
// user's keys on the wire.
func GetMnemonic(w http.ResponseWriter, r *http.Request) {
	JsonError(w, "The recovery phrase is available only locally, in the CLI wallet generator "+
		"or the Qt GUI. It is never served over HTTP.", http.StatusForbidden)
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

	// Enforce the documented minimum (8) at the HTTP boundary too, so the error
	// is clear rather than surfacing from deep in ChangePasswordInPlace
	// (QWID-2026-30).
	if err := wallet.ValidatePasswordStrength(req.NewPassword); err != nil {
		JsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Compute the new login hash BEFORE mutating the wallet, so a hashing
	// failure aborts with both stores still on the old password (QWID-2026-30).
	newHash, err := bcryptHash(req.NewPassword)
	if err != nil {
		JsonError(w, "Password change failed", http.StatusInternalServerError)
		return
	}

	wl := sess.Wallet
	if err := wl.ChangePasswordInPlace(req.CurrentPassword, req.NewPassword); err != nil {
		JsonError(w, "Wrong current password", http.StatusBadRequest)
		return
	}

	// The wallet file is now encrypted under the NEW password. Persist the
	// matching login hash; if that fails, roll the wallet back to the old
	// password so the login hash and the wallet file never diverge into a
	// permanent lockout (QWID-2026-30). Errors are surfaced, never swallowed.
	if Users != nil {
		Users.mu.Lock()
		entry, ok := Users.users[sess.Username]
		var saveErr error
		var oldHash string
		if ok {
			oldHash = entry.PasswordHash
			entry.PasswordHash = newHash
			saveErr = Users.save()
			if saveErr != nil {
				entry.PasswordHash = oldHash // undo the in-memory change
			}
		}
		Users.mu.Unlock()

		if ok && saveErr != nil {
			if rbErr := wl.ChangePasswordInPlace(req.NewPassword, req.CurrentPassword); rbErr != nil {
				logger.GetLogger().Printf("CRITICAL: password-change desync for %q: registry save failed (%v) and wallet rollback failed (%v); wallet is under the NEW password but the login hash is OLD", sess.Username, saveErr, rbErr)
				JsonError(w, "Password change failed and could not be rolled back; contact support before logging out", http.StatusInternalServerError)
				return
			}
			JsonError(w, "Password change failed; no changes were applied", http.StatusInternalServerError)
			return
		}
	}

	JsonResponse(w, map[string]string{"success": "Password changed"})
}
