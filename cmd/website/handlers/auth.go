package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"
	clientrpc "github.com/wonabru/qwid-node/rpc/client"
	"github.com/wonabru/qwid-node/services/transactionServices"
	"github.com/wonabru/qwid-node/statistics"
	"github.com/wonabru/qwid-node/transactionsDefinition"
	"github.com/wonabru/qwid-node/wallet"
)

// Rate limiting
type rateLimiter struct {
	mu      sync.Mutex
	entries map[string][]time.Time
}

var (
	registerLimiter = &rateLimiter{entries: make(map[string][]time.Time)}
	loginLimiter    = &rateLimiter{entries: make(map[string][]time.Time)}
)

func (rl *rateLimiter) allow(ip string, maxCount int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-window)

	// Clean old entries
	var valid []time.Time
	for _, t := range rl.entries[ip] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	rl.entries[ip] = valid

	if len(valid) >= maxCount {
		return false
	}
	rl.entries[ip] = append(rl.entries[ip], now)
	return true
}

func getClientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	return r.RemoteAddr
}

func Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		JsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := getClientIP(r)
	if !registerLimiter.allow(ip, 5, 10*time.Minute) {
		JsonError(w, "Too many registration attempts. Try again later.", http.StatusTooManyRequests)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if len(req.Username) < 3 || len(req.Username) > 32 {
		JsonError(w, "Username must be 3-32 characters", http.StatusBadRequest)
		return
	}
	// WH-M1: enforce the shared minimum password strength (8+ chars).
	if err := wallet.ValidatePasswordStrength(req.Password); err != nil {
		JsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check for valid characters in username
	for _, c := range req.Username {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			JsonError(w, "Username can only contain letters, numbers, underscores, and hyphens", http.StatusBadRequest)
			return
		}
	}

	if Users.Exists(req.Username) {
		JsonError(w, "Username already taken", http.StatusConflict)
		return
	}

	// Create user wallet directory
	walletDir := UserWalletDir(WebsiteBasePath, req.Username)
	if err := os.MkdirAll(walletDir, 0755); err != nil {
		JsonError(w, "Failed to create wallet directory", http.StatusInternalServerError)
		return
	}

	// Create wallet
	wl := wallet.EmptyWallet(0, SigName, SigName2)
	wl.HomePath = walletDir
	wl.SetPassword(req.Password)
	wl.Iv = wallet.GenerateNewIv()

	acc, err := wallet.GenerateNewAccount(wl, wl.SigName)
	if err != nil {
		if !common.IsPaused() {
			JsonError(w, fmt.Sprintf("Failed to generate primary account: %v", err), http.StatusInternalServerError)
			return
		}
		logger.GetLogger().Println("Warning: primary account generation failed (paused):", err)
	} else {
		wl.MainAddress = acc.Address
		acc.PublicKey.MainAddress = wl.MainAddress
		wl.Account1 = acc
		copy(wl.Account1.EncryptedSecretKey, acc.EncryptedSecretKey)
	}

	acc, err = wallet.GenerateNewAccount(wl, wl.SigName2)
	if err != nil {
		if !common.IsPaused2() {
			JsonError(w, fmt.Sprintf("Failed to generate secondary account: %v", err), http.StatusInternalServerError)
			return
		}
		logger.GetLogger().Println("Warning: secondary account generation failed (paused):", err)
	} else {
		// If primary failed (paused), use secondary address as main
		emptyAddr := common.EmptyAddress()
		if bytes.Equal(wl.MainAddress.GetBytes(), emptyAddr.GetBytes()) {
			wl.MainAddress = acc.Address
		}
		acc.PublicKey.MainAddress = wl.MainAddress
		wl.Account2 = acc
		copy(wl.Account2.EncryptedSecretKey, acc.EncryptedSecretKey)
	}

	if err := wl.StoreJSON(); err != nil {
		JsonError(w, fmt.Sprintf("Failed to store wallet: %v", err), http.StatusInternalServerError)
		return
	}

	address := wl.MainAddress.GetHex()

	// Register user
	if err := Users.Create(req.Username, req.Password, walletDir, address); err != nil {
		JsonError(w, fmt.Sprintf("Failed to register user: %v", err), http.StatusInternalServerError)
		return
	}

	// Send welcome transaction (5000 QWD) from node wallet
	go sendWelcomeTransaction(wl.MainAddress)

	JsonResponse(w, map[string]interface{}{
		"success": true,
		"address": address,
		"message": "Account created successfully. Please login.",
	})
}

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		JsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := getClientIP(r)
	if !loginLimiter.allow(ip, 10, 10*time.Minute) {
		JsonError(w, "Too many login attempts. Try again later.", http.StatusTooManyRequests)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	entry, err := Users.Authenticate(req.Username, req.Password)
	if err != nil {
		JsonError(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Load user's wallet
	userWallet, err := loadUserWallet(entry.WalletDir, req.Password)
	if err != nil {
		JsonError(w, fmt.Sprintf("Failed to load wallet: %v", err), http.StatusInternalServerError)
		return
	}

	token, err := Sessions.Create(req.Username, userWallet)
	if err != nil {
		JsonError(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	Sessions.SetCookie(w, token)

	JsonResponse(w, map[string]interface{}{
		"success":  true,
		"username": req.Username,
		"address":  entry.Address,
	})
}

func Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		JsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		Sessions.Delete(cookie.Value)
	}
	Sessions.ClearCookie(w)

	JsonResponse(w, map[string]string{"success": "true"})
}

func GetSessionInfo(w http.ResponseWriter, r *http.Request) {
	sess := GetSession(r.Context())
	if sess == nil {
		JsonError(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	entry := Users.GetEntry(sess.Username)
	address := ""
	if entry != nil {
		address = entry.Address
	}

	JsonResponse(w, map[string]interface{}{
		"username": sess.Username,
		"address":  address,
	})
}

func loadUserWallet(walletDir, password string) (*wallet.Wallet, error) {
	return wallet.LoadJSONFromDir(walletDir, 0, password, SigName, SigName2)
}

const welcomeAmountQWD = 5000

func sendWelcomeTransaction(recipient common.Address) {
	if NodeWallet == nil {
		logger.GetLogger().Println("sendWelcomeTransaction: node wallet not loaded")
		return
	}

	amount := int64(welcomeAmountQWD * 1e8)

	txd := transactionsDefinition.TxData{
		Recipient:                  recipient,
		Amount:                     amount,
		OptData:                    []byte{},
		Pubkey:                     common.PubKey{},
		LockedAmount:               0,
		ReleasePerBlock:            0,
		DelegatedAccountForLocking: common.GetDelegatedAccountAddress(1),
	}

	par := transactionsDefinition.TxParam{
		ChainID:     int16(23),
		Sender:      NodeWallet.MainAddress,
		SendingTime: common.GetCurrentTimeStampInSecond(),
		Nonce:       common.RandomNonce(),
	}

	tx := transactionsDefinition.Transaction{
		TxData:    txd,
		TxParam:   par,
		Hash:      common.Hash{},
		Signature: common.Signature{},
		Height:    0,
		GasPrice:  int64(rand.Intn(0x0000000f)) + 1,
		GasUsage:  0,
	}

	clientrpc.InRPC <- SignMessage([]byte("STAT"))
	reply := <-clientrpc.OutRPC
	if bytes.Equal(reply, []byte("Timeout")) {
		logger.GetLogger().Println("sendWelcomeTransaction: timeout getting stats")
		return
	}

	sm := statistics.GetStatsManager()
	st := sm.Stats
	if err := common.Unmarshal(reply, common.StatDBPrefix, &st); err != nil {
		logger.GetLogger().Println("sendWelcomeTransaction: failed to unmarshal stats:", err)
		return
	}

	tx.GasUsage = tx.GasUsageEstimate()
	tx.Height = st.Height

	if err := tx.CalcHashAndSet(); err != nil {
		logger.GetLogger().Println("sendWelcomeTransaction: failed to calc hash:", err)
		return
	}

	primary := !common.IsPaused()
	if err := tx.Sign(NodeWallet, primary); err != nil {
		logger.GetLogger().Println("sendWelcomeTransaction: failed to sign:", err)
		return
	}

	msg, err := transactionServices.GenerateTransactionMsg([]transactionsDefinition.Transaction{tx}, []byte("tx"), [2]byte{'T', 'T'})
	if err != nil {
		logger.GetLogger().Println("sendWelcomeTransaction: failed to generate msg:", err)
		return
	}

	clientrpc.InRPC <- SignMessage(append([]byte("TRAN"), msg.GetBytes()...))
	<-clientrpc.OutRPC

	logger.GetLogger().Println("sendWelcomeTransaction: sent", welcomeAmountQWD, "QWD to", recipient.GetHex())
}
