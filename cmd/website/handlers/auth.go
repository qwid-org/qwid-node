package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
	"github.com/qwid-org/qwid-node/services/transactionServices"
	"github.com/qwid-org/qwid-node/statistics"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/wallet"
)

// Rate limiting
type rateLimiter struct {
	mu      sync.Mutex
	entries map[string][]time.Time
}

var (
	registerLimiter = &rateLimiter{entries: make(map[string][]time.Time)}
	loginLimiter    = &rateLimiter{entries: make(map[string][]time.Time)}
	// WH-M11: per-account failed-login lockout (independent of the IP limiter,
	// which WH-M10 also hardens).
	loginLockout = &rateLimiter{entries: make(map[string][]time.Time)}
	// WH-M3: rate limiter for financial endpoints (send/stake/trade).
	financialLimiter = &rateLimiter{entries: make(map[string][]time.Time)}
	// WH-H2: global cap on welcome-transaction issuance, so an attacker with many
	// IPs cannot farm unlimited welcome funds via registration.
	welcomeLimiter = &rateLimiter{entries: make(map[string][]time.Time)}
)

const maxWelcomePerHour = 50

// FinancialRateLimit limits state-changing money operations per client IP.
func FinancialRateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !financialLimiter.allow(getClientIP(r), 20, time.Minute) {
			JsonError(w, "Too many requests. Please slow down.", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

const (
	maxFailedLogins = 5
	lockoutWindow   = 15 * time.Minute
)

// recordFailure logs a failed login for username. clearFailures resets them on
// a successful login. isLockedOut reports whether the account is currently locked.
func (rl *rateLimiter) recordFailure(username string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.entries[username] = append(rl.entries[username], time.Now())
}

func (rl *rateLimiter) clearFailures(username string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.entries, username)
}

func (rl *rateLimiter) isLockedOut(username string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-lockoutWindow)
	var valid []time.Time
	for _, t := range rl.entries[username] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	rl.entries[username] = valid
	return len(valid) >= maxFailedLogins
}

// cleanup drops keys whose timestamps are all older than maxAge, so the map does
// not grow unboundedly with one entry per IP/username ever seen (WH-M8).
func (rl *rateLimiter) cleanup(maxAge time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for k, times := range rl.entries {
		var valid []time.Time
		for _, t := range times {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.entries, k)
		} else {
			rl.entries[k] = valid
		}
	}
}

func init() {
	// WH-M8: periodically purge stale rate-limiter/lockout entries.
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			for _, rl := range []*rateLimiter{registerLimiter, loginLimiter, loginLockout, financialLimiter, welcomeLimiter} {
				rl.cleanup(time.Hour)
			}
		}
	}()
}

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

// getClientIP returns the client IP for rate limiting. WH-M10: X-Forwarded-For
// is attacker-controlled and is only trusted when TRUST_PROXY=true (i.e. the app
// really is behind a proxy that sets it). Otherwise the real transport peer
// address is used, so an attacker cannot rotate the header to bypass limits.
func getClientIP(r *http.Request) string {
	if os.Getenv("TRUST_PROXY") == "true" {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			return strings.TrimSpace(strings.Split(fwd, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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
		// WH-H3: do not disclose that the username exists. Return the same generic
		// 400 as other registration failures (not a distinct "already taken"/409),
		// so the response is not a trivially-scriptable enumeration oracle. Bulk
		// enumeration is further throttled by registerLimiter (5/10min/IP). The
		// existence check is retained because the wallet directory is derived from
		// the username and must not be overwritten.
		JsonError(w, "Registration could not be completed. Please try different details.", http.StatusBadRequest)
		return
	}

	// Create user wallet directory
	walletDir := UserWalletDir(WebsiteBasePath, req.Username)
	if err := os.MkdirAll(walletDir, 0700); err != nil {
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
		// WH-H3: Create also guards duplicates; on a TOCTOU race with the Exists
		// check above it returns "user already exists". Do not surface that — log
		// server-side and return the same generic message so this path is not a
		// fallback enumeration oracle.
		logger.GetLogger().Println("register: Users.Create failed:", err)
		JsonError(w, "Registration could not be completed. Please try different details.", http.StatusBadRequest)
		return
	}

	// Send welcome transaction (5000 QWD) from node wallet, subject to a global
	// hourly cap (WH-H2). Registration still succeeds if the cap is reached.
	if welcomeLimiter.allow("global", maxWelcomePerHour, time.Hour) {
		go sendWelcomeTransaction(wl.MainAddress)
	} else {
		logger.GetLogger().Println("welcome tx global cap reached; skipping for", req.Username)
	}

	// No recovery phrase here either: the phrase must never cross HTTP (design
	// decision 3), so website wallets are generated with random keys. Say so,
	// rather than letting the README's "new wallets are created from a 24-word
	// recovery phrase" be read as covering this flow.
	JsonResponse(w, map[string]interface{}{
		"success":  true,
		"address":  address,
		"mnemonic": false,
		"message": "Account created successfully. Please login. NOTE: this wallet has NO 24-word recovery phrase — " +
			"recovery phrases are never sent over the network. Your password and this site's encrypted wallet file " +
			"are the only way to reach these funds.",
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

	// WH-M11: reject logins for an account that has hit the failed-attempt limit.
	if loginLockout.isLockedOut(req.Username) {
		JsonError(w, "Account temporarily locked due to failed login attempts. Try again later.", http.StatusTooManyRequests)
		return
	}

	entry, err := Users.Authenticate(req.Username, req.Password)
	if err != nil {
		loginLockout.recordFailure(req.Username)
		JsonError(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}
	loginLockout.clearFailures(req.Username)

	// Load user's wallet
	userWallet, err := loadUserWallet(entry.WalletDir, req.Password)
	if err != nil {
		JsonError(w, fmt.Sprintf("Failed to load wallet: %v", err), http.StatusInternalServerError)
		return
	}

	// WH-H8: invalidate any prior sessions for this user before issuing a new one.
	Sessions.DeleteByUsername(req.Username)

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

	reply := clientrpc.Call(SignMessage([]byte("STAT")))
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

	clientrpc.Call(SignMessage(append([]byte("TRAN"), msg.GetBytes()...)))

	logger.GetLogger().Println("sendWelcomeTransaction: sent", welcomeAmountQWD, "QWD to", recipient.GetHex())
}
