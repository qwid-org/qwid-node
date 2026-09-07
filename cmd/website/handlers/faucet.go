package handlers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/qwid-org/qwid-node/logger"
)

// QWID-2026-29: the welcome faucet previously bounded only the DRAIN RATE (50
// welcome payments per hour). Over time that still lets a sybil registrant drain
// the operator's node wallet completely. FaucetLedger adds a hard LIFETIME
// budget: a persisted running total of welcome QWD paid, refused once the
// configured ceiling is reached. Being persisted, the budget survives restarts,
// so a node cannot be drained by cycling the website process.

// defaultFaucetLifetimeBudgetQWD is the total welcome QWD the faucet will ever
// pay out unless the operator overrides it with FAUCET_LIFETIME_BUDGET_QWD.
const defaultFaucetLifetimeBudgetQWD = 1_000_000

type faucetState struct {
	TotalPaidQWD int64 `json:"total_paid_qwd"`
}

type FaucetLedger struct {
	mu        sync.Mutex
	filePath  string
	budgetQWD int64
	totalPaid int64
}

// Faucet is the process-wide welcome-payment ledger, initialized by
// InitFaucetLedger at startup alongside the user registry.
var Faucet *FaucetLedger

// InitFaucetLedger loads (or creates) the persisted faucet ledger under basePath
// and resolves the lifetime budget from FAUCET_LIFETIME_BUDGET_QWD (a positive
// integer number of QWD), falling back to defaultFaucetLifetimeBudgetQWD.
func InitFaucetLedger(basePath string) error {
	fl := &FaucetLedger{
		filePath:  filepath.Join(basePath, "faucet.json"),
		budgetQWD: defaultFaucetLifetimeBudgetQWD,
	}
	if v := os.Getenv("FAUCET_LIFETIME_BUDGET_QWD"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			fl.budgetQWD = n
		} else {
			logger.GetLogger().Println("FAUCET_LIFETIME_BUDGET_QWD invalid; using default", defaultFaucetLifetimeBudgetQWD)
		}
	}
	if err := fl.load(); err != nil {
		return err
	}
	Faucet = fl
	logger.GetLogger().Printf("faucet lifetime budget: %d QWD; already paid: %d QWD", fl.budgetQWD, fl.totalPaid)
	return nil
}

func (f *FaucetLedger) load() error {
	data, err := os.ReadFile(f.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var st faucetState
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}
	f.totalPaid = st.TotalPaidQWD
	return nil
}

// saveLocked persists the running total. Caller holds f.mu.
func (f *FaucetLedger) saveLocked() error {
	data, err := json.MarshalIndent(faucetState{TotalPaidQWD: f.totalPaid}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(f.filePath, data, 0600)
}

// reserve atomically checks the lifetime budget and, if amountQWD fits, records
// it as paid and persists the new total. It returns false (reserving nothing) if
// the payment would exceed the budget or the total cannot be persisted — a
// persist failure must not hand out unmetered funds.
func (f *FaucetLedger) reserve(amountQWD int64) bool {
	if f == nil || amountQWD <= 0 {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.totalPaid+amountQWD > f.budgetQWD {
		return false
	}
	prev := f.totalPaid
	f.totalPaid += amountQWD
	if err := f.saveLocked(); err != nil {
		f.totalPaid = prev
		logger.GetLogger().Println("faucet: failed to persist reservation; refusing payment:", err)
		return false
	}
	return true
}

// refund returns a previously reserved amount to the budget after a welcome
// payment fails to send, so a transient failure does not permanently consume the
// lifetime budget.
func (f *FaucetLedger) refund(amountQWD int64) {
	if f == nil || amountQWD <= 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.totalPaid -= amountQWD
	if f.totalPaid < 0 {
		f.totalPaid = 0
	}
	if err := f.saveLocked(); err != nil {
		logger.GetLogger().Println("faucet: failed to persist refund:", err)
	}
}
