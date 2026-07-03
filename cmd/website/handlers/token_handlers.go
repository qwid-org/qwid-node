package handlers

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"
	clientrpc "github.com/wonabru/qwid-node/rpc/client"
	"github.com/wonabru/qwid-node/services/transactionServices"
	"github.com/wonabru/qwid-node/statistics"
	"github.com/wonabru/qwid-node/transactionsDefinition"
)

var validTokenName = regexp.MustCompile(`^[a-zA-Z0-9 _-]{1,32}$`)
var validTokenSymbol = regexp.MustCompile(`^[A-Z0-9]{1,10}$`)

const tokenContractTemplate = `// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.4;

contract Token {
    address public minter;
    mapping(address => int64) public balances;
    string public constant name = "%s";
    string public constant symbol = "%s";
    uint8 public constant decimals = 8;

    function balanceOf(address owner) public view returns (int64) {
        return balances[owner];
    }

    event Sent(address from, address to, int64 amount);

    constructor() {
        minter = msg.sender;
        balances[msg.sender] = 100000000000000;
    }

    function mint(address receiver, int64 amount) public {
        require(msg.sender == minter);
        balances[receiver] += amount;
    }

    function transfer(address receiver, int64 amount) public {
        require(amount <= balances[msg.sender]);
        balances[msg.sender] -= amount;
        balances[receiver] += amount;
        emit Sent(msg.sender, receiver, amount);
    }
}
`

func CreateToken(w http.ResponseWriter, r *http.Request) {
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
		Name   string `json:"name"`
		Symbol string `json:"symbol"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Symbol = strings.TrimSpace(strings.ToUpper(req.Symbol))

	if !validTokenName.MatchString(req.Name) {
		JsonError(w, "Token name must be 1-32 alphanumeric characters", http.StatusBadRequest)
		return
	}
	if !validTokenSymbol.MatchString(req.Symbol) {
		JsonError(w, "Token symbol must be 1-10 uppercase letters/numbers", http.StatusBadRequest)
		return
	}

	// Generate Solidity source
	source := fmt.Sprintf(tokenContractTemplate, req.Name, req.Symbol)

	// Write to temp file
	tmpFile, err := os.CreateTemp("", "token_*.sol")
	if err != nil {
		JsonError(w, "Failed to create temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(source); err != nil {
		tmpFile.Close()
		JsonError(w, "Failed to write contract", http.StatusInternalServerError)
		return
	}
	tmpFile.Close()

	// Compile with solc
	cmd := exec.Command("solc", "--evm-version", "paris", "--bin", tmpFile.Name())
	var binOut, binErr bytes.Buffer
	cmd.Stdout = &binOut
	cmd.Stderr = &binErr
	if err := cmd.Run(); err != nil {
		JsonError(w, "Solidity compiler error: "+binErr.String(), http.StatusInternalServerError)
		return
	}

	// Parse bytecode (last non-empty line)
	lines := strings.Split(binOut.String(), "\n")
	bytecode := ""
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if len(line) > 0 {
			bytecode = line
			break
		}
	}
	if bytecode == "" {
		JsonError(w, "Compilation produced no bytecode", http.StatusInternalServerError)
		return
	}

	codeBytes, err := hex.DecodeString(bytecode)
	if err != nil {
		JsonError(w, "Invalid bytecode hex", http.StatusInternalServerError)
		return
	}

	// Build deployment transaction (empty recipient = contract creation)
	wl := sess.Wallet
	primary := !common.IsPaused()

	// Always include pubkey so the transaction can be verified
	// even if the user hasn't sent any prior transactions
	pk := common.PubKey{}
	if primary {
		pk = wl.Account1.PublicKey
	} else {
		pk = wl.Account2.PublicKey
	}

	txd := transactionsDefinition.TxData{
		Recipient:                  common.EmptyAddress(),
		Amount:                     0,
		OptData:                    codeBytes,
		Pubkey:                     pk,
		LockedAmount:               0,
		ReleasePerBlock:            0,
		DelegatedAccountForLocking: common.GetDelegatedAccountAddress(1),
	}

	par := transactionsDefinition.TxParam{
		ChainID:     int16(23),
		Sender:      wl.MainAddress,
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

	// Get current height
	clientrpc.InRPC <- SignMessage([]byte("STAT"))
	reply := <-clientrpc.OutRPC
	if bytes.Equal(reply, []byte("Timeout")) {
		JsonError(w, "Timeout getting network stats", http.StatusGatewayTimeout)
		return
	}

	sm := statistics.GetStatsManager()
	st := sm.Stats
	if err := common.Unmarshal(reply, common.StatDBPrefix, &st); err != nil {
		JsonError(w, "Failed to get network stats", http.StatusInternalServerError)
		return
	}

	tx.GasUsage = tx.GasUsageEstimate()
	tx.Height = st.Height

	if err := tx.CalcHashAndSet(); err != nil {
		JsonError(w, "Failed to calculate hash", http.StatusInternalServerError)
		return
	}

	if err := tx.Sign(wl, primary); err != nil {
		JsonError(w, "Failed to sign transaction", http.StatusInternalServerError)
		return
	}

	msg, err := transactionServices.GenerateTransactionMsg([]transactionsDefinition.Transaction{tx}, []byte("tx"), [2]byte{'T', 'T'})
	if err != nil {
		JsonError(w, "Failed to generate message", http.StatusInternalServerError)
		return
	}

	clientrpc.InRPC <- SignMessage(append([]byte("TRAN"), msg.GetBytes()...))
	<-clientrpc.OutRPC

	logger.GetLogger().Println("CreateToken: deployed token", req.Name, "("+req.Symbol+") tx:", tx.Hash.GetHex())

	JsonResponse(w, map[string]string{
		"success": "true",
		"txHash":  tx.Hash.GetHex(),
		"name":    req.Name,
		"symbol":  req.Symbol,
		"message": fmt.Sprintf("Token %s (%s) deployment transaction sent. 1,000,000 tokens minted to your address.", req.Name, req.Symbol),
	})
}
