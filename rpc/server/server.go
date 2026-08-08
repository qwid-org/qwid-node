package serverrpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/rpc"
	"os"
	"strconv"
	"sync/atomic"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/blocks"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/core/stateDB"
	"github.com/wonabru/qwid-node/crypto/oqs"
	"github.com/wonabru/qwid-node/logger"
	"github.com/wonabru/qwid-node/pubkeys"
	nonceServices "github.com/wonabru/qwid-node/services/nonceService"
	"github.com/wonabru/qwid-node/services/transactionServices"
	"github.com/wonabru/qwid-node/statistics"
	"github.com/wonabru/qwid-node/tcpip"
	"github.com/wonabru/qwid-node/transactionsDefinition"
	"github.com/wonabru/qwid-node/transactionsPool"
	"github.com/wonabru/qwid-node/wallet"
)

type Listener struct {
	remoteIP string
}

func extractRemoteIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}

var rpcConnCount int64 // NP-H6: current in-flight RPC connections

// tryAcquireRPCSlot atomically reserves a connection slot if under the cap,
// returning true on success (a rejected acquire rolls the counter back). NP-H6.
func tryAcquireRPCSlot() bool {
	if atomic.AddInt64(&rpcConnCount, 1) > int64(common.MaxConcurrentRPCConnections) {
		atomic.AddInt64(&rpcConnCount, -1)
		return false
	}
	return true
}

func releaseRPCSlot() { atomic.AddInt64(&rpcConnCount, -1) }

func ListenRPC() {
	// NP-C4: bind the wallet-node RPC to loopback by default so unauthenticated
	// operations (e.g. TRAN) are not exposed to the network. Operators who
	// deliberately run the wallet on a separate host can override the bind host
	// via RPC_BIND_ADDRESS (understanding the exposure).
	bindHost := os.Getenv("RPC_BIND_ADDRESS")
	if bindHost == "" {
		bindHost = "127.0.0.1"
	}
	var address = bindHost + ":" + strconv.Itoa(tcpip.Ports[tcpip.RPCTopic])
	listener, err := net.Listen("tcp", address)
	if err != nil {
		logger.GetLogger().Fatalf("Error resolving TCP address: %v", err)
	}
	defer listener.Close()
	logger.GetLogger().Printf("RPC server listening on %s", address)
	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.GetLogger().Printf("RPC accept error: %v", err)
			continue
		}
		// NP-H6: bound concurrent RPC connections.
		if !tryAcquireRPCSlot() {
			logger.GetLogger().Printf("RPC connection cap (%d) reached; rejecting %s", common.MaxConcurrentRPCConnections, conn.RemoteAddr())
			conn.Close()
			continue
		}
		remoteIP := extractRemoteIP(conn.RemoteAddr().String())
		go func(c net.Conn, ip string) {
			defer releaseRPCSlot()
			srv := rpc.NewServer()
			srv.Register(&Listener{remoteIP: ip})
			srv.ServeConn(c)
		}(conn, remoteIP)
	}
}

func (l *Listener) Send(lineBeg []byte, reply *[]byte) error {
	if len(lineBeg) < 4 {
		*reply = []byte("Error with message. Too small length calling server")
		return nil
	}

	line, left, err := common.BytesWithLenToBytes(lineBeg)
	if err != nil {
		*reply = []byte("wrong query")
		return nil
	}
	if len(line) < 4 {
		*reply = []byte("wrong query length")
		return nil
	}
	operation := string(line[0:4])

	verificationNeeded := true
	for _, noVerification := range common.ConnectionsWithoutVerification {
		if bytes.Equal([]byte(operation), noVerification) {
			verificationNeeded = false
			break
		}
	}
	byt := []byte{}
	signatureBytes := []byte{}

	if len(line) > 4 {
		byt = line[4:]
	}
	signatureBytes = left
	if verificationNeeded {
		if l.remoteIP != "127.0.0.1" && l.remoteIP != "::1" {
			*reply = []byte("Private operations only allowed from localhost")
			return nil
		}
		if len(signatureBytes) == 0 {
			*reply = []byte("Invalid signature with length 0")
			return nil
		}
		activeWallet := wallet.GetActiveWallet()

		pubKey := activeWallet.Account1.PublicKey
		if signatureBytes[0] != 0 {
			pubKey = activeWallet.Account2.PublicKey
		}

		if !wallet.Verify(common.BytesToLenAndBytes(line), signatureBytes, pubKey.GetBytes(), common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2()) {
			*reply = []byte("Invalid signature")
			return nil
		}
	}

	switch operation {
	case "STAT":
		handleSTAT(byt, reply)
	case "WALL":
		handleWALL(byt, reply)
	case "TRAN":
		handleTRAN(byt, reply)
	case "CNCL":
		handleCNCL(byt, reply)
	case "VIEW":
		handleVIEW(byt, reply)
	case "ACCT":
		handleACCT(byt, reply)
	case "MINE":
		handleMINE(byt, reply)
	case "CHCK":
		handleCHECK(byt, reply)
	case "ENCR":
		handleENCR(byt, reply)
	case "VOTE":
		handleVOTE(byt, reply)
	case "DETS":
		handleDETS(byt, reply)
	case "STAK":
		handleSTAK(byt, reply)
	case "ACCS":
		handleACCS(byt, reply)
	case "ADEX":
		handleADEX(byt, reply)
	case "LTKN":
		handleLTKN(byt, reply)
	case "GTBL":
		handleGTBL(byt, reply)
	case "ESCR":
		handleESCR(byt, reply)
	case "MULT":
		handleMULT(byt, reply)
	case "PEND":
		handlePEND(byt, reply)
	case "PEER":
		handlePEER(byt, reply)
	case "PUBA":
		handlePUBA(byt, reply)
	case "HELO":
		handleHELO(byt, reply)
	case "VALS":
		handleVALS(byt, reply)
	default:
		*reply = []byte("Invalid operation")
	}
	return nil
}

func handleWALL(line []byte, reply *[]byte) {
	logger.GetLogger().Println(string(line))
	w := wallet.GetActiveWallet()
	// NP-C5: return a redacted public projection — never the KdfSalt, the
	// EncryptedSecretKey, the Iv, or HomePath (the offline-attack material).
	r, err := json.Marshal(w.PublicView())
	if err != nil {
		logger.GetLogger().Println("Cannot marshal wallet public view")
		return
	}
	*reply = r
}

func handleCHECK(line []byte, reply *[]byte) {
	logger.GetLogger().Println(string(line))
	w := wallet.GetActiveWallet()
	*reply = nil
	_, err := pubkeys.LoadPubKey(w.Account1.Address.GetBytes())
	if err != nil {
		*reply = []byte("Primary pubkey is not registered in blockchain. Please send transaction including primary PubKey to blockchain")

	}
	_, err = pubkeys.LoadPubKey(w.Account2.Address.GetBytes())
	if err != nil {
		*reply = []byte("Secondary pubkey is not registered in blockchain. Please send transaction including secondary PubKey to blockchain")
	}
}

func handleESCR(line []byte, reply *[]byte) {
	logger.GetLogger().Println(string(line))
	*reply = nil
	//primary := line[0] == 0
	//delay := common.GetInt64FromByte(line[1:9])

}

func handleMULT(line []byte, reply *[]byte) {
	logger.GetLogger().Println(string(line))
	*reply = nil
}

func handleENCR(line []byte, reply *[]byte) {
	logger.GetLogger().Println(string(line))
	*reply = nil

	enb1, err := oqs.GenerateBytesFromParams(common.SigName(), common.PubKeyLength(false), common.PrivateKeyLength(), common.SignatureLength(false), common.IsPaused())
	if err != nil {
		*reply = []byte(err.Error())
		return
	}
	enb := common.BytesToLenAndBytes(enb1)

	enb2, err := oqs.GenerateBytesFromParams(common.SigName2(), common.PubKeyLength2(false), common.PrivateKeyLength2(), common.SignatureLength2(false), common.IsPaused2())
	if err != nil {
		*reply = []byte(err.Error())
		return
	}
	enb = append(enb, common.BytesToLenAndBytes(enb2)...)
	*reply = enb
}

func handleHELO(line []byte, reply *[]byte) {
	if common.IsPaused() {
		*reply = []byte("Hi1")

	} else {
		*reply = []byte("Hi0")
	}
}

func handleMINE(line []byte, reply *[]byte) {
	ip := [4]byte{0, 0, 0, 0}
	if len(line) == 4 {
		copy(ip[:], line)
	}
	firstDel := common.GetDelegatedAccountAddress(1)
	if firstDel.GetHex() != common.GetDelegatedAccount().Hex() {
		nonceServices.InitNonceService()
		go nonceServices.StartSubscribingNonceMsgSelf()
		go nonceServices.StartSubscribingNonceMsg(tcpip.MyIP)
		if bytes.Equal(ip[:], []byte{0, 0, 0, 0}) == false {
			go nonceServices.StartSubscribingNonceMsg(ip)
		}
		*reply = []byte("Mining initiated")
	} else {
		*reply = []byte("First delegated account just automatically mines")
	}

}

func handleVOTE(line []byte, reply *[]byte) {
	enb1, line, err := common.BytesWithLenToBytes(line)
	if err != nil {
		*reply = []byte("cannot decode bytes 1")
		return
	}
	en1 := []byte{}
	if len(enb1) > 0 {
		config1, err := oqs.FromBytesToEncryptionConfig(enb1)
		if err != nil {
			*reply = []byte("cannot decode encryption from bytes 1")
			return
		}
		en1, _ = oqs.GenerateBytesFromParams(config1.SigName, config1.PubKeyLength, config1.PrivateKeyLength, config1.SignatureLength, config1.IsPaused)
	}
	enb2, left, err := common.BytesWithLenToBytes(line)
	if err != nil || len(left) > 0 {
		*reply = []byte("cannot decode bytes 2")
		return
	}
	en2 := []byte{}
	if len(enb2) > 0 {
		config2, err := oqs.FromBytesToEncryptionConfig(enb2)
		if err != nil {
			*reply = []byte("cannot decode encryption from bytes 2")
			return
		}
		en2, _ = oqs.GenerateBytesFromParams(config2.SigName, config2.PubKeyLength, config2.PrivateKeyLength, config2.SignatureLength, config2.IsPaused)
	}
	nonceServices.SetEncryptionData(en1, en2)
	*reply = []byte("Voting for new encryption is successful")
}

func handleGTBL(byt []byte, reply *[]byte) {
	if len(byt) == 2*common.AddressLength {
		addr := common.Address{}
		addr.Init(byt[:common.AddressLength])
		coin := common.Address{}
		coin.Init(byt[common.AddressLength : 2*common.AddressLength])
		inputs := stateDB.BalanceOfFunc
		ba := common.LeftPadBytes(addr.GetBytes(), 32)
		inputs = append(inputs, ba...)

		h := common.GetHeight()

		bl, err := blocks.LoadBlock(h)
		if err != nil {
			*reply = []byte(fmt.Sprint(err))
			return
		}

		output, _, _, _, _, err := blocks.GetViewFunctionReturns(coin, inputs, bl)
		if err != nil {
			*reply = []byte("Some error in SC query GTBL")
			return
		}
		*reply = common.Hex2Bytes(output)
	} else {
		*reply = []byte("Invalid query GTBL")
	}
}

func handleLTKN(line []byte, reply *[]byte) {
	blocks.StateMutex.RLock()
	accs := blocks.State.GetAllRegisteredTokens()
	blocks.StateMutex.RUnlock()
	if len(accs) > 0 {
		newAccs := map[string]stateDB.TokenInfo{}
		for k, v := range accs {
			newAccs[hex.EncodeToString(k[:])] = v
		}
		am, err := json.Marshal(newAccs)
		if err != nil {
			*reply = []byte(fmt.Sprint(err))
			return
		}
		*reply = am
	}
}

func handleADEX(byt []byte, reply *[]byte) {
	// NP-H8: validate length before slicing (unauthenticated, network-reachable).
	if len(byt) < common.AddressLength {
		*reply = []byte("invalid ADEX request length")
		return
	}
	dexAcc := account.GetDexAccountByAddressBytes(byt[:common.AddressLength])
	marshal := dexAcc.Marshal()
	*reply = marshal
}

func handleVIEW(line []byte, reply *[]byte) {
	m := blocks.PasiveFunction{}

	err := json.Unmarshal(line, &m)
	if err != nil {
		*reply = []byte(fmt.Sprint(err))
		return
	}

	bl, err := blocks.LoadBlock(m.Height)
	if err != nil {
		*reply = []byte(fmt.Sprint(err))
		return
	}

	l, logs, _, _, _, err := blocks.GetViewFunctionReturns(m.Address, m.OptData, bl)
	if err != nil {
		*reply = []byte(fmt.Sprint(logs))
	}
	*reply, _ = hex.DecodeString(l)
}

func handleDETS(line []byte, reply *[]byte) {

	switch len(line) {
	case common.AddressLength:
		byt := [common.AddressLength]byte{}
		copy(byt[:], line)
		account.AccountsRWMutex.RLock()
		acc := account.Accounts.AllAccounts[byt]
		account.AccountsRWMutex.RUnlock()
		// Same as handleACCT: the state no longer carries the history lists,
		// so fill the transport slices from the DB index - the address-details
		// views (webui explorer, tx history) are built from this reply.
		acc.TransactionsSender = account.GetTxHistorySent(byt, 50)
		acc.TransactionsRecipient = account.GetTxHistoryReceived(byt, 50)
		am := acc.Marshal()
		*reply = append([]byte("AC"), am...)
		break
	case common.HashLength:
		location := ""
		var tx transactionsDefinition.Transaction
		var err error

		// Check confirmed DB (TT)
		tx, err = transactionsDefinition.LoadFromDBPoolTx(common.TransactionDBPrefix[:], line)
		if err == nil {
			location = "confirmed_db"
		}

		// Check pool DB (D0)
		if location == "" {
			tx, err = transactionsDefinition.LoadFromDBPoolTx(common.TransactionPoolHashesDBPrefix[:], line)
			if err == nil {
				location = "pool_db"
			}
		}

		// Check in-memory pools
		if location == "" && transactionsPool.PoolsTx.HasTransaction(line) {
			location = "memory_main"
		}
		if location == "" && transactionsPool.PoolTxEscrow.HasTransaction(line) {
			location = "memory_escrow"
		}
		if location == "" && transactionsPool.PoolTxMultiSign.HasTransaction(line) {
			location = "memory_multisign"
		}

		if location == "" {
			logger.GetLogger().Println("transaction not found in any location:", hex.EncodeToString(line))
			*reply = []byte("TX")
			return
		}
		txb := tx.GetBytes()
		locationBytes := []byte(location)
		// Format: "TX" + 1 byte location length + location string + tx bytes
		*reply = append([]byte("TX"), byte(len(locationBytes)))
		*reply = append(*reply, locationBytes...)
		*reply = append(*reply, txb...)
		break
	case 8:
		height := common.GetInt64FromByte(line)
		block, err := blocks.LoadBlock(height)
		if err != nil {
			logger.GetLogger().Println(err)
			*reply = []byte("BL")
			return
		}
		bb := block.GetBytes()
		*reply = append([]byte("BL"), bb...)
		break
	default:
		*reply = []byte("NO")
	}
}

func handleACCT(line []byte, reply *[]byte) {
	// NP-M8: validate length before slicing (network-reachable).
	if len(line) < common.AddressLength {
		*reply = []byte("invalid ACCT request length")
		return
	}
	byt := [common.AddressLength]byte{}
	copy(byt[:], line[:common.AddressLength])
	account.AccountsRWMutex.RLock()
	acc := account.Accounts.AllAccounts[byt] // value copy
	account.AccountsRWMutex.RUnlock()
	// The state no longer carries the history lists - fill the transport
	// slices with the last 50 hashes from the DB index. SentCount and
	// ReceivedCount travel alongside, so clients see the true totals even
	// though the lists are capped.
	acc.TransactionsSender = account.GetTxHistorySent(byt, 50)
	acc.TransactionsRecipient = account.GetTxHistoryReceived(byt, 50)
	am := acc.Marshal()

	*reply = am
}

func handleSTAK(line []byte, reply *[]byte) {
	// NP-H7: need the address plus the 1-byte delegated-account index
	// (unauthenticated, network-reachable). n is a byte, so it always indexes
	// StakingAccounts (len 256) safely.
	if len(line) < common.AddressLength+1 {
		*reply = []byte("invalid STAK request length")
		return
	}
	byt := [common.AddressLength]byte{}
	copy(byt[:], line[:common.AddressLength])
	n := int(line[common.AddressLength])
	// StakingAccount is copied by value, but StakingDetails is a map. A value
	// copy therefore still points at the live map and it must be marshalled while
	// holding the read lock. Unlocking before Marshal allowed block processing to
	// update StakingDetails concurrently, causing the runtime fatal error
	// "concurrent map iteration and map write".
	account.StakingRWMutex.RLock()
	acc := account.StakingAccounts[n].AllStakingAccounts[byt]
	am := acc.Marshal()
	account.StakingRWMutex.RUnlock()
	// GetLockedAmount acquires StakingRWMutex internally — must be called outside our lock
	locked, _ := account.GetLockedAmount(byt[:], common.GetHeight(), n)
	*reply = append(am, common.GetByteInt64(locked)...)
}

// handleACCS returns an address's staking accounts across ALL delegated accounts
// in a single response, so clients need one RPC instead of 255 STAK calls.
// Response: a 4-byte little-endian entry count, then per entry a length-prefixed
// blob = marshaled StakingAccount followed by its 8-byte locked amount.
func handleACCS(line []byte, reply *[]byte) {
	if len(line) < common.AddressLength {
		*reply = []byte("invalid ACCS request length")
		return
	}
	byt := [common.AddressLength]byte{}
	copy(byt[:], line[:common.AddressLength])

	// StakingDetails is a map, so Marshal must run under the read lock (see
	// handleSTAK). GetLockedAmount takes the lock itself, so collect the marshaled
	// accounts first and query locked amounts after releasing the lock.
	type stakeEntry struct {
		id        int
		marshaled []byte
	}
	entries := []stakeEntry{}
	account.StakingRWMutex.RLock()
	for i := 1; i < 256; i++ {
		acc := account.StakingAccounts[i].AllStakingAccounts[byt]
		if acc.StakedBalance > 0 || acc.StakingRewards > 0 {
			entries = append(entries, stakeEntry{id: i, marshaled: acc.Marshal()})
		}
	}
	account.StakingRWMutex.RUnlock()

	h := common.GetHeight()
	out := common.GetByteInt32(int32(len(entries)))
	for _, e := range entries {
		locked, _ := account.GetLockedAmount(byt[:], h, e.id)
		blob := make([]byte, 0, len(e.marshaled)+8)
		blob = append(blob, e.marshaled...)
		blob = append(blob, common.GetByteInt64(locked)...)
		out = append(out, common.BytesToLenAndBytes(blob)...)
	}
	*reply = out
}

func handleTRAN(byt []byte, reply *[]byte) {

	*reply = []byte("transaction sent")
	transactionServices.OnMessage([4]byte{0, 0, 0, 0}, byt)

}

func handleCNCL(byt []byte, reply *[]byte) {

	*reply = []byte("hash is not 32 bytes")

	if len(byt) == common.HashLength {
		w := wallet.GetActiveWallet()
		if transactionsPool.PoolsTx.TransactionExists(byt) {
			tx := transactionsPool.PoolsTx.PopTransactionByHash(byt)
			if bytes.Equal(tx.TxParam.Sender.GetBytes(), w.MainAddress.GetBytes()) == false {
				transactionsPool.PoolsTx.AddTransaction(tx, tx.Hash)
				*reply = []byte("you are not the owner of transaction")
				return
			}
			transactionsPool.PoolsTx.BanTransactionByHash(byt)
			*reply = []byte("transaction cancelled locally")
			return
		}
		if transactionsPool.PoolTxEscrow.TransactionExists(byt) {
			tx, _ := transactionsPool.PoolTxEscrow.GetTransactionByHash(byt)
			if bytes.Equal(tx.TxParam.Sender.GetBytes(), w.MainAddress.GetBytes()) == false {
				*reply = []byte("you are not the owner of transaction")
				return
			}
			// Escrow has already been accepted by consensus. Do not remove only
			// this node's copy; the WebUI must submit a signed cancellation tx.
			*reply = []byte("escrow cancellation transaction required")
			return
		}
		if transactionsPool.PoolTxMultiSign.TransactionExists(byt) {
			tx := transactionsPool.PoolTxMultiSign.PopTransactionByHash(byt)
			if bytes.Equal(tx.TxParam.Sender.GetBytes(), w.MainAddress.GetBytes()) == false {
				transactionsPool.PoolTxMultiSign.AddTransaction(tx, tx.Hash)
				*reply = []byte("you are not the owner of transaction")
				return
			}
			transactionsPool.PoolTxMultiSign.BanTransactionByHash(byt)
			*reply = []byte("transaction cancelled locally")
			return
		}
		*reply = []byte("transaction not found in a cancellable pool")
		return
	}

}

func handleSTAT(byt []byte, reply *[]byte) {
	sm := statistics.GetStatsManager()
	// Update pending transactions count in real-time
	sm.Mu.Lock()
	sm.Stats.TransactionsPending = transactionsPool.PoolsTx.NumberOfTransactions()
	sm.Stats.Height = common.GetHeight()
	sm.Stats.HeightMax = common.GetHeightMax()
	sm.Stats.Syncing = common.IsSyncing.Load()
	lastBlock, err := blocks.LoadBlock(sm.Stats.Height)
	if err == nil {
		sm.Stats.Difficulty = lastBlock.BaseBlock.BaseHeader.Difficulty
	}
	sm.Mu.Unlock()
	msb, err := common.Marshal(sm.Stats, common.StatDBPrefix)
	if err != nil {
		logger.GetLogger().Println(err)
		return
	}
	*reply = msb
}

func handlePEND(byt []byte, reply *[]byte) {
	// Get pending transactions from all pools
	type PendingTx struct {
		Hash      string  `json:"hash"`
		Sender    string  `json:"sender"`
		Recipient string  `json:"recipient"`
		Amount    float64 `json:"amount"`
		Height    int64   `json:"height"`
		Pool      string  `json:"pool"`
	}

	pendingTxs := []PendingTx{}

	// Get from main pool
	txs := transactionsPool.PoolsTx.PeekTransactions(50, 0)
	for _, tx := range txs {
		pendingTxs = append(pendingTxs, PendingTx{
			Hash:      tx.Hash.GetHex(),
			Sender:    tx.TxParam.Sender.GetHex(),
			Recipient: tx.TxData.Recipient.GetHex(),
			Amount:    float64(tx.TxData.Amount) / 1e8,
			Height:    tx.Height,
			Pool:      "main",
		})
	}

	// Get from escrow pool (use max height to return all pending escrow txs)
	escrowTxs := transactionsPool.PoolTxEscrow.PeekTransactions(50, math.MaxInt64)
	for _, tx := range escrowTxs {
		pendingTxs = append(pendingTxs, PendingTx{
			Hash:      tx.Hash.GetHex(),
			Sender:    tx.TxParam.Sender.GetHex(),
			Recipient: tx.TxData.Recipient.GetHex(),
			Amount:    float64(tx.TxData.Amount) / 1e8,
			Height:    tx.Height,
			Pool:      "escrow",
		})
	}

	// Get from multi-sig pool
	multiTxs := transactionsPool.PoolTxMultiSign.PeekTransactions(50, math.MaxInt64)
	for _, tx := range multiTxs {
		pendingTxs = append(pendingTxs, PendingTx{
			Hash:      tx.Hash.GetHex(),
			Sender:    tx.TxParam.Sender.GetHex(),
			Recipient: tx.TxData.Recipient.GetHex(),
			Amount:    float64(tx.TxData.Amount) / 1e8,
			Height:    tx.Height,
			Pool:      "multisig",
		})
	}

	result, err := json.Marshal(pendingTxs)
	if err != nil {
		*reply = []byte("[]")
		return
	}
	*reply = result
}

func handlePEER(byt []byte, reply *[]byte) {
	type PeersResponse struct {
		ConnectedPeers []map[string]interface{} `json:"connectedPeers"`
		BannedPeers    []map[string]interface{} `json:"bannedPeers"`
		WhitelistedIPs []string                 `json:"whitelistedIPs"`
		PeerCount      int                      `json:"peerCount"`
		BannedCount    int                      `json:"bannedCount"`
	}

	connectedPeers := tcpip.GetConnectedPeersInfo()
	bannedPeers := tcpip.GetBannedPeersInfo()
	whitelistedIPs := tcpip.GetWhitelistedIPs()

	resp := PeersResponse{
		ConnectedPeers: connectedPeers,
		BannedPeers:    bannedPeers,
		WhitelistedIPs: whitelistedIPs,
		PeerCount:      len(connectedPeers),
		BannedCount:    len(bannedPeers),
	}

	result, err := json.Marshal(resp)
	if err != nil {
		*reply = []byte("{\"error\":\"failed to marshal peer info\"}")
		return
	}
	*reply = result
}

func handlePUBA(line []byte, reply *[]byte) {
	if len(line) < common.AddressLength {
		*reply = []byte("{\"error\":\"invalid address length\"}")
		return
	}

	addr := common.Address{}
	err := addr.Init(line[:common.AddressLength])
	if err != nil {
		*reply = []byte("{\"error\":\"invalid address\"}")
		return
	}

	type PubKeyAddrInfo struct {
		Address string `json:"address"`
		Primary bool   `json:"primary"`
	}
	type PubKeyResponse struct {
		HasPrimary   bool             `json:"hasPrimary"`
		HasSecondary bool             `json:"hasSecondary"`
		Addresses    []PubKeyAddrInfo `json:"addresses"`
	}

	resp := PubKeyResponse{}
	addresses, err := pubkeys.LoadAddresses(addr)
	if err == nil {
		for _, a := range addresses {
			resp.Addresses = append(resp.Addresses, PubKeyAddrInfo{
				Address: a.GetHex(),
				Primary: a.Primary,
			})
			if a.Primary {
				resp.HasPrimary = true
			} else {
				resp.HasSecondary = true
			}
		}
	}

	result, err := json.Marshal(resp)
	if err != nil {
		*reply = []byte("{\"error\":\"failed to marshal pubkey info\"}")
		return
	}
	*reply = result
}

func handleVALS(line []byte, reply *[]byte) {
	type ValidatorInfo struct {
		ID               int     `json:"id"`
		DelegatedAddress string  `json:"delegatedAddress"`
		OperatorAddress  string  `json:"operatorAddress"`
		TotalStaked      float64 `json:"totalStaked"`
		StakerCount      int     `json:"stakerCount"`
		IsOperational    bool    `json:"isOperational"`
	}
	type VALSResponse struct {
		TotalStaked float64         `json:"totalStaked"`
		Validators  []ValidatorInfo `json:"validators"`
	}

	totalStaked := account.GetStakedInAllDelegatedAccounts()

	validators := []ValidatorInfo{}
	account.StakingRWMutex.RLock()
	for i := 1; i < 256; i++ {
		stakers := account.StakingAccounts[i].AllStakingAccounts
		if len(stakers) == 0 {
			continue
		}
		sum := int64(0)
		activeStakers := 0
		var operatorAddr [common.AddressLength]byte
		hasOperator := false
		for _, sa := range stakers {
			if sa.StakedBalance > 0 {
				sum += sa.StakedBalance
				activeStakers++
			}
			if sa.OperationalAccount && sa.StakedBalance > 0 {
				if !hasOperator || sa.StakedBalance > 0 {
					copy(operatorAddr[:], sa.Address[:])
					hasOperator = true
				}
			}
		}
		if sum == 0 {
			continue
		}
		da := common.GetDelegatedAccountAddress(int16(i))
		validators = append(validators, ValidatorInfo{
			ID:               i,
			DelegatedAddress: da.GetHex(),
			OperatorAddress:  hex.EncodeToString(operatorAddr[:]),
			TotalStaked:      account.Int64toFloat64(sum),
			StakerCount:      activeStakers,
			IsOperational:    hasOperator,
		})
	}
	account.StakingRWMutex.RUnlock()
	// Marshal outside the lock — JSON encoding can be slow for large data sets.

	resp := VALSResponse{
		TotalStaked: account.Int64toFloat64(totalStaked),
		Validators:  validators,
	}

	result, err := json.Marshal(resp)
	if err != nil {
		*reply = []byte("{\"error\":\"failed to marshal validators\"}")
		return
	}
	*reply = result
}
