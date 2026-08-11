package serverrpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/core/stateDB"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/message"
	"github.com/qwid-org/qwid-node/pubkeys"
	nonceServices "github.com/qwid-org/qwid-node/services/nonceService"
	"github.com/qwid-org/qwid-node/services/transactionServices"
	"github.com/qwid-org/qwid-node/statistics"
	"github.com/qwid-org/qwid-node/tcpip"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
	"github.com/qwid-org/qwid-node/wallet"
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

// lookupRegisteredPubKey resolves an account's on-chain registered key.
// Indirected so tests do not need a populated key trie.
var lookupRegisteredPubKey = pubkeys.LoadPubKeyWithPrimary

// requestAccountAddress returns the account a request is about, taken from the
// first AddressLength bytes of its payload, when the operation carries one.
//
// The lengths are checked per operation rather than "at least an address":
// CNCL's older form is a bare 32-byte hash, and reading its leading bytes as an
// address would authenticate the request against whatever account they happen
// to spell. A payload that does not match is treated as carrying no account,
// which is what keeps wallets built before this change working.
//
// GTBL carries a CONTRACT address, which is not the caller's identity and must
// never be used to authenticate them.
func requestAccountAddress(operation string, payload []byte) (common.Address, bool) {
	carries := false
	switch operation {
	case "ACCT":
		// The payload is the address being queried.
		carries = len(payload) >= common.AddressLength
	case "CNCL":
		// The caller's address followed by the hash to cancel.
		carries = len(payload) == common.AddressLength+common.HashLength
	case "PEND":
		// Optional: an address narrows the pools to that account's traffic.
		carries = len(payload) == common.AddressLength
	case "CHCK":
		// The wallet's two account addresses, primary first. The first is the
		// main address, which is the identity to authenticate against.
		carries = len(payload) == 2*common.AddressLength
	case "VOTE":
		// The voter, followed by the two encryption blobs. Unlike the others
		// this is not optional — see handleVOTE.
		carries = len(payload) > common.AddressLength
	}
	if !carries {
		return common.Address{}, false
	}
	addr := common.Address{}
	if err := addr.Init(payload[:common.AddressLength]); err != nil {
		return common.Address{}, false
	}
	return addr, true
}

// loadLocalWalletKeys reads the public keys of every wallet generated on this
// machine. Indirected for tests.
var loadLocalWalletKeys = wallet.LocalWalletPublicKeys

var (
	localWalletKeyMutex  sync.Mutex
	localWalletKeyCache  []wallet.WalletPublicKeys
	localWalletKeyLoaded bool
)

func invalidateLocalWalletKeyCache() {
	localWalletKeyMutex.Lock()
	defer localWalletKeyMutex.Unlock()
	localWalletKeyCache, localWalletKeyLoaded = nil, false
}

// localWalletKeys returns the cached local wallet keys, scanning the wallet
// directory on first use. Cached because the scan touches the filesystem and
// runs on the RPC path; a wallet generated while the node is up is picked up
// after a restart, which is when it becomes usable anyway.
func localWalletKeys() []wallet.WalletPublicKeys {
	localWalletKeyMutex.Lock()
	defer localWalletKeyMutex.Unlock()
	if localWalletKeyLoaded {
		return localWalletKeyCache
	}
	keys, err := loadLocalWalletKeys()
	if err != nil {
		logger.GetLogger().Println("cannot read local wallet public keys:", err)
	}
	localWalletKeyCache, localWalletKeyLoaded = keys, true
	return localWalletKeyCache
}

// schemeHalf picks the half of a key pair matching the scheme the signature
// selected. Verifying a secondary signature against a primary key can only ever
// fail, so getting this wrong locks out every wallet on the second scheme.
func schemeHalf(w wallet.WalletPublicKeys, primary bool) []byte {
	if primary {
		return w.Primary
	}
	return w.Secondary
}

// activeWalletKeys returns the node's own wallet as one entry, or nothing when
// no wallet has been loaded yet. GetActiveWallet returns nil until then, and
// dereferencing it inside an RPC handler would answer an unauthenticated
// request with a panic; an empty result fails cleanly as "Invalid signature".
func activeWalletKeys() []wallet.WalletPublicKeys {
	aw := wallet.GetActiveWallet()
	if aw == nil {
		return nil
	}
	return []wallet.WalletPublicKeys{{
		Number:      aw.WalletNumber,
		MainAddress: aw.MainAddress,
		Primary:     aw.Account1.PublicKey.GetBytes(),
		Secondary:   aw.Account2.PublicKey.GetBytes(),
	}}
}

// candidateVerificationKeys returns every public key a signed request may
// legitimately be signed with.
//
// A request that NAMES an account is authenticated by that account alone: its
// key as registered on-chain. Accepting anything else would let anyone holding
// a local wallet sign requests about other people's accounts.
//
// An account with no on-chain key has never had a transaction processed, so
// there is nothing to check it against. Rather than lock it out — a wallet's
// very first request would otherwise be refused — the node accepts the wallet
// on this machine that HOLDS that address, and only that one. This is what
// makes it safe for a privileged operation such as cancelling to name an
// address instead of implicitly meaning the mining wallet.
//
// A request that names no account (WALL, MINE, VOTE, PEER, ...) carries no
// identity to check, so any wallet the operator generated on this machine is
// accepted — not just the mining one. Their public halves are stored
// unencrypted in the wallet files, so the node needs no password to know them.
func candidateVerificationKeys(operation string, payload []byte, primary bool) [][]byte {
	if addr, named := requestAccountAddress(operation, payload); named {
		if pk, err := lookupRegisteredPubKey(addr, primary); err == nil {
			if b := pk.GetBytes(); len(b) > 0 {
				return [][]byte{b}
			}
		}
		return walletKeysHoldingAddress(addr, primary)
	}
	if nodeLevelOperations[operation] {
		return schemeHalves(activeWalletKeys(), primary)
	}
	return everyLocalWalletKey(primary)
}

// nodeLevelOperations change how the NODE behaves rather than reporting on an
// account, so only the wallet the node runs as may ask for them. They name no
// account, and without this they would fall through to "any wallet on this
// machine" — which would let a second wallet start the node's mining services.
//
// VOTE belongs to the same class but is not listed here: it carries the voter's
// address, so it takes the stricter account path above and is checked against
// that account's registered key.
var nodeLevelOperations = map[string]bool{"MINE": true}

// walletKeysHoldingAddress returns the keys of the local wallets whose own main
// address is addr — normally exactly one, and none when the address belongs to
// somebody else. An empty result means the request cannot be authenticated and
// is refused, which is the intended answer for a stranger's account.
func walletKeysHoldingAddress(addr common.Address, primary bool) [][]byte {
	want := addr.GetBytes()
	keys := [][]byte{}
	for _, w := range append(activeWalletKeys(), localWalletKeys()...) {
		owner := w.MainAddress
		if !bytes.Equal(owner.GetBytes(), want) {
			continue
		}
		if k := schemeHalf(w, primary); len(k) > 0 {
			keys = append(keys, k)
		}
	}
	return keys
}

// schemeHalves collects the matching half of each wallet's key pair, dropping
// wallets that have none.
func schemeHalves(wallets []wallet.WalletPublicKeys, primary bool) [][]byte {
	keys := [][]byte{}
	for _, w := range wallets {
		if k := schemeHalf(w, primary); len(k) > 0 {
			keys = append(keys, k)
		}
	}
	return keys
}

// everyLocalWalletKey returns the key of every wallet on this machine, the
// active one first: it is the common case, so a valid request usually verifies
// on the first attempt instead of after a walk through the others.
func everyLocalWalletKey(primary bool) [][]byte {
	return schemeHalves(append(activeWalletKeys(), localWalletKeys()...), primary)
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
		primary := signatureBytes[0] == 0
		signed := false
		for _, pubKey := range candidateVerificationKeys(operation, byt, primary) {
			if len(pubKey) == 0 {
				continue
			}
			if wallet.Verify(common.BytesToLenAndBytes(line), signatureBytes, pubKey, common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2()) {
				signed = true
				break
			}
		}
		if !signed {
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

// handleCHECK reports whether an account's two scheme keys are registered
// on-chain. The addresses come from the request — primary first, then secondary
// — so a wallet other than the mining one learns about ITS OWN registration
// rather than the node's. An empty payload still means the node's own wallet.
func handleCHECK(line []byte, reply *[]byte) {
	logger.GetLogger().Println(string(line))
	*reply = nil

	var primaryAddr, secondaryAddr []byte
	if len(line) == 2*common.AddressLength {
		primaryAddr = line[:common.AddressLength]
		secondaryAddr = line[common.AddressLength:]
	} else {
		w := wallet.GetActiveWallet()
		if w == nil {
			*reply = []byte("no wallet loaded on this node; send the addresses to check")
			return
		}
		primaryAddr = w.Account1.Address.GetBytes()
		secondaryAddr = w.Account2.Address.GetBytes()
	}

	if _, err := pubkeys.LoadPubKey(primaryAddr); err != nil {
		*reply = []byte("Primary pubkey is not registered in blockchain. Please send transaction including primary PubKey to blockchain")
	}
	if _, err := pubkeys.LoadPubKey(secondaryAddr); err != nil {
		*reply = []byte("Secondary pubkey is not registered in blockchain. Please send transaction including secondary PubKey to blockchain")
	}
}

// ESCR and MULT used to sit here. Both only logged their payload and returned
// nothing — handleESCR's intended body was commented out — and nothing in the
// tree ever called either of them.
//
// Escrow and multi-signature are configured by TRANSACTION, not by RPC: the
// wallet builds a TxData carrying EscrowTransactionsDelay, MultiSignNumber and
// MultiSignAddresses, signs it with its own key and submits it through TRAN
// (cmd/webui ModifyEscrow, cmd/gui escrow). Consensus then applies it to the
// sender's account. That path is already bound to the caller's account, so
// there was nothing for these two to answer for and nothing to make them carry
// an address for — only an authenticated RPC operation that did nothing.

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

// handleVOTE records the node's vote on a signature-scheme change.
//
// The node has exactly ONE vote: it is cast by its delegated account, weighted
// by that account's stake (voting.SaveVotesEncryption1), and it travels inside
// the nonce transaction the mining wallet signs. There is no per-account vote
// to keep, so unlike CNCL, PEND and CHCK the address in the request is not a
// question to answer — it is the claim of who is voting, and the node casts the
// vote only for the wallet it actually mines with.
//
// This is deliberately fail-closed: a payload naming nobody is refused rather
// than treated as the node's own. Falling back would leave the vote castable by
// any wallet that can reach the RPC socket, which is exactly what accepting a
// signature from every locally-generated wallet made possible.
func handleVOTE(line []byte, reply *[]byte) {
	voter, named := requestAccountAddress("VOTE", line)
	if !named {
		*reply = []byte("vote must name the voting account")
		return
	}
	line = line[common.AddressLength:]

	miner := wallet.GetActiveWallet()
	if miner == nil {
		*reply = []byte("this node has no wallet loaded and cannot vote")
		return
	}
	if !bytes.Equal(voter.GetBytes(), miner.MainAddress.GetBytes()) {
		// The vote belongs to the account the node stakes with. Another wallet
		// on the same machine is a different owner, not a co-owner.
		*reply = []byte("only the wallet this node mines with can cast its vote")
		return
	}

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

// txLocation describes where a transaction currently is.
//
// Being on the chain and being outstanding are independent facts: an escrow
// transfer is written to the confirmed DB by the block that carries it and
// only then enters the escrow pool, where it waits until its settlement
// height. The same holds for a transfer awaiting co-signatures. Reporting a
// single first-match location put every such transaction under plain
// "confirmed_db" and made the wallet show unsettled transfers as done.
//
// "confirmed_db" therefore still wins as the primary state — that is what most
// callers ask about — and the outstanding state is appended as a qualifier:
//
//	confirmed_db            on chain, nothing outstanding
//	confirmed_db+escrow     on chain, value not moved yet
//	confirmed_db+multisig   on chain, awaiting signatures
//
// Transactions that never reached a block keep their previous single values.
func txLocation(inConfirmed, inPoolDB, inMain, inEscrow, inMultisig bool) string {
	if inConfirmed {
		switch {
		case inEscrow:
			return "confirmed_db+escrow"
		case inMultisig:
			return "confirmed_db+multisig"
		}
		return "confirmed_db"
	}
	switch {
	case inPoolDB:
		return "pool_db"
	case inMain:
		return "memory_main"
	case inEscrow:
		return "memory_escrow"
	case inMultisig:
		return "memory_multisign"
	}
	return ""
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
		var tx transactionsDefinition.Transaction
		var err error

		// Check confirmed DB (TT)
		tx, err = transactionsDefinition.LoadFromDBPoolTx(common.TransactionDBPrefix[:], line)
		inConfirmed := err == nil

		// Check pool DB (D0). Only needed for the transaction bytes when the
		// confirmed DB did not have them.
		inPoolDB := false
		if !inConfirmed {
			tx, err = transactionsDefinition.LoadFromDBPoolTx(common.TransactionPoolHashesDBPrefix[:], line)
			inPoolDB = err == nil
		}

		// Pool membership is checked unconditionally: a confirmed transaction
		// can still be waiting in the escrow or multisig pool, and that is
		// exactly the state the old first-match resolution hid.
		location := txLocation(
			inConfirmed,
			inPoolDB,
			transactionsPool.PoolsTx.HasTransaction(line),
			transactionsPool.PoolTxEscrow.HasTransaction(line),
			transactionsPool.PoolTxMultiSign.HasTransaction(line),
		)

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
	acc = account.WithTxHistory(acc, byt, 50)
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

// rejectUnacceptableTransactions returns the first reason a submitted batch
// must not be broadcast. It covers the cases the chain will refuse outright, so
// the wallet learns why instead of watching a transaction never confirm.
//
// The whole payload is broadcast or not, so one bad transaction refuses the
// batch — accepting part of it is not something the caller can act on.
func rejectUnacceptableTransactions(txs []transactionsDefinition.Transaction) error {
	for _, tx := range txs {
		if err := blocks.ValidateContractDeployment(tx); err != nil {
			return err
		}
	}
	return nil
}

// handleTRAN accepts a transaction batch from the local wallet.
//
// It used to answer "transaction sent" before looking at the payload and then
// hand it to the network unconditionally. A submission the chain refuses — a
// contract deployment from an escrow or multi-signature account, which cannot
// execute — was therefore reported as accepted, and the only evidence of
// failure was that it never confirmed. Decoding and checking first costs one
// parse and turns that silence into a message.
//
// Only locally-submitted transactions take this path; peer traffic still goes
// straight to transactionServices.OnMessage, which is deliberately untouched.
func handleTRAN(byt []byte, reply *[]byte) {

	isValid, amsg := message.CheckValidMessage(byt)
	if !isValid {
		*reply = []byte("transaction rejected: malformed message")
		return
	}
	txMsg, ok := amsg.(message.TransactionsMessage)
	if !ok {
		*reply = []byte("transaction rejected: not a transaction message")
		return
	}
	// Transactions arrive grouped by topic; the check applies to all of them.
	byTopic, err := txMsg.GetTransactionsFromBytes(common.SigName(), common.SigName2(),
		common.IsPaused(), common.IsPaused2())
	if err != nil {
		*reply = []byte("transaction rejected: " + err.Error())
		return
	}
	txs := make([]transactionsDefinition.Transaction, 0, len(byTopic))
	for _, group := range byTopic {
		txs = append(txs, group...)
	}
	if err := rejectUnacceptableTransactions(txs); err != nil {
		logger.GetLogger().Println("refusing local submission:", err)
		*reply = []byte("transaction rejected: " + err.Error())
		return
	}

	*reply = []byte("transaction sent")
	transactionServices.OnMessage([4]byte{0, 0, 0, 0}, byt)

}

// callerAddress resolves the account a request acts for: the one it names, or
// the node's own wallet when it names none. The second result is false when
// neither is available — no address in the payload and no wallet loaded — which
// the caller must treat as "cannot act", not as "the empty account".
//
// The old handlers read wallet.GetActiveWallet().MainAddress directly. That is
// nil until a wallet is loaded, so a request arriving first panicked inside the
// RPC server instead of answering.
func callerAddress(operation string, payload []byte) (common.Address, bool) {
	if addr, named := requestAccountAddress(operation, payload); named {
		return addr, true
	}
	if aw := wallet.GetActiveWallet(); aw != nil {
		return aw.MainAddress, true
	}
	return common.Address{}, false
}

// handleCNCL cancels a pooled transaction on behalf of the account named in the
// request — the address, then the 32-byte hash. Ownership is still checked
// against the pooled sender, so naming an address is not a way to cancel
// somebody else's transaction; the signature check has already established that
// the caller controls the address it named.
//
// The older payload is the bare hash and still means the node's own wallet.
func handleCNCL(byt []byte, reply *[]byte) {

	*reply = []byte("hash is not 32 bytes")

	hash := byt
	if len(byt) == common.AddressLength+common.HashLength {
		hash = byt[common.AddressLength:]
	}
	if len(hash) != common.HashLength {
		return
	}

	owner, ok := callerAddress("CNCL", byt)
	if !ok {
		*reply = []byte("no wallet to cancel on behalf of")
		return
	}
	ownerBytes := owner.GetBytes()

	if transactionsPool.PoolsTx.TransactionExists(hash) {
		tx := transactionsPool.PoolsTx.PopTransactionByHash(hash)
		if bytes.Equal(tx.TxParam.Sender.GetBytes(), ownerBytes) == false {
			transactionsPool.PoolsTx.AddTransaction(tx, tx.Hash)
			*reply = []byte("you are not the owner of transaction")
			return
		}
		transactionsPool.PoolsTx.BanTransactionByHash(hash)
		*reply = []byte("transaction cancelled locally")
		return
	}
	if transactionsPool.PoolTxEscrow.TransactionExists(hash) {
		tx, _ := transactionsPool.PoolTxEscrow.GetTransactionByHash(hash)
		if bytes.Equal(tx.TxParam.Sender.GetBytes(), ownerBytes) == false {
			*reply = []byte("you are not the owner of transaction")
			return
		}
		// Escrow has already been accepted by consensus. Do not remove only
		// this node's copy; the WebUI must submit a signed cancellation tx.
		*reply = []byte("escrow cancellation transaction required")
		return
	}
	if transactionsPool.PoolTxMultiSign.TransactionExists(hash) {
		tx := transactionsPool.PoolTxMultiSign.PopTransactionByHash(hash)
		if bytes.Equal(tx.TxParam.Sender.GetBytes(), ownerBytes) == false {
			transactionsPool.AddMultiSignTransaction(tx)
			*reply = []byte("you are not the owner of transaction")
			return
		}
		// Drop the persisted copy too, or the restart would resurrect the
		// cancelled transaction into the pool.
		transactionsPool.RemoveMultiSignTransaction(hash)
		transactionsPool.PoolTxMultiSign.BanTransactionByHash(hash)
		*reply = []byte("transaction cancelled locally")
		return
	}
	*reply = []byte("transaction not found in a cancellable pool")
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
	// Get pending transactions from all pools.
	//
	// MaturesAt is set for escrow only, where it is the height the transfer
	// settles at. An escrow transaction is confirmed on-chain the moment its
	// block is processed and only then enters the escrow pool
	// (blocks/processTransaction.go), so it is legitimately both "in
	// confirmed_db" and "waiting" until it matures. Reporting it as bare
	// "pending", like a transaction still waiting to reach a block, reads as
	// though it might never land.
	type PendingTx struct {
		Hash      string  `json:"hash"`
		Sender    string  `json:"sender"`
		Recipient string  `json:"recipient"`
		Amount    float64 `json:"amount"`
		Height    int64   `json:"height"`
		Pool      string  `json:"pool"`
		MaturesAt int64   `json:"maturesAt,omitempty"`
		// Multisig only. Approves is the hash of the transaction a
		// co-signature is aimed at — without it an owner with several pending
		// transfers cannot tell which one a signature belongs to. Approvals /
		// Required are the progress on a main transaction.
		Approves  string `json:"approves,omitempty"`
		Approvals int    `json:"approvals,omitempty"`
		Required  int    `json:"required,omitempty"`
	}

	// A request naming an account gets that account's traffic — what it sent and
	// what is coming to it — instead of the whole pool. The pools hold every
	// node's transactions, so an unfiltered answer showed a wallet a list it
	// could not attribute. A bare PEND still returns everything: wallets built
	// before this change send one, and an empty list would read as "nothing
	// pending".
	concerns := func(transactionsDefinition.Transaction) bool { return true }
	if addr, named := requestAccountAddress("PEND", byt); named {
		want := addr.GetBytes()
		concerns = func(tx transactionsDefinition.Transaction) bool {
			return bytes.Equal(tx.TxParam.Sender.GetBytes(), want) ||
				bytes.Equal(tx.TxData.Recipient.GetBytes(), want)
		}
	}

	pendingTxs := []PendingTx{}

	// Get from main pool
	txs := transactionsPool.PoolsTx.PeekTransactions(50, 0)
	for _, tx := range txs {
		if !concerns(tx) {
			continue
		}
		pendingTxs = append(pendingTxs, PendingTx{
			Hash:      tx.Hash.GetHex(),
			Sender:    tx.TxParam.Sender.GetHex(),
			Recipient: tx.TxData.Recipient.GetHex(),
			Amount:    float64(tx.TxData.Amount) / 1e8,
			Height:    tx.Height,
			Pool:      "main",
		})
	}

	// Escrow. MaturesAt comes from blocks.EscrowMaturityHeight, which reads the
	// sender account's delay — the value settlement actually gates on. The
	// escrow pool's own ordering key must NOT be used here: it is
	// tx.Height + tx.TxData.EscrowTransactionsDelay, and that field is set only
	// on a ModifyEscrow configuration transaction, so for an ordinary transfer
	// it is zero and the key equals the transaction's own height.
	for _, e := range transactionsPool.PoolTxEscrow.PeekEntries(50) {
		tx := e.Transaction
		if !concerns(tx) {
			continue
		}
		pendingTxs = append(pendingTxs, PendingTx{
			Hash:      tx.Hash.GetHex(),
			Sender:    tx.TxParam.Sender.GetHex(),
			Recipient: tx.TxData.Recipient.GetHex(),
			Amount:    float64(tx.TxData.Amount) / 1e8,
			Height:    tx.Height,
			Pool:      "escrow",
			MaturesAt: blocks.EscrowMaturityHeight(tx),
		})
	}

	// Multisig: this used to call PeekTransactions(50, math.MaxInt64), but the
	// multisig pool matches priority by equality against a key derived from
	// the multi-signature hash, so that query could never match and the wallet
	// showed no pending multi-signature transactions at all. No MaturesAt
	// here: a multisig transaction waits for co-signers, not for a height.
	for _, e := range transactionsPool.PoolTxMultiSign.PeekEntries(50) {
		tx := e.Transaction
		if !concerns(tx) {
			continue
		}
		entry := PendingTx{
			Hash:      tx.Hash.GetHex(),
			Sender:    tx.TxParam.Sender.GetHex(),
			Recipient: tx.TxData.Recipient.GetHex(),
			Amount:    float64(tx.TxData.Amount) / 1e8,
			Height:    tx.Height,
			Pool:      "multisig",
		}
		if bytes.Equal(tx.TxParam.MultiSignTx.GetBytes(), blocks.ZerosHash) {
			// A main transaction: report how far its approvals have got. The
			// group is keyed by this transaction's own hash, which is also the
			// key its co-signatures were pooled under.
			group := transactionsPool.PoolTxMultiSign.PeekTransactions(
				common.MaxTransactionInPool, common.GetInt64FromByte(tx.Hash.GetBytes()))
			entry.Approvals, entry.Required = blocks.CountMultiSignApprovals(tx, group)
		} else {
			entry.Approves = tx.TxParam.MultiSignTx.GetHex()
		}
		pendingTxs = append(pendingTxs, entry)
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
