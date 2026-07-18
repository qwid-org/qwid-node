package nonceServices

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"sync"
	"time"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/blocks"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"
	"github.com/wonabru/qwid-node/message"
	"github.com/wonabru/qwid-node/pubkeys"
	"github.com/wonabru/qwid-node/services"
	"github.com/wonabru/qwid-node/tcpip"
	"github.com/wonabru/qwid-node/transactionsDefinition"
	"github.com/wonabru/qwid-node/voting"
	"github.com/wonabru/qwid-node/wallet"
)

// NP-H11: oracle values influence consensus, so they must come from a
// cryptographically secure RNG, not the predictable x/exp/rand.
func cryptoRandInt63() int64 {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		logger.GetLogger().Println("crypto/rand failed:", err)
		return 0
	}
	return int64(binary.BigEndian.Uint64(b[:]) >> 1)
}

func cryptoRandIntn(n int64) int64 {
	if n <= 0 {
		return 0
	}
	return cryptoRandInt63() % n
}

var lastReplyPerPeer = make(map[[4]byte]time.Time)
var lastReplyMutex sync.Mutex
var EncryptionOptData []byte
var encryptionMutex sync.Mutex

func init() {
	ResetToDefaultEncryptionOptData()
}

func ResetToDefaultEncryptionOptData() {
	encryptionMutex.Lock()
	defer encryptionMutex.Unlock()
	// Encryption1 and Encryption2 when changed than needs to add bytes
	encryption1 := common.BytesToLenAndBytes([]byte{})
	encryption2 := common.BytesToLenAndBytes([]byte{})
	EncryptionOptData = append(encryption1, encryption2...)
}

func SetEncryptionData(ne1 []byte, ne2 []byte) {
	encryptionMutex.Lock()
	defer encryptionMutex.Unlock()
	// Encryption1 and Encryption2 when changed than needs to add bytes
	encryption1 := common.BytesToLenAndBytes(ne1)
	encryption2 := common.BytesToLenAndBytes(ne2)
	EncryptionOptData = append(encryption1, encryption2...)
}

func InitChannelVoting(voteChan chan []byte) {
	quit := false
	for !quit {
		select {
		case s := <-voteChan:
			primary := true
			if s[0] != 0 {
				primary = false
			}
			err := blocks.SetEncryptionFromBytes(s[1:], primary)
			if err != nil {
				logger.GetLogger().Println(err)
				voteChan <- []byte(err.Error())
			} else {

				if err != nil {
					voteChan <- []byte(err.Error())
				} else {
					voteChan <- []byte("Set new encryption was successful")
				}
			}

		case <-tcpip.Quit:
			quit = true
		default:
			// Optional: Add a small sleep to prevent busy-waiting
			time.Sleep(time.Millisecond)
		}
	}
}

func InitNonceService() {
	services.SendMutexNonce.Lock()
	services.SendChanNonce = make(chan []byte, 100)

	services.SendChanSelfNonce = make(chan []byte, 100)
	services.SendMutexNonce.Unlock()
	startPublishingNonceMsg()
	time.Sleep(time.Second)
	go sendNonceMsgInLoop()
	go InitChannelVoting(blocks.VoteChannel)
	go sendNonceMsgInLoopSelf()
}

func generateNonceMsg(topic [2]byte) (message.TransactionsMessage, error) {
	h := common.GetHeight()
	w := wallet.GetActiveWallet()
	primary := common.GetNodeSignPrimary(h)
	sender := wallet.GetActiveWallet().MainAddress

	var nonceTransaction transactionsDefinition.Transaction
	tp := transactionsDefinition.TxParam{
		ChainID:     common.GetChainID(),
		Sender:      sender,
		SendingTime: common.GetCurrentTimeStampInSecond(),
		Nonce:       0,
	}
	lastBlockHash, err := blocks.LoadHashOfBlock(h)
	if err != nil {
		lastBlockHash = common.EmptyHash().GetBytes()
	}
	optData := common.GetByteInt64(h)
	optData = append(optData, lastBlockHash...)

	//TODO Price oracle currently is random: 0.9 - 1.1 KURA/USD
	priceOracle := cryptoRandIntn(10000000) - 5000000 + 100000000
	randOracle := cryptoRandInt63()
	optData = append(optData, common.GetByteInt64(priceOracle)...)
	optData = append(optData, common.GetByteInt64(randOracle)...)

	voting.VotesEncryptionMutex.Lock()
	if voting.AfterReset {
		ResetToDefaultEncryptionOptData()
		voting.AfterReset = false
	}
	voting.VotesEncryptionMutex.Unlock()

	// NP-M12: read EncryptionOptData under encryptionMutex — the lock the writers
	// (SetEncryptionData/ResetToDefaultEncryptionOptData) hold — not VotesEncryptionMutex.
	encryptionMutex.Lock()
	optData = append(optData, EncryptionOptData...)
	encryptionMutex.Unlock()

	pubkey := common.PubKey{}
	if primary == false {
		pktrie, err := pubkeys.LoadTreeWithoutAddresses(sender)
		if err != nil {
			return message.TransactionsMessage{}, err
		}
		isAddr := pktrie.IsAddressInTree(w.Account2.Address)
		if !isAddr {
			logger.GetLogger().Println("no address2 in blockchain")
			pubkey = w.Account2.PublicKey
		}
	}

	dataTx := transactionsDefinition.TxData{
		Recipient: common.GetDelegatedAccount(), // will be delegated account temporary
		Amount:    0,
		OptData:   optData[:],
		Pubkey:    pubkey,
	}
	nonceTransaction = transactionsDefinition.Transaction{
		TxData:    dataTx,
		TxParam:   tp,
		Hash:      common.Hash{},
		Signature: common.Signature{},
		Height:    h + 1,
		GasPrice:  0,
		GasUsage:  0,
	}

	err = (&nonceTransaction).CalcHashAndSet()
	if err != nil {
		return message.TransactionsMessage{}, err
	}

	err = (&nonceTransaction).Sign(w, primary)
	if err != nil {
		return message.TransactionsMessage{}, err
	}

	bm := message.BaseMessage{
		Head:    []byte("nn"),
		ChainID: common.GetChainID(),
	}
	bb := nonceTransaction.GetBytes()
	n := message.TransactionsMessage{
		BaseMessage:       bm,
		TransactionsBytes: map[[2]byte][][]byte{topic: {bb}},
	}

	return n, nil
}

func sendNonceMsgInLoopSelf() {
	var topic = [2]byte{'S', 'S'}
	// Q:
	for {
		ret := sendNonceMsgSelf(tcpip.MyIPSelfNonce, topic)

		if !ret {
			time.Sleep(3 * time.Second)
		}

		// select {
		// case s := <-chanRecv:
		// 	if len(s) == 4 && bytes.Equal(s, []byte("EXIT")) {
		// 		break Q
		// 	}
		// default:

		// }
		time.Sleep(time.Second)
	}
}

// canProduce reports whether this node is currently an eligible block producer:
// its operator pubkey is registered on-chain (so peers can verify the blocks it
// signs) and it is a staked top-128 validator. A node that is not (yet) a
// registered, staked validator must not emit nonces — peers cannot verify them
// and would otherwise reject/ban us.
// isEligibleProducer is the testable core of canProduce: given the operator
// address, its delegated-account id, and whether its pubkey is registered
// on-chain, report whether it may produce blocks.
func isEligibleProducer(operator common.Address, delID int, pubkeyRegistered bool) bool {
	if !pubkeyRegistered {
		return false
	}
	return account.IsTop128StakingNode(delID, operator)
}

func canProduce() bool {
	w := wallet.GetActiveWallet()
	if w == nil {
		return false
	}
	operator := w.MainAddress
	_, pkErr := pubkeys.LoadPubKeyWithPrimary(operator, true)
	delID, err := account.IntDelegatedAccountFromAddress(common.GetDelegatedAccount())
	if err != nil {
		return false
	}
	return isEligibleProducer(operator, delID, pkErr == nil)
}

func sendNonceMsg(ip [4]byte, topic [2]byte) bool {
	h := common.GetHeight()
	if h < common.CurrentHeightOfNetwork {
		return false
	}
	isync := common.IsSyncing.Load()
	if isync == true {
		return false
	}
	if !canProduce() {
		return false
	}
	n, err := generateNonceMsg(topic)
	if err != nil {
		logger.GetLogger().Println(err)
		return false
	}
	if !Send(ip, n.GetBytes()) {
		logger.GetLogger().Println("could not send nonce message")
		return false
	}
	return true
}

func sendNonceMsgSelf(ip [4]byte, topic [2]byte) bool {
	h := common.GetHeight()
	if h < common.CurrentHeightOfNetwork {
		return false
	}
	if !canProduce() {
		return false
	}
	n, err := generateNonceMsg(topic)
	if err != nil {
		logger.GetLogger().Println(err)
		return false
	}
	if !SendSelf(ip, n.GetBytes()) {
		logger.GetLogger().Println("could not send self nonce message")
		return false
	}
	return true
}

func Send(addr [4]byte, nb []byte) bool {
	nb = append(addr[:], nb...)
	if services.SendMutexNonce.TryLock() {
		defer services.SendMutexNonce.Unlock()
		select {
		case services.SendChanNonce <- nb:
			return true
		default:
			return false
		}
	}
	return false
}

func SendSelf(addr [4]byte, nb []byte) bool {
	nb = append(addr[:], nb...)
	if services.SendMutexSelfNonce.TryLock() {
		defer services.SendMutexSelfNonce.Unlock()
		select {
		case services.SendChanSelfNonce <- nb:
			return true
		default:
			return false
		}
	}
	return false
}

func sendNonceMsgInLoop() {
	for {
		if len(tcpip.GetPeersConnected(tcpip.NonceTopic)) == 0 {
			time.Sleep(3 * time.Second)
			continue
		}
		var topic = [2]byte{'N', 'N'}
		ret := sendNonceMsg([4]byte{0, 0, 0, 0}, topic)
		if !ret {
			time.Sleep(3 * time.Second)
		}
		time.Sleep(10 * time.Second)
	}
}

func startPublishingNonceMsg() {
	go tcpip.StartNewListener(tcpip.NonceTopic)
	go tcpip.LoopSend(services.SendChanNonce, tcpip.NonceTopic)
	go tcpip.StartNewListener(tcpip.SelfNonceTopic)
	go tcpip.LoopSend(services.SendChanSelfNonce, tcpip.SelfNonceTopic)
}

func StartSubscribingNonceMsg(ip [4]byte) {
	recvChan := make(chan []byte, 100) // Use a buffered channel
	quit := false
	var ipr [4]byte
	go tcpip.StartNewConnection(ip, recvChan, tcpip.NonceTopic)
	for !services.QUIT.Load() && !quit {
		select {
		case s := <-recvChan:
			if len(s) == 4 && bytes.Equal(s, []byte("EXIT")) {
				quit = true
				break
			}
			if len(s) > 4 {
				copy(ipr[:], s[:4])
				OnMessage(ipr, s[4:])
				//send reply to valid nonce message from other nodes
				if !bytes.Equal(ipr[:], tcpip.MyIP[:]) && !bytes.Equal(ipr[:], []byte{0, 0, 0, 0}) {
					lastReplyMutex.Lock()
					lastTime := lastReplyPerPeer[ipr]
					if time.Since(lastTime) >= 5*time.Second {
						lastReplyPerPeer[ipr] = time.Now()
						lastReplyMutex.Unlock()
						sendReply(ipr)
					} else {
						lastReplyMutex.Unlock()
					}
				}
			}
		case <-tcpip.Quit:
			services.QUIT.Store(true)
		}
	}
}

func sendReply(addr [4]byte) {
	logger.GetLogger().Println("send reply to ", addr)
	var topic = [2]byte{'N', 'N'}
	n, err := generateNonceMsg(topic)
	if err != nil {
		logger.GetLogger().Println(err)
		return
	}
	if Send(addr, n.GetBytes()) {
		logger.GetLogger().Println("send reply to node ", addr, " my ip ", tcpip.MyIP)
	}
}

func StartSubscribingNonceMsgSelf() {
	recvChanSelf := make(chan []byte, 100) // Use a buffered channel
	recvChanExit := make(chan []byte, 100) // Use a buffered channel
	quit := false
	var ip [4]byte
	go tcpip.StartNewConnection(tcpip.MyIPSelfNonce, recvChanSelf, tcpip.SelfNonceTopic)

	for !services.QUIT.Load() && !quit {
		select {
		case s := <-recvChanSelf:
			if len(s) == 4 && bytes.Equal(s, []byte("EXIT")) {
				recvChanExit <- s
				quit = true
				break
			}
			if len(s) > 4 {
				copy(ip[:], s[:4])
				OnMessage(ip, s[4:])
			}
		case <-tcpip.Quit:
			services.QUIT.Store(true)
		default:

			// Optional: Add a small sleep to prevent busy-waiting
			time.Sleep(time.Millisecond)
		}
	}
}
