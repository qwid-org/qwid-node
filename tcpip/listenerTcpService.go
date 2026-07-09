package tcpip

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"
)

var ChanPeer = make(chan []byte, 50)

func StartNewListener(topic [2]byte) {

	conn, err := Listen([4]byte{0, 0, 0, 0}, Ports[topic])
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	defer func() {
		PeersMutex.Lock()
		defer PeersMutex.Unlock()
		for _, tcpConn := range tcpConnections[topic] {
			tcpConn.Close()
		}
	}()
	for {
		select {
		case <-Quit:
			logger.GetLogger().Println("Should exit StartNewListener")
			return
		default:
			conn.SetDeadline(time.Now().Add(time.Second))
			_, err := Accept(topic, conn)
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					continue
				}
				logger.GetLogger().Println(err)
				continue
			}
		}
	}
}

type connEntry struct {
	ip   [4]byte
	conn *net.TCPConn
}

func LoopSend(sendChan <-chan []byte, topic [2]byte) {
	var ipr [4]byte
	for {
		select {
		case s := <-sendChan:
			if len(s) > 4 {
				copy(ipr[:], s[:4])
			} else {
				logger.GetLogger().Println("wrong message", topic)
				continue
			}

			// Snapshot connections under RLock — do NOT hold the lock during I/O.
			var targets []connEntry
			PeersMutex.RLock()
			if bytes.Equal(ipr[:], []byte{0, 0, 0, 0}) {
				for k, tcpConn0 := range tcpConnections[topic] {
					if _, ok := validPeersConnected[k]; ok && !bytes.Equal(k[:], MyIP[:]) {
						targets = append(targets, connEntry{k, tcpConn0})
					} else if !bytes.Equal(k[:], MyIP[:]) {
						logger.GetLogger().Println("when send to all, ignore connection", k)
					}
				}
			} else {
				if _, ok2 := validPeersConnected[ipr]; !ok2 {
					logger.GetLogger().Println("ignore when send to ", ipr)
				} else if tcpConn, ok := tcpConnections[topic][ipr]; ok {
					targets = append(targets, connEntry{ipr, tcpConn})
				}
			}
			PeersMutex.RUnlock()

			// Send outside the lock — I/O must not hold PeersMutex.
			var deletedIPs [][]byte
			for _, t := range targets {
				if err := Send(t.conn, s[4:]); err != nil {
					logger.GetLogger().Printf("LoopSend: error sending to %v: %v", t.ip, err)
					PeersMutex.Lock()
					deleted := CloseAndRemoveConnection(t.conn)
					PeersMutex.Unlock()
					deletedIPs = append(deletedIPs, deleted...)
				}
			}

			for _, deletedIP := range deletedIPs {
				ChanPeer <- deletedIP
			}
		case <-Quit:
			logger.GetLogger().Println("Should exit LoopSend")
			return
		}
		// NP-C2: no default case — the select blocks until sendChan or Quit is
		// ready instead of busy-spinning at 100% CPU.
	}
}

func StartNewConnection(ip [4]byte, receiveChan chan []byte, topic [2]byte) {
	ipport := fmt.Sprintf("%d.%d.%d.%d:%d", ip[0], ip[1], ip[2], ip[3], Ports[topic])
	if bytes.Equal(ip[:], []byte{127, 0, 0, 1}) {
		ipport = fmt.Sprintf(":%d", Ports[topic])
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", ipport)
	if err != nil {
		logger.GetLogger().Printf("Failed to resolve TCP address for %s: %v", ipport, err)
		return
	}

	if !AllowConnectionFromIP(ip) {
		logger.GetLogger().Printf("connection rate limit exceeded for %s; skipping dial", ipport)
		return
	}

	var tcpConn *net.TCPConn
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		tcpConn, err = net.DialTCP("tcp", nil, tcpAddr)
		if err == nil {
			break
		}
		logger.GetLogger().Printf("Connection attempt %d to %s failed: %v", i+1, ipport, err)

		time.Sleep(time.Second * 2)
		PeersMutex.Lock()
		ReduceTrustRegisterPeer(ip)
		trust, ok := validPeersConnected[ip]
		PeersMutex.Unlock()
		if ok && trust <= 0 {
			BanIP(ip)
		} else if i == maxRetries-1 {
			BanIP(ip)
		}

	}

	if err != nil {
		logger.GetLogger().Printf("Failed to establish connection to %s after %d attempts: %v", ipport, maxRetries, err)
		return
	}
	logger.GetLogger().Printf("Connection successful to %s topic %c%c", ipport, topic[0], topic[1])

	// NP-C3: run the peer-auth handshake on the freshly dialed connection BEFORE
	// it is published into tcpConnections and BEFORE the receive loop below reads
	// anything from it. tcpConn is only known to this goroutine at this point —
	// it is not yet reachable by LoopSend (which sends to whatever is already in
	// tcpConnections[topic]) or by any other receive loop — so there is no
	// reader/writer racing the handshake frames on this stream.
	self, idErr := activeWalletIdentity()
	if idErr != nil {
		logger.GetLogger().Println("handshake: cannot build identity:", idErr)
		tcpConn.Close()
		return
	}
	peerID, hsErr := HandshakeInitiator(tcpConn, self)
	if hsErr != nil {
		logger.GetLogger().Println("outbound handshake failed with", ipport, ":", hsErr)
		tcpConn.Close()
		PeersMutex.Lock()
		ReduceTrustRegisterPeer(ip)
		PeersMutex.Unlock()
		return
	}
	storeVerifiedNodeID(topic, ip, peerID)

	// Register the outbound connection for receiving.
	// If an accepted connection already exists in tcpConnections for this peer+topic,
	// keep it for sending (the other node reads from the outbound end of that connection).
	// This outbound connection will still be used for the receive loop below.
	PeersMutex.Lock()
	if _, ok := tcpConnections[topic]; !ok {
		tcpConnections[topic] = make(map[[4]byte]*net.TCPConn)
	}
	// Track whether we stored the outbound connection in tcpConnections.
	// If an accepted connection already exists, we keep it for sending and
	// only use this outbound connection for the receive loop.
	outboundStoredInMap := false
	if existingConn, exists := tcpConnections[topic][ip]; exists {
		_ = existingConn
	} else {
		tcpConnections[topic][ip] = tcpConn
		outboundStoredInMap = true
	}
	var topicipBytes [6]byte
	copy(topicipBytes[:], append(topic[:], ip[:]...))
	peersConnected[topicipBytes] = topic
	validPeersConnected[ip] = common.ConnectionMaxTries
	nodePeersConnected[ip] = common.ConnectionMaxTries
	PeersMutex.Unlock()

	reconnectionTries := 0
	resetNumber := 0

	// cleanupOutbound closes the outbound connection and triggers reconnection.
	// If the outbound conn is not in tcpConnections, we close it directly and
	// send a ChanPeer notification to trigger re-establishment.
	cleanupOutbound := func() {
		PeersMutex.Lock()
		if outboundStoredInMap {
			deletedIP := CloseAndRemoveConnection(tcpConn)
			PeersMutex.Unlock()
			for _, d := range deletedIP {
				ChanPeer <- d
			}
		} else {
			if tcpConn != nil {
				tcpConn.Close()
			}
			PeersMutex.Unlock()
			// Notify to re-establish the receive connection
			ChanPeer <- append(topic[:], ip[:]...)
		}
	}

	defer func() {
		if r := recover(); r != nil {
			logger.GetLogger().Printf("Recovered from panic in connection to %v: %v", ip, r)
			receiveChan <- []byte("EXIT")
			cleanupOutbound()
		}
	}()


	rTopic := map[[2]byte][]byte{}

	for {
		resetNumber++
		if resetNumber%100 == 0 {
			reconnectionTries = 0
		}

		select {
		case <-Quit:
			PeersMutex.Lock()
			CloseAndRemoveConnection(tcpConn)
			PeersMutex.Unlock()
			return
		default:
			r := Receive(topic, tcpConn)
			if r == nil {
				continue
			}
			if bytes.Equal(r, []byte("<-ERR->")) {
				if reconnectionTries > common.ConnectionMaxTries {
					logger.GetLogger().Println("error in read. Closing connection", ip, string(r))
					tcpConn.Close()
					tcpConn, err = net.DialTCP("tcp", nil, tcpAddr)
					if err != nil {
						logger.GetLogger().Printf("Connection attempt to %s failed: %v", ipport, err.Error())
						// Reconnection failed — exit cleanly so subscriber can
						// be re-established by the peer discovery loop.
						receiveChan <- []byte("EXIT")
						return
					}
					reconnectionTries = 0
					continue
				}
				reconnectionTries++
				time.Sleep(time.Millisecond * 10)
				continue
			}
			if bytes.Equal(r, []byte("<-CLS->")) {
				receiveChan <- []byte("EXIT")
				cleanupOutbound()
				return

			}
			//if bytes.Equal(r, []byte("WAIT")) {
			//	waitChan <- topic[:]
			//	continue
			//}

			rt, ok := rTopic[topic]
			if ok {
				r = append(rt, r...)
			}
			// NP-M3: guard the trailing-marker check so a fragment shorter than
			// the 7-byte "<-END->" marker cannot panic on r[len(r)-7:].
			if len(r) < 7 || !bytes.Equal(r[len(r)-7:], []byte("<-END->")) {
				rTopic[topic] = r
			} else {
				rTopic[topic] = []byte{}
			}

			if int32(len(r)) > MaxMessageSizeForTopic(topic) {
				logger.GetLogger().Println("error: too long message received: ", len(r))
				PeersMutex.Lock()
				ReduceTrustRegisterPeer(ip)
				PeersMutex.Unlock()
				rTopic[topic] = []byte{}
				if trust, ok := validPeersConnected[ip]; ok && trust <= 0 {
					BanIP(ip)
					receiveChan <- []byte("EXIT")
					return
				}
				continue
			}
			if bytes.Equal(r[len(r)-7:], []byte("<-END->")) {
				if len(r) > 4 {
					if bytes.Equal(r[:4], common.MessageInitialization[:]) {
						if !AllowMessageFromIP(ip) {
							logger.GetLogger().Println("message rate limit exceeded for", ip)
							PeersMutex.Lock()
							ReduceTrustRegisterPeer(ip)
							trust, ok := validPeersConnected[ip]
							PeersMutex.Unlock()
							if ok && trust <= 0 {
								BanIP(ip)
								receiveChan <- []byte("EXIT")
								return
							}
							continue // drop this message; do not dispatch
						}
						receiveChan <- append(ip[:], r[4:]...)
					} else {
						logger.GetLogger().Println("wrong MessageInitialization", r[:4], "should be", common.MessageInitialization[:])
						PeersMutex.Lock()
						ReduceTrustRegisterPeer(ip)
						PeersMutex.Unlock()
						if trust, ok := validPeersConnected[ip]; ok && trust <= 0 {
							BanIP(ip)
							receiveChan <- []byte("EXIT")
							return
						}
					}
				}
			}
		}
	}
}

func CloseAndRemoveConnection(tcpConn *net.TCPConn) [][]byte {
	if tcpConn == nil {
		return [][]byte{}
	}

	topicipBytes := [6]byte{}
	deletedIP := [][]byte{}
	// Find and remove the connection using pointer comparison
	for topic, connections := range tcpConnections {
		for peerIP, conn := range connections {
			if conn == tcpConn {
				deletedIP = append(deletedIP, append(topic[:], peerIP[:]...))
				tcpConn.Close()
				copy(topicipBytes[:], append(topic[:], peerIP[:]...))
				delete(tcpConnections[topic], peerIP)
				delete(peersConnected, topicipBytes)
				delete(oldPeers, topicipBytes)
				// If no more topic connections remain for this IP, remove from peer maps
				hasConnection := false
				for _, conns := range tcpConnections {
					if _, ok := conns[peerIP]; ok {
						hasConnection = true
						break
					}
				}
				if !hasConnection {
					delete(validPeersConnected, peerIP)
					delete(nodePeersConnected, peerIP)
				}
				return deletedIP
			}
		}
	}
	return deletedIP
}
