package tcpip

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

var ChanPeer = make(chan []byte, 50)

var (
	dialingMutex sync.Mutex
	dialing      = make(map[[6]byte]struct{})
)

func beginDial(topic [2]byte, ip [4]byte) bool {
	var key [6]byte
	copy(key[:2], topic[:])
	copy(key[2:], ip[:])
	dialingMutex.Lock()
	defer dialingMutex.Unlock()
	if _, exists := dialing[key]; exists {
		return false
	}
	dialing[key] = struct{}{}
	return true
}

func endDial(topic [2]byte, ip [4]byte) {
	var key [6]byte
	copy(key[:2], topic[:])
	copy(key[2:], ip[:])
	dialingMutex.Lock()
	delete(dialing, key)
	dialingMutex.Unlock()
}

// quietConnTimeout is how long an outbound connection may deliver nothing
// before it is declared dead and torn down. A peer lost to a NAT-mapping drop
// or a silent reboot produces no EOF and no read error - just an endless run of
// 30s read timeouts - so without this guard the receive loop spins forever,
// the dialing dedup blocks every reconnection attempt ("connection already
// active or pending"), and requests sent to the stale connection vanish. In a
// syncing node that shows up as transactions that never arrive and a sync
// wedged on the same height until restart. Every live topic carries traffic
// far more often than this (sync 'hi' each second, nonces each block).
const quietConnTimeout = 3 * time.Minute

// closeAndRemovePeerTopic closes and unregisters whatever connection is stored
// for (topic, ip) - outbound or accepted. Used on quiet-death, where the whole
// peer went silent: keeping a possibly-equally-dead accepted stream as the send
// path would make the fresh dial reuse it and keep sending into the void.
// RecycleTopicConnection tears down every connection to ip on topic and asks
// discovery to re-establish it. This is the recovery of last resort for a
// half-dead link: the local receive loop may be perfectly healthy while the
// PEER's send side points at a stale stream (e.g. left over from our earlier
// restart), in which case its replies never arrive and nothing on our side
// times out. A fresh dial forces the peer to register a new stream for us.
func RecycleTopicConnection(topic [2]byte, ip [4]byte) {
	logger.GetLogger().Printf("recycling connection to %v on topic %c%c", ip, topic[0], topic[1])
	deletedIP := closeAndRemovePeerTopic(topic, ip)
	for _, d := range deletedIP {
		select {
		case ChanPeer <- d:
		default:
			logger.GetLogger().Println("NP-M2: ChanPeer full, dropping peer notification")
		}
	}
	if len(deletedIP) == 0 {
		select {
		case ChanPeer <- append(topic[:], ip[:]...):
		default:
			logger.GetLogger().Println("NP-M2: ChanPeer full, dropping peer notification")
		}
	}
}

// DropTopicConnection closes and unregisters every connection to ip on topic and
// - unlike RecycleTopicConnection - does NOT ask discovery to re-establish it.
//
// This is for turning a peer away on purpose: one whose genesis block is not
// ours has nothing we want, now or on retry. Recycling such a peer would dial it
// straight back and spin.
func DropTopicConnection(topic [2]byte, ip [4]byte) {
	logger.GetLogger().Printf("dropping connection to %v on topic %c%c", ip, topic[0], topic[1])
	closeAndRemovePeerTopic(topic, ip)
}

func closeAndRemovePeerTopic(topic [2]byte, ip [4]byte) [][]byte {
	PeersMutex.Lock()
	defer PeersMutex.Unlock()
	deletedIP := [][]byte{}
	if conn, ok := tcpConnections[topic][ip]; ok {
		deletedIP = CloseAndRemoveConnection(conn)
	}
	if accepted, ok := acceptedConnections[topic][ip]; ok {
		accepted.Close()
		delete(acceptedConnections[topic], ip)
	}
	return deletedIP
}

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
	conn net.Conn
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
					// Broadcasts go to peers, never back into our own listener:
					// a self-connection would hand us our own 'hi' and let the
					// node treat itself as a peer that is ahead of it. The
					// self-nonce path sends to itself directly, not by broadcast.
					if IsSelfIP(k) {
						continue
					}
					if _, ok := validPeersConnected[k]; ok {
						targets = append(targets, connEntry{k, tcpConn0})
					} else {
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
				select {
				case ChanPeer <- deletedIP:
				default:
					logger.GetLogger().Println("NP-M2: ChanPeer full, dropping peer notification")
				}
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
	if !beginDial(topic, ip) {
		logger.GetLogger().Printf("connection already active or pending for topic %c%c peer %v", topic[0], topic[1], ip)
		select {
		case receiveChan <- []byte("EXIT"):
		default:
		}
		return
	}
	defer endDial(topic, ip)
	// Every terminal path must release the subscriber. Previously resolve,
	// rate-limit, dial and handshake failures returned silently, leaving a busy
	// subscriber goroutine behind and enabling overlapping retry lifecycles.
	defer func() {
		select {
		case receiveChan <- []byte("EXIT"):
		default:
		}
	}()
	ipport := fmt.Sprintf("%d.%d.%d.%d:%d", ip[0], ip[1], ip[2], ip[3], Ports[topic])
	if bytes.Equal(ip[:], []byte{127, 0, 0, 1}) {
		ipport = fmt.Sprintf(":%d", Ports[topic])
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", ipport)
	if err != nil {
		logger.GetLogger().Printf("Failed to resolve TCP address for %s: %v", ipport, err)
		return
	}

	if IsIPBanned(ip) {
		logger.GetLogger().Printf("peer %s is banned or blacklisted; skipping dial", ipport)
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

	}

	if err != nil {
		logger.GetLogger().Printf("Failed to establish connection to %s after %d attempts: %v", ipport, maxRetries, err)
		return
	}
	// Keepalive on the outbound stream too (the accepted path already sets it),
	// so the kernel notices a vanished peer instead of buffering writes forever.
	tcpConn.SetKeepAlive(true)
	tcpConn.SetKeepAlivePeriod(30 * time.Second)
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
	peerID, sKeys, hsErr := HandshakeInitiator(tcpConn, self)
	if hsErr != nil {
		logger.GetLogger().Println("outbound handshake failed with", ipport, ":", hsErr)
		tcpConn.Close()
		// Only authenticated protocol abuse is bannable. EOF, reset and timeout
		// are ordinary transport failures and end this lifecycle without a ban.
		if isHandshakeProtocolViolation(hsErr) {
			BanIP(ip)
		}
		return
	}
	storeVerifiedNodeID(topic, ip, peerID)

	// Task 3: wrap the raw, now-authenticated stream in the AEAD record layer.
	// tcpConn stays the raw *net.TCPConn (used for dial/re-dial and Close);
	// conn is the net.Conn actually stored/sent/received on from here on.
	// Use the session keys the handshake just returned directly — routing them
	// through a shared (topic, ip)-keyed map would collide with the concurrent
	// responder handshake on a self-connection (genesis node dialing itself on
	// 127.0.0.1), clobbering the directional keys and breaking decryption.
	if sKeys == nil {
		logger.GetLogger().Println("outbound handshake: no session keys derived for", ip)
		tcpConn.Close()
		return
	}
	conn, err := newEncryptedConn(tcpConn, sKeys)
	if err != nil {
		logger.GetLogger().Println("outbound handshake: failed to wrap connection:", err)
		tcpConn.Close()
		return
	}

	// Register the outbound connection for receiving.
	// If an accepted connection already exists in tcpConnections for this peer+topic,
	// keep it for sending (the other node reads from the outbound end of that connection).
	// This outbound connection will still be used for the receive loop below.
	PeersMutex.Lock()
	if _, ok := tcpConnections[topic]; !ok {
		tcpConnections[topic] = make(map[[4]byte]net.Conn)
	}
	// Track whether we stored the outbound connection in tcpConnections.
	// If an accepted connection already exists, we keep it for sending and
	// only use this outbound connection for the receive loop.
	outboundStoredInMap := false
	if existingConn, exists := tcpConnections[topic][ip]; exists {
		_ = existingConn
	} else {
		tcpConnections[topic][ip] = conn
		outboundStoredInMap = true
	}
	var topicipBytes [6]byte
	copy(topicipBytes[:], append(topic[:], ip[:]...))
	peersConnected[topicipBytes] = topic
	validPeersConnected[ip] = common.ConnectionMaxTries
	nodePeersConnected[ip] = common.ConnectionMaxTries
	PeersMutex.Unlock()

	reconnectionTries := 0

	// cleanupOutbound closes the outbound connection and triggers reconnection.
	// If the outbound conn is not in tcpConnections, we close it directly and
	// send a ChanPeer notification to trigger re-establishment.
	cleanupOutbound := func() {
		PeersMutex.Lock()
		if outboundStoredInMap {
			deletedIP := CloseAndRemoveConnection(conn)
			PeersMutex.Unlock()
			for _, d := range deletedIP {
				select {
				case ChanPeer <- d:
				default:
					logger.GetLogger().Println("NP-M2: ChanPeer full, dropping peer notification")
				}
			}
		} else {
			if conn != nil {
				conn.Close()
			}
			PeersMutex.Unlock()
			// Notify to re-establish the receive connection
			select {
			case ChanPeer <- append(topic[:], ip[:]...):
			default:
				logger.GetLogger().Println("NP-M2: ChanPeer full, dropping peer notification")
			}
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
	// Topics currently discarding the tail of an over-long message. Dropping the
	// accumulated prefix is not enough: the rest of that message keeps arriving,
	// and without this the next fragment is mistaken for the start of a new one,
	// which is what produced "wrong MessageInitialization" and left the
	// connection permanently desynchronised.
	discardingTopic := map[[2]byte]bool{}

	// lastData tracks the last moment ANY bytes arrived on this connection, so a
	// silently dead peer (NAT drop, hard reboot - no EOF, no error, only read
	// timeouts) is detected instead of spinning here forever while the dialing
	// dedup blocks every reconnection. Self/loopback connections are exempt: they
	// cannot die to a NAT and may be legitimately quiet.
	lastData := time.Now()

	for {
		select {
		case <-Quit:
			PeersMutex.Lock()
			CloseAndRemoveConnection(conn)
			PeersMutex.Unlock()
			return
		default:
			r := Receive(topic, conn)
			if r == nil {
				if !IsSelfIP(ip) && time.Since(lastData) > quietConnTimeout {
					logger.GetLogger().Printf("no data from %v on topic %c%c for %s - dropping dead connection and reconnecting",
						ip, topic[0], topic[1], time.Since(lastData).Truncate(time.Second))
					if conn != nil {
						conn.Close()
					}
					deletedIP := closeAndRemovePeerTopic(topic, ip)
					receiveChan <- []byte("EXIT")
					for _, d := range deletedIP {
						select {
						case ChanPeer <- d:
						default:
							logger.GetLogger().Println("NP-M2: ChanPeer full, dropping peer notification")
						}
					}
					// Ask discovery to re-establish this exact (topic, ip) even if
					// the map held nothing to delete.
					if len(deletedIP) == 0 {
						select {
						case ChanPeer <- append(topic[:], ip[:]...):
						default:
							logger.GetLogger().Println("NP-M2: ChanPeer full, dropping peer notification")
						}
					}
					return
				}
				continue
			}
			lastData = time.Now()
			if bytes.Equal(r, []byte("<-ERR->")) {
				if reconnectionTries > common.ConnectionMaxTries {
					logger.GetLogger().Println("error in read. Closing connection", ip, string(r))
					conn.Close()
					tcpConn, err = net.DialTCP("tcp", nil, tcpAddr)
					if err != nil {
						logger.GetLogger().Printf("Connection attempt to %s failed: %v", ipport, err.Error())
						// Reconnection failed — exit cleanly so subscriber can
						// be re-established by the peer discovery loop.
						receiveChan <- []byte("EXIT")
						return
					}
					tcpConn.SetKeepAlive(true)
					tcpConn.SetKeepAlivePeriod(30 * time.Second)
					// NP-C3: the re-dial produced a brand-new TCP stream, so it
					// must be re-authenticated with a fresh handshake before the
					// receive loop resumes reading from it — otherwise an
					// unauthenticated stream would be trusted just like the
					// original, already-handshaken connection.
					if _, sKeys, hsErr := HandshakeInitiator(tcpConn, self); hsErr != nil {
						logger.GetLogger().Println("re-dial handshake failed with", ipport, ":", hsErr)
						tcpConn.Close()
						if isHandshakeProtocolViolation(hsErr) {
							BanIP(ip)
						}
						receiveChan <- []byte("EXIT")
						return
					} else {
						// Task 3: re-wrap the re-dialed raw stream with the fresh
						// session keys before the receive loop resumes reading —
						// the old encryptedConn (and its counters) belonged to the
						// now-closed connection and must not be reused. Use the keys
						// the handshake just returned directly (a shared (topic, ip)
						// map would collide with the concurrent responder handshake
						// on a self-connection).
						if sKeys == nil {
							logger.GetLogger().Println("re-dial handshake: no session keys derived for", ip)
							tcpConn.Close()
							receiveChan <- []byte("EXIT")
							return
						}
						newConn, wrapErr := newEncryptedConn(tcpConn, sKeys)
						if wrapErr != nil {
							logger.GetLogger().Println("re-dial handshake: failed to wrap connection:", wrapErr)
							tcpConn.Close()
							receiveChan <- []byte("EXIT")
							return
						}
						conn = newConn
						if outboundStoredInMap {
							PeersMutex.Lock()
							if _, ok := tcpConnections[topic]; !ok {
								tcpConnections[topic] = make(map[[4]byte]net.Conn)
							}
							tcpConnections[topic][ip] = conn
							PeersMutex.Unlock()
						}
					}
					reconnectionTries = 0
					lastData = time.Now() // fresh stream - restart the quiet clock
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
			reconnectionTries = 0 // NP-M4: a real frame arrived — the connection is healthy, so reset the consecutive-error counter (was reset on a fixed iteration cadence)
			//if bytes.Equal(r, []byte("WAIT")) {
			//	waitChan <- topic[:]
			//	continue
			//}

			if discardingTopic[topic] {
				// Still inside the over-long message: swallow fragments until its
				// end marker, then resume framing on a real boundary.
				if len(r) >= 7 && bytes.Equal(r[len(r)-7:], []byte("<-END->")) {
					discardingTopic[topic] = false
					logger.GetLogger().Printf("resynchronised on topic %c%c after discarding an over-long message", topic[0], topic[1])
				}
				continue
			}

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
				logger.GetLogger().Printf("error: too long message received on topic %c%c: %d bytes, cap is %d",
					topic[0], topic[1], len(r), MaxMessageSizeForTopic(topic))
				// Unless this fragment already ended the message, the rest of it
				// is still in flight and must be skipped rather than parsed.
				if len(r) < 7 || !bytes.Equal(r[len(r)-7:], []byte("<-END->")) {
					discardingTopic[topic] = true
				}
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

func CloseAndRemoveConnection(tcpConn net.Conn) [][]byte {
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
				if accepted, ok := acceptedConnections[topic][peerIP]; ok && accepted == tcpConn {
					delete(acceptedConnections[topic], peerIP)
				}
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
