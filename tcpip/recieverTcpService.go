package tcpip

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"golang.org/x/exp/rand"
)

var (
	peersConnected      = map[[6]byte][2]byte{}
	validPeersConnected = map[[4]byte]int{}
	nodePeersConnected  = map[[4]byte]int{}
	oldPeers            = map[[6]byte][2]byte{}
	PeersCount          = 0
	waitChan            = make(chan []byte)
	tcpConnections      = make(map[[2]byte]map[[4]byte]net.Conn)
	// acceptedConnections identifies entries installed by the listener.  An
	// outbound connection may temporarily occupy tcpConnections until the peer's
	// matching inbound stream arrives; replacing that entry must not close the
	// outbound stream because its receive loop is still using it.
	acceptedConnections = make(map[[2]byte]map[[4]byte]net.Conn)
	PeersMutex          = &sync.RWMutex{}
	Quit                chan os.Signal
	TransactionTopic    = [2]byte{'T', 'T'}
	NonceTopic          = [2]byte{'N', 'N'}
	SelfNonceTopic      = [2]byte{'S', 'S'}
	SyncTopic           = [2]byte{'B', 'B'}
	RPCTopic            = [2]byte{'R', 'P'}
)

var Ports = map[[2]byte]int{
	TransactionTopic: 19023,
	NonceTopic:       18023,
	SelfNonceTopic:   17023,
	SyncTopic:        16023,
	RPCTopic:         19009,
}

var MyIP [4]byte
var MyIPSelfNonce [4]byte
var InternalIP [4]byte

func init() {
	Quit = make(chan os.Signal)
	signal.Notify(Quit, syscall.SIGTERM, syscall.SIGINT, os.Interrupt)
	MyIP = GetIp()
	copy(InternalIP[:], MyIP[:])

	logger.GetLogger().Println("Discover MyIP: ", MyIP)
	for k := range Ports {
		tcpConnections[k] = map[[4]byte]net.Conn{}
		acceptedConnections[k] = map[[4]byte]net.Conn{}
	}
	// Get NODE_IP environment variable
	ips := os.Getenv("NODE_IP")
	if ips == "" {
		logger.GetLogger().Println("Warning: NODE_IP environment variable is not set")
		return
	}

	// Parse the IP address
	ip := net.ParseIP(ips)
	if ip == nil {
		logger.GetLogger().Fatalf("Failed to parse NODE_IP '%s' as an IP address", ips)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		logger.GetLogger().Fatalf("Failed to parse NODE_IP '%s' as 4 byte format", ips)
	}
	// Assign the parsed IP to tcpip.MyIP
	MyIP = [4]byte(ip4)

	// Get NODE_IP_SELF_NONCE environment variable
	ips = os.Getenv("NODE_IP_SELF_NONCE")
	if ips == "" {
		logger.GetLogger().Println("Warning: NODE_IP_SELF_NONCE environment variable is not set")
		MyIPSelfNonce = [4]byte(MyIP)
	} else {

		// Parse the IP address
		ip := net.ParseIP(ips)
		if ip == nil {
			logger.GetLogger().Fatalf("Failed to parse NODE_IP_SELF_NONCE '%s' as an IP address", ips)
		}

		ip4 := ip.To4()
		if ip4 == nil {
			logger.GetLogger().Fatalf("Failed to parse NODE_IP_SELF_NONCE '%s' as 4 byte format", ips)
		}
		// Assign the parsed IP to tcpip.MyIP
		MyIPSelfNonce = [4]byte(ip4)
	}

	AddWhiteListIPs(MyIP)
	AddWhiteListIPs(MyIPSelfNonce)
	AddWhiteListIPs([4]byte{0, 0, 0, 0})
	// Rest of your application logic here...
	logger.GetLogger().Printf("Successfully set NODE_IP to %d.%d.%d.%d", int(MyIP[0]), int(MyIP[1]), int(MyIP[2]), int(MyIP[3]))
	validPeersConnected[MyIP] = 100
	validPeersConnected[MyIPSelfNonce] = 100
	// Get BLACKLIST_IP environment variable (comma-separated, permanent bans)
	ips = os.Getenv("BLACKLIST_IP")
	if ips != "" {
		for _, ipStr := range strings.Split(ips, ",") {
			ipStr = strings.TrimSpace(ipStr)
			ip = net.ParseIP(ipStr)
			if ip == nil {
				logger.GetLogger().Printf("Warning: Failed to parse BLACKLIST_IP '%s' as an IP address\n", ipStr)
				continue
			}
			ip4 = ip.To4()
			if ip4 == nil {
				logger.GetLogger().Printf("Warning: failed to parse BLACKLIST_IP '%s' as 4 byte format\n", ipStr)
				continue
			}
			logger.GetLogger().Printf("Permanently blacklisting IP %s", ipStr)
			AddBlackListIPs([4]byte(ip4))
		}
	}
	// Get WHITELIST_IP environment variable
	ips = os.Getenv("WHITELIST_IP")
	if ips == "" {
		logger.GetLogger().Println("Warning: WHITELIST_IP environment variable is not set")
		return
	}

	// Split the string into individual IP addresses
	ipStrings := strings.Split(ips, ",")
	// Process each IP address
	for _, ipStr := range ipStrings {
		logger.GetLogger().Println(ipStr)
		// Trim any whitespace
		ipStr = strings.TrimSpace(ipStr)

		// Parse the IP address
		ip = net.ParseIP(ipStr)
		if ip == nil {
			logger.GetLogger().Printf("Warning: Failed to parse WHITELIST_IP '%s' as an IP address\n", ipStr)
			return
		}

		ip4 = ip.To4()
		if ip4 == nil {
			logger.GetLogger().Printf("Warning: failed to parse WHITELIST_IP '%s' as 4 byte format\n", ipStr)
			return
		}
		AddWhiteListIPs([4]byte(ip4))
	}
}

func GetIp() [4]byte {
	ifaces, err := net.Interfaces()
	if err != nil {
		logger.GetLogger().Println("Can not obtain net interface")
		return [4]byte{}
	}
	ipInternal := [4]byte{}
	zeros := [4]byte{}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			logger.GetLogger().Println("Can not get net addresses")
			return [4]byte{}
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			if ip.IsLoopback() {
				continue
			}
			if !ip.IsPrivate() {
				return [4]byte(ip.To4())
			} else if bytes.Equal(ipInternal[:], zeros[:]) {
				ipInternal = [4]byte(ip.To4())
			}
		}
	}
	return ipInternal
}
func Listen(ip [4]byte, port int) (*net.TCPListener, error) {
	ipport := fmt.Sprintf("%d.%d.%d.%d:%d", ip[0], ip[1], ip[2], ip[3], port)
	protocol := "tcp"
	addr, err := net.ResolveTCPAddr(protocol, ipport)
	if err != nil {
		logger.GetLogger().Println("Wrong Address", err)
		return nil, err
	}
	conn, err := net.ListenTCP(protocol, addr)
	if err != nil {
		logger.GetLogger().Printf("Some error %v\n", err)
		return nil, err
	}
	return conn, nil
}

func Accept(topic [2]byte, conn *net.TCPListener) (*net.TCPConn, error) {
	tcpConn, err := conn.AcceptTCP()
	if err != nil {
		return nil, fmt.Errorf("error accepting connection: %w", err)
	}

	ip, err := parsePeerIP(tcpConn)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("registration failed for connection: %w", err)
	}
	if !admitPeer(ip) {
		tcpConn.Close()
		return nil, fmt.Errorf("registration failed for connection")
	}
	// NP-H2: bound concurrent inbound connections per topic. Whitelisted operators bypass.
	if !isWhitelisted(ip) && inboundCapReached(topic) {
		tcpConn.Close()
		return nil, fmt.Errorf("inbound connection cap reached for topic")
	}

	// NP-C3: run the peer-auth handshake on the freshly accepted connection
	// BEFORE it is published into tcpConnections. Accept() runs synchronously
	// in StartNewListener's loop and tcpConn is not reachable by any other
	// goroutine (LoopSend, the receive loop in StartNewConnection, etc.) until
	// publishAcceptedConn below runs — so there is no reader/writer racing the
	// handshake frames on this stream.
	self, idErr := activeWalletIdentity()
	if idErr != nil {
		logger.GetLogger().Println("handshake: cannot build identity:", idErr)
		tcpConn.Close()
		return nil, fmt.Errorf("handshake identity unavailable")
	}
	peerID, sKeys, hsErr := HandshakeResponder(tcpConn, self)
	if hsErr != nil {
		logger.GetLogger().Println("inbound handshake failed:", hsErr)
		tcpConn.Close()
		// Ban only authenticated protocol abuse. A peer that disconnects during
		// handshake may simply have restarted or lost connectivity.
		if isHandshakeProtocolViolation(hsErr) {
			BanIP(ip)
		}
		return nil, fmt.Errorf("inbound handshake failed: %w", hsErr)
	}
	storeVerifiedNodeID(topic, ip, peerID)

	// TCP-specific options must be set on the raw *net.TCPConn before it is
	// wrapped in encryptedConn (net.Conn has no SetKeepAlive).
	tcpConn.SetKeepAlive(true)

	// Task 3: wrap the raw, now-authenticated stream in the AEAD record layer
	// using the keys the handshake just derived. Use sKeys directly — routing
	// it through a shared (topic, ip)-keyed map would collide with the
	// concurrent initiator handshake on a self-connection (genesis node dialing
	// itself on 127.0.0.1), clobbering the directional keys and breaking
	// decryption on both ends.
	if sKeys == nil {
		logger.GetLogger().Println("inbound handshake: no session keys derived for", ip)
		tcpConn.Close()
		return nil, fmt.Errorf("inbound handshake: session keys unavailable")
	}
	ec, err := newEncryptedConn(tcpConn, sKeys)
	if err != nil {
		logger.GetLogger().Println("inbound handshake: failed to wrap connection:", err)
		tcpConn.Close()
		return nil, fmt.Errorf("inbound handshake: encryptedConn wrap failed: %w", err)
	}

	// Key the connection by the authenticated peer's HANDLE, not the transport
	// IP: two nodes behind one NAT arrive from the same IP and used to evict
	// each other's accepted stream on the shared (topic, ip) slot. The handle
	// keeps them apart everywhere downstream (maps, claims, counters). Our own
	// self-connection keeps the transport key (see connKeyFor).
	key := connKeyFor(peerID, ip)
	publishAcceptedConn(topic, key, ec)
	// Read the inbound stream too. A peer that cannot be dialed back (NAT)
	// sends on the very link it dialed to us; without a reader here it was
	// mute. Self-connections keep the historical single-reader model (the dial
	// end reads), so no reader is spawned for them (key == transport IP then).
	if IsPeerHandle(key) {
		go acceptedReceiveLoop(topic, key, ip, ec)
	}
	return tcpConn, nil
}

func Send(conn net.Conn, message []byte) error {

	message = append(common.MessageInitialization[:], message...)
	message = append(message, []byte("<-END->")...)

	// Set write deadline to 2 seconds
	conn.SetWriteDeadline(time.Now().Add(4 * time.Second))

	_, err := conn.Write(message)
	if err != nil {
		logger.GetLogger().Printf("Can't send response: %v", err)
		return err
	}
	return nil
}

// Receive reads data from the connection and handles errors. conn is the
// post-handshake connection stored in tcpConnections, which since Task 3 is
// always an encryptedConn (net.Conn) for authenticated peers — Read()
// transparently decrypts. A decrypt failure (tampering/desync) surfaces from
// encryptedConn.Read as a plain error, is not io.EOF and not a net.Error
// timeout, so it falls through to the "<-ERR->" sentinel below like any other
// read error, and the caller (StartNewConnection's receive loop) drops/
// reconnects the connection — it never continues past a decrypt failure.
func Receive(topic [2]byte, conn net.Conn) []byte {
	const bufSize = 1024 //1048576

	if conn == nil {
		return []byte("<-CLS->")
	}

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, bufSize)
	n, err := conn.Read(buf)

	if err != nil {
		if err == io.EOF {
			return []byte("<-CLS->")
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil // read timeout, not an error — just no data yet
		}
		//handleConnectionError(err, topic, conn)
		return []byte("<-ERR->")
	}

	return buf[:n]
}

// ValidRegisterPeer Confirm that ip is valid node
func ValidRegisterPeer(ip [4]byte) {
	ip = canonicalIP(ip) // trust is per transport source, tags may be handles
	PeersMutex.Lock()
	defer PeersMutex.Unlock()
	if n, ok := validPeersConnected[ip]; ok {
		if n < 3 {
			validPeersConnected[ip]++
		}
		return
	}
	validPeersConnected[ip] = common.ConnectionMaxTries

}

// NodeRegisterPeer Confirm that ip is valid node IP
func NodeRegisterPeer(ip [4]byte) {
	ip = canonicalIP(ip) // trust is per transport source, tags may be handles
	PeersMutex.Lock()
	defer PeersMutex.Unlock()
	if _, ok := nodePeersConnected[ip]; ok {
		validPeersConnected[ip] = common.ConnectionMaxTries
		return
	}
	nodePeersConnected[ip] = common.ConnectionMaxTries
}

// ReduceTrustRegisterPeer limit connections attempts needs to be peer lock
func ReduceTrustRegisterPeer(ip [4]byte) {
	ip = canonicalIP(ip) // trust is per transport source, tags may be handles
	// || bytes.Equal(ip[:2], InternalIP[:2])
	if bytes.Equal(ip[:], MyIP[:]) || bytes.Equal(ip[:], []byte{0, 0, 0, 0}) {
		return
	}
	if _, ok := validPeersConnected[ip]; !ok {
		return
	}

	validPeersConnected[ip]--
	if validPeersConnected[ip] <= 0 {
		delete(validPeersConnected, ip)
	}
}

func FullyDeleteConnection(tcpConn net.Conn) {
	PeersMutex.Lock()
	defer PeersMutex.Unlock()
	CloseAndRemoveConnection(tcpConn)
}

// parsePeerIP extracts the 4-byte IPv4 address from an accepted TCP connection's
// remote address.
func parsePeerIP(tcpConn *net.TCPConn) ([4]byte, error) {
	raddr := tcpConn.RemoteAddr().String()
	ra := strings.Split(raddr, ":")
	ips := strings.Split(ra[0], ".")
	var ip [4]byte
	if len(ips) != 4 {
		return ip, fmt.Errorf("invalid remote address: %s", raddr)
	}
	for i := 0; i < 4; i++ {
		num, err := strconv.Atoi(ips[i])
		if err != nil {
			return ip, fmt.Errorf("invalid IP address segment: %s", ips[i])
		}
		ip[i] = byte(num)
	}
	return ip, nil
}

// IsSelfIP reports whether ip refers to this node itself — either configured
// self address or IPv4 loopback. Self-connections (e.g. the self-nonce topic)
// dial our own listener, so the dial end and accept end are two ends of ONE TCP
// link that collide on the same (topic, ip) map key; they must not be treated
// as duplicate connections where the "old" one gets closed.
//
// It is equally the answer to "is this a peer?": a self-connection carries our
// own messages back to us, so counting it as a peer makes a node that is alone
// on the network look connected, and makes our own height claim look like a
// peer's.
func IsSelfIP(ip [4]byte) bool {
	return bytes.Equal(ip[:], MyIP[:]) ||
		bytes.Equal(ip[:], MyIPSelfNonce[:]) ||
		bytes.Equal(ip[:], []byte{127, 0, 0, 1})
}

// admitPeer runs the ban/rate-limit checks for an inbound connection BEFORE any
// handshake or connection registration happens. It does not touch tcpConnections.
// NP-C3: this gate must run first so an unauthenticated/banned peer never even
// reaches the handshake step.
func admitPeer(ip [4]byte) bool {
	if IsIPBanned(ip) {
		logger.GetLogger().Println("IP is BANNED", ip)
		return false
	}
	if !AllowConnectionFromIP(ip) {
		logger.GetLogger().Println("connection rate limit exceeded for", ip)
		BanIP(ip)
		return false
	}
	return true
}

// publishAcceptedConn registers an accepted connection for sending/tracking.
// NP-C3: this MUST only be called AFTER the peer-auth handshake has succeeded
// on tcpConn, because publishing into tcpConnections makes the connection a
// live target for LoopSend — publishing before the handshake completes would
// let ordinary topic traffic interleave on the wire with handshake frames.
func publishAcceptedConn(topic [2]byte, ip [4]byte, tcpConn net.Conn) {
	var topicipBytes [6]byte
	copy(topicipBytes[:], append(topic[:], ip[:]...))

	PeersMutex.Lock()
	defer PeersMutex.Unlock()

	// Initialize the map for the topic if it doesn't exist
	if _, ok := tcpConnections[topic]; !ok {
		tcpConnections[topic] = make(map[[4]byte]net.Conn)
	}

	if _, ok := acceptedConnections[topic]; !ok {
		acceptedConnections[topic] = make(map[[4]byte]net.Conn)
	}

	// Replace only an older accepted/send stream. The generic map can currently
	// contain the peer's outbound/read stream; closing it here caused the
	// handshake -> EOF -> reconnect -> ban storm during simultaneous dialing.
	if oldConn, ok := tcpConnections[topic][ip]; ok {
		// For a self/loopback connection (the genesis node dialing its own
		// listener, e.g. the self-nonce topic) the "old" entry is the dial-side
		// end of the SAME physical TCP link: StartNewConnection reads from that
		// end (D) while LoopSend must write to this accepted end (A) for the
		// bytes to reach D's reader. Closing D here would tear down the dialer's
		// live receive loop and send both ends into an endless reconnect loop.
		// So only close a genuinely distinct old connection to a remote peer;
		// for self, just replace the map value (LoopSend then writes to A).
		if previousAccepted, accepted := acceptedConnections[topic][ip]; accepted && oldConn == previousAccepted && oldConn != tcpConn && !IsSelfIP(ip) {
			// Close the old connection before replacing it, so the other node's
			// outbound receive loop gets a clean EOF instead of lingering and
			// triggering repeated reconnections.
			oldConn.Close()
		}
	}

	// Register the accepted connection for sending. Trust counters are per
	// transport source (canonicalIP), while the map key may be a peer handle.
	tcpConnections[topic][ip] = tcpConn
	acceptedConnections[topic][ip] = tcpConn
	peersConnected[topicipBytes] = topic
	trustIP := canonicalIP(ip)
	validPeersConnected[trustIP] = common.ConnectionMaxTries
	nodePeersConnected[trustIP] = common.ConnectionMaxTries
}

// IsTransportConnected reports whether any connection on topic terminates at
// the given transport IP. Map keys may be virtual peer handles, so a plain map
// lookup by IP misses them; peer discovery uses this to decide whether a
// learned address still needs dialing.
func IsTransportConnected(topic [2]byte, ip [4]byte) bool {
	PeersMutex.RLock()
	defer PeersMutex.RUnlock()
	for key := range tcpConnections[topic] {
		if key == ip || canonicalIP(key) == ip {
			return true
		}
	}
	return false
}

func GetPeersConnected(topic [2]byte) map[[6]byte][2]byte {
	PeersMutex.RLock()
	defer PeersMutex.RUnlock()

	copyOfPeers := make(map[[6]byte][2]byte, len(peersConnected))
	for key, value := range peersConnected {
		if value == topic {
			copyOfPeers[key] = value
		}
	}

	return copyOfPeers
}

func GetIPsConnected() [][]byte {
	if PeersMutex.TryLock() {
		defer PeersMutex.Unlock()
		// Only return IPs that have at least one active TCP connection
		uniqueIPs := make(map[[4]byte]struct{})
		for _, connections := range tcpConnections {
			for ip := range connections {
				// Map keys may be virtual peer handles; peer discovery must
				// advertise DIALABLE transport addresses.
				if IsPeerHandle(ip) {
					real, ok := RealIPForHandle(ip)
					if !ok {
						continue
					}
					ip = real
				}
				// Never advertise our own addresses. Loopback in particular is
				// meaningless to anyone else: a peer that learns 127.0.0.1 from us
				// dials its OWN listener, ends up exchanging 'hi' with itself and
				// then treats its own height as a peer's.
				if IsSelfIP(ip) {
					continue
				}
				uniqueIPs[ip] = struct{}{}
			}
		}
		var ips [][]byte
		for ip := range uniqueIPs {
			ips = append(ips, ip[:])
		}
		PeersCount = len(ips)
		// return one random peer only
		if PeersCount > 0 {
			rn := rand.Intn(PeersCount)
			return [][]byte{ips[rn]}
		} else {
			return [][]byte{}
		}
	}
	return [][]byte{}
}

// inboundCapReached reports whether the number of concurrent inbound connections
// already registered for topic has reached MaxInboundConnectionsPerTopic. NP-H2.
func inboundCapReached(topic [2]byte) bool {
	PeersMutex.RLock()
	defer PeersMutex.RUnlock()
	return len(tcpConnections[topic]) >= common.MaxInboundConnectionsPerTopic
}

func GetPeersCount() int {
	PeersMutex.RLock()
	defer PeersMutex.RUnlock()
	uniqueIPs := make(map[[4]byte]struct{})
	for _, connections := range tcpConnections {
		for ip := range connections {
			if !IsSelfIP(ip) {
				uniqueIPs[ip] = struct{}{}
			}
		}
	}
	return len(uniqueIPs)
}

// CountPeersOnTopic returns how many distinct remote peers we hold a connection
// to on topic. The self-connection is not counted: it can only echo our own
// messages back, so a node whose only "peer" is itself has nobody to sync from
// and must keep re-dialling its bootstrap peers.
func CountPeersOnTopic(topic [2]byte) int {
	PeersMutex.RLock()
	defer PeersMutex.RUnlock()
	n := 0
	for ip := range tcpConnections[topic] {
		if !IsSelfIP(ip) {
			n++
		}
	}
	return n
}

func LookUpForNewPeersToConnect(chanPeer chan []byte) {
	for {
		var newPeers [][]byte

		PeersMutex.Lock()
		for topicip, topic := range peersConnected {
			_, ok := oldPeers[topicip]
			if ok == false {
				oldPeers[topicip] = topic
				peerCopy := make([]byte, len(topicip))
				copy(peerCopy, topicip[:])
				newPeers = append(newPeers, peerCopy)
			}
		}
		for topicip := range oldPeers {
			_, ok := peersConnected[topicip]
			if ok == false {
				delete(oldPeers, topicip)
			}
		}
		PeersMutex.Unlock()

		// Send notifications outside the lock to avoid blocking LoopSend
		for _, peer := range newPeers {
			chanPeer <- peer
		}

		time.Sleep(time.Second * 1)
	}
}
