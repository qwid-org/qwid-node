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

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"
	"golang.org/x/exp/rand"
)

var (
	peersConnected      = map[[6]byte][2]byte{}
	validPeersConnected = map[[4]byte]int{}
	nodePeersConnected  = map[[4]byte]int{}
	oldPeers            = map[[6]byte][2]byte{}
	PeersCount          = 0
	waitChan            = make(chan []byte)
	tcpConnections      = make(map[[2]byte]map[[4]byte]*net.TCPConn)
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
		tcpConnections[k] = map[[4]byte]*net.TCPConn{}
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
	peerID, hsErr := HandshakeResponder(tcpConn, self)
	if hsErr != nil {
		logger.GetLogger().Println("inbound handshake failed:", hsErr)
		tcpConn.Close()
		PeersMutex.Lock()
		ReduceTrustRegisterPeer(ip)
		PeersMutex.Unlock()
		return nil, fmt.Errorf("inbound handshake failed: %w", hsErr)
	}
	storeVerifiedNodeID(topic, ip, peerID)

	publishAcceptedConn(topic, ip, tcpConn)
	tcpConn.SetKeepAlive(true)
	return tcpConn, nil
}

func Send(conn *net.TCPConn, message []byte) error {

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

// Receive reads data from the connection and handles errors
func Receive(topic [2]byte, conn *net.TCPConn) []byte {
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

func FullyDeleteConnection(tcpConn *net.TCPConn) {
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
func publishAcceptedConn(topic [2]byte, ip [4]byte, tcpConn *net.TCPConn) {
	var topicipBytes [6]byte
	copy(topicipBytes[:], append(topic[:], ip[:]...))

	PeersMutex.Lock()
	defer PeersMutex.Unlock()

	// Initialize the map for the topic if it doesn't exist
	if _, ok := tcpConnections[topic]; !ok {
		tcpConnections[topic] = make(map[[4]byte]*net.TCPConn)
	}

	// Check if we already have a connection for this peer
	if oldConn, ok := tcpConnections[topic][ip]; ok {
		// Close the old connection before replacing it, so the other node's
		// outbound receive loop gets a clean EOF instead of lingering and
		// triggering repeated reconnections.
		oldConn.Close()
	}

	// Register the accepted connection for sending
	tcpConnections[topic][ip] = tcpConn
	peersConnected[topicipBytes] = topic
	validPeersConnected[ip] = common.ConnectionMaxTries
	nodePeersConnected[ip] = common.ConnectionMaxTries
}

// RegisterPeer registers a new peer connection.
//
// NP-C3 note: this pre-handshake convenience wrapper (admit checks + immediate
// publish) is kept only for any external/test callers that don't need the
// handshake gate. The live inbound accept path in Accept() below does NOT call
// this — it calls admitPeer() and publishAcceptedConn() separately, with the
// peer-auth handshake running strictly in between, so a connection is never
// visible to LoopSend before it is authenticated.
func RegisterPeer(topic [2]byte, tcpConn *net.TCPConn) bool {
	ip, err := parsePeerIP(tcpConn)
	if err != nil {
		fmt.Println(err)
		return false
	}
	if !admitPeer(ip) {
		return false
	}
	publishAcceptedConn(topic, ip, tcpConn)
	return true
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
				if bytes.Equal(ip[:], MyIP[:]) {
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

func GetPeersCount() int {
	PeersMutex.RLock()
	defer PeersMutex.RUnlock()
	uniqueIPs := make(map[[4]byte]struct{})
	for _, connections := range tcpConnections {
		for ip := range connections {
			if !bytes.Equal(ip[:], MyIP[:]) {
				uniqueIPs[ip] = struct{}{}
			}
		}
	}
	return len(uniqueIPs)
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
