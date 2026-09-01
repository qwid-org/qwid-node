package tcpip

import (
	"time"
	"bytes"
	"fmt"
	"net"
	"sync"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

// Peer handles: a stable virtual [4]byte address per authenticated nodeID.
//
// Every connection map, height claim, and message tag in this codebase is
// keyed by a 4-byte address. That key used to be the transport IP, which
// collapses two nodes behind one NAT into a single peer: their accepted
// connections evict each other on the shared (topic, ip) map slot, their
// height claims overwrite each other, and the node that cannot be dialed
// back is effectively mute. A handle is allocated from the non-routable
// 10.254.0.0/16 range the first time a nodeID completes the handshake and is
// stable for the life of the process, so two NAT-shared nodes become two
// distinct peers everywhere - claims, quorums, connection maps - without
// changing any handler signature or wire format.
//
// The real transport IP is kept per handle for the few places that genuinely
// need it: dialing, banning, and per-source rate limiting.
var (
	handleMutex    sync.Mutex
	handleByNodeID        = map[[common.AddressLength]byte][4]byte{}
	realIPByHandle        = map[[4]byte][4]byte{}
	nodeIDByHandle        = map[[4]byte]common.Address{}
	nextHandle     uint16 = 1
)

// IsPeerHandle reports whether a 4-byte address is a virtual peer handle
// rather than a transport IP.
func IsPeerHandle(ip [4]byte) bool {
	return ip[0] == 10 && ip[1] == 254
}

// HandleForPeer returns the stable handle for an authenticated peer nodeID,
// allocating one on first sight, and records the transport IP currently behind
// it (a peer may reconnect from a different address; the latest one wins).
func HandleForPeer(nodeID common.Address, realIP [4]byte) [4]byte {
	var key [common.AddressLength]byte
	copy(key[:], nodeID.GetBytes())
	handleMutex.Lock()
	defer handleMutex.Unlock()
	if h, ok := handleByNodeID[key]; ok {
		realIPByHandle[h] = realIP
		return h
	}
	h := [4]byte{10, 254, byte(nextHandle >> 8), byte(nextHandle)}
	nextHandle++
	handleByNodeID[key] = h
	realIPByHandle[h] = realIP
	nodeIDByHandle[h] = nodeID
	logger.GetLogger().Printf("peer handle %v allocated for nodeID %x (transport %v)", h, nodeID.GetBytes()[:6], realIP)
	return h
}

// RealIPForHandle translates a handle back to the transport IP last seen
// behind it. For a non-handle address it returns the address itself.
func RealIPForHandle(ip [4]byte) ([4]byte, bool) {
	if !IsPeerHandle(ip) {
		return ip, true
	}
	handleMutex.Lock()
	defer handleMutex.Unlock()
	real, ok := realIPByHandle[ip]
	return real, ok
}

// canonicalIP maps a handle to its transport IP for the subsystems that work
// per SOURCE rather than per node: dialing, bans, trust and rate limits. A
// handle with no known transport (should not happen) maps to itself, which is
// harmless - a 10.254/16 address is neither dialable nor shared.
func canonicalIP(ip [4]byte) [4]byte {
	if real, ok := RealIPForHandle(ip); ok {
		return real
	}
	return ip
}

// selfNodeID is the wallet identity handshakes present; a peer whose nodeID
// equals ours is our own self-connection and never gets a handle.
func selfNodeID() (common.Address, bool) {
	id, err := activeWalletIdentity()
	if err != nil {
		return common.Address{}, false
	}
	return id.Address, true
}

// connKeyFor decides the map/tag key for an authenticated connection: the
// peer's handle, except for our own self-connection, which keeps the transport
// address so the established self-connection semantics (IsSelfIP, the shared
// dial/accept ends of one loopback link) stay untouched.
func connKeyFor(peerID common.Address, realIP [4]byte) [4]byte {
	if self, ok := selfNodeID(); ok && bytes.Equal(self.GetBytes(), peerID.GetBytes()) {
		return realIP
	}
	return HandleForPeer(peerID, realIP)
}

// PeerLabel renders a peer address for logs. A virtual handle becomes
// "peer-N(nodeIDprefix@transportIP)" so an operator never has to guess which
// node "[10 254 0 1]" is — handle numbering is LOCAL to each node (allocated
// in first-seen order), so the same virtual address means different peers in
// different nodes' logs. A plain transport IP renders as before.
func PeerLabel(ip [4]byte) string {
	if !IsPeerHandle(ip) {
		return fmt.Sprintf("%v", ip)
	}
	handleMutex.Lock()
	real := realIPByHandle[ip]
	id, okID := nodeIDByHandle[ip]
	handleMutex.Unlock()
	n := int(ip[2])<<8 | int(ip[3])
	if !okID {
		return fmt.Sprintf("peer-%d(?)", n)
	}
	return fmt.Sprintf("peer-%d(%x@%d.%d.%d.%d)", n, id.GetBytes()[:4], real[0], real[1], real[2], real[3])
}

// Topic handlers: the services' OnMessage entry points, registered so the
// accepted-connection receive loops (which live in tcpip and cannot import the
// services) can dispatch inbound messages.
var (
	topicHandlerMutex sync.RWMutex
	topicHandlers     = map[[2]byte]func([4]byte, []byte){}
)

// RegisterTopicHandler installs the message handler for a topic. Called once
// per topic by the owning service at startup, alongside StartNewListener.
func RegisterTopicHandler(topic [2]byte, handler func(addr [4]byte, m []byte)) {
	topicHandlerMutex.Lock()
	topicHandlers[topic] = handler
	topicHandlerMutex.Unlock()
}

func topicHandler(topic [2]byte) func([4]byte, []byte) {
	topicHandlerMutex.RLock()
	defer topicHandlerMutex.RUnlock()
	return topicHandlers[topic]
}

// frameAssembler reassembles the wire framing for one connection: messages
// are MessageInitialization || body || "<-END->", back to back on the stream.
//
// The delimiter is searched INSIDE the accumulated buffer, not just at read
// boundaries. The old framing only recognised a message when "<-END->"
// happened to fall exactly at the end of a read chunk - true by luck on a
// quiet link (gaps between messages align the reads) and almost never true on
// a busy one, where messages queue back to back: frames got glued, the parser
// took the first message of the glued blob and the rest was silently lost.
// Under sync load that surfaced as "the peer sends many bx, we receive two".
type frameAssembler struct {
	topic      [2]byte
	buf        []byte
	scanned    int // prefix of buf already searched for the delimiter
	discarding bool
}

var frameEnd = []byte("<-END->")

// push consumes one read chunk and returns every complete message payload in
// the buffer (init marker stripped), plus whether a protocol violation was
// seen (over-long frame or bad initialization marker).
func (fa *frameAssembler) push(r []byte) (payloads [][]byte, violation bool) {
	fa.buf = append(fa.buf, r...)
	for {
		// Resume the search where it stopped, backed off so a delimiter split
		// across two pushes is still found.
		start := fa.scanned - (len(frameEnd) - 1)
		if start < 0 {
			start = 0
		}
		idx := bytes.Index(fa.buf[start:], frameEnd)
		if idx < 0 {
			fa.scanned = len(fa.buf)
			if !fa.discarding && int32(len(fa.buf)) > MaxMessageSizeForTopic(fa.topic) {
				logger.GetLogger().Printf("error: too long message received on topic %c%c: %d bytes, cap is %d",
					fa.topic[0], fa.topic[1], len(fa.buf), MaxMessageSizeForTopic(fa.topic))
				violation = true
				fa.discarding = true
				fa.buf = nil
				fa.scanned = 0
			}
			return payloads, violation
		}
		idx += start
		frame := fa.buf[:idx]
		fa.buf = append([]byte(nil), fa.buf[idx+len(frameEnd):]...)
		fa.scanned = 0
		if fa.discarding {
			// Tail of the over-long frame ended; resume normal framing.
			fa.discarding = false
			logger.GetLogger().Printf("resynchronised on topic %c%c after discarding an over-long message", fa.topic[0], fa.topic[1])
			continue
		}
		if int32(len(frame)) > MaxMessageSizeForTopic(fa.topic) {
			logger.GetLogger().Printf("error: too long message received on topic %c%c: %d bytes, cap is %d",
				fa.topic[0], fa.topic[1], len(frame), MaxMessageSizeForTopic(fa.topic))
			violation = true
			continue
		}
		if len(frame) <= 4 || !bytes.Equal(frame[:4], common.MessageInitialization[:]) {
			logger.GetLogger().Println("wrong MessageInitialization", frame[:min(4, len(frame))], "should be", common.MessageInitialization[:])
			violation = true
			continue
		}
		payloads = append(payloads, frame[4:])
	}
}

// acceptedReceiveLoop reads an ACCEPTED (inbound) connection and dispatches
// its messages, tagged with the peer's handle.
//
// Accepted connections used to be write-only: each side read only the links it
// dialed itself. Between two publicly-routable nodes that works (two
// unidirectional links), but a peer behind NAT cannot be dialed back - its
// only link is the one it dialed to us, it sends on that link, and nothing on
// our side ever read it, so the peer was mute. This loop closes that gap.
//
// Silence here is LEGITIMATE and never fatal: for a publicly-routable peer the
// accepted link is our send-leg (the peer reads it and writes nothing), so a
// quiet-death timeout would tear down our own send path. The loop exits only
// when the connection actually errors or closes; TCP keepalive plus LoopSend
// write errors handle genuinely dead sockets.
func acceptedReceiveLoop(topic [2]byte, key [4]byte, realIP [4]byte, conn net.Conn) {
	handler := topicHandler(topic)
	fa := frameAssembler{topic: topic}
	// lastNote throttles the shared inbound-activity record to ~1/s; this loop
	// sees one call per KB fragment. Recorded under KEY (the handle), because
	// that is the address the missing-tx watchdog knows the peer by — and this
	// loop is the ONLY path a NAT peer's bx answers arrive on, so without this
	// the watchdog is blind to their in-flight transfers and recycles them.
	lastNote := time.Time{}
	for {
		select {
		case <-Quit:
			return
		default:
		}
		r := Receive(topic, conn)
		if r == nil {
			continue
		}
		if time.Since(lastNote) >= time.Second {
			NoteInbound(topic, key)
			lastNote = time.Now()
		}
		if bytes.Equal(r, []byte("<-CLS->")) || bytes.Equal(r, []byte("<-ERR->")) {
			// The peer closed or the stream broke; unregister whatever is still
			// stored under this key so LoopSend stops targeting a dead socket.
			PeersMutex.Lock()
			if stored, ok := acceptedConnections[topic][key]; ok && stored == conn {
				CloseAndRemoveConnection(conn)
			}
			PeersMutex.Unlock()
			return
		}
		payloads, violation := fa.push(r)
		if violation {
			PeersMutex.Lock()
			ReduceTrustRegisterPeer(realIP)
			trust, ok := validPeersConnected[realIP]
			PeersMutex.Unlock()
			if ok && trust <= 0 {
				BanIP(realIP)
				conn.Close()
				return
			}
			continue
		}
		for _, m := range payloads {
			var head [2]byte
			if len(m) >= 2 {
				copy(head[:], m[:2])
			}
			// Rate limiting stays per transport source - that is what the
			// limiter defends against - while dispatch is tagged per node.
			if !AllowMessageFromIPForHead(realIP, head) {
				logger.GetLogger().Printf("message rate limit exceeded for %v (head %q)", realIP, string(head[:]))
				PeersMutex.Lock()
				ReduceTrustRegisterPeer(realIP)
				trust, ok := validPeersConnected[realIP]
				PeersMutex.Unlock()
				if ok && trust <= 0 {
					BanIP(realIP)
					conn.Close()
					return
				}
				continue
			}
			if handler != nil {
				handler(key, m)
			}
		}
	}
}
