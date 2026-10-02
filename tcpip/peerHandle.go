package tcpip

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

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
//
// Handles are never shared (S1-06). The 16-bit counter used to wrap after
// 65 536 nodeIDs - cheap to mint - and hand a live handle to a new peer,
// redirecting the honest peer's bans, limits and dials to the attacker. Now a
// handle is reused only after it has been evicted; one transport address
// holds at most maxHandlesPerIP of them (its oldest is evicted first), and
// only if the whole space is in use is the globally least recently used one
// evicted.
var (
	handleMutex    sync.Mutex
	handleByNodeID        = map[[common.AddressLength]byte][4]byte{}
	realIPByHandle        = map[[4]byte][4]byte{}
	nodeIDByHandle        = map[[4]byte]common.Address{}
	handleLastUse         = map[[4]byte]int64{}
	handlesByIP           = map[[4]byte]map[[4]byte]struct{}{}
	handleUseClock int64
	nextHandle     uint16 = 1
	// handleSpace is the number of usable handles: 10.254.0.1 - 10.254.255.254.
	handleSpace = 65534
)

// maxHandlesPerIP bounds the nodeIDs one transport address can hold handles
// for: well above the inbound connections it may keep (4 per topic, S1-04).
const maxHandlesPerIP = 32

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
	handleUseClock++
	if h, ok := handleByNodeID[key]; ok {
		setHandleIPLocked(h, realIP)
		handleLastUse[h] = handleUseClock
		return h
	}
	if len(handlesByIP[realIP]) >= maxHandlesPerIP {
		evictHandleLocked(oldestHandleLocked(handlesByIP[realIP]))
	}
	h, ok := freeHandleLocked()
	if !ok {
		all := make(map[[4]byte]struct{}, len(nodeIDByHandle))
		for k := range nodeIDByHandle {
			all[k] = struct{}{}
		}
		evictHandleLocked(oldestHandleLocked(all))
		h, _ = freeHandleLocked()
	}
	handleByNodeID[key] = h
	nodeIDByHandle[h] = nodeID
	setHandleIPLocked(h, realIP)
	handleLastUse[h] = handleUseClock
	logger.GetLogger().Printf("peer handle %v allocated for nodeID %x (transport %v)", h, nodeID.GetBytes()[:6], realIP)
	return h
}

func setHandleIPLocked(h, realIP [4]byte) {
	if old, ok := realIPByHandle[h]; ok && old != realIP {
		delete(handlesByIP[old], h)
		if len(handlesByIP[old]) == 0 {
			delete(handlesByIP, old)
		}
	}
	realIPByHandle[h] = realIP
	if handlesByIP[realIP] == nil {
		handlesByIP[realIP] = map[[4]byte]struct{}{}
	}
	handlesByIP[realIP][h] = struct{}{}
}

// freeHandleLocked returns the next handle not currently assigned.
func freeHandleLocked() ([4]byte, bool) {
	if len(nodeIDByHandle) >= handleSpace {
		return [4]byte{}, false
	}
	for i := 0; i <= handleSpace; i++ {
		n := nextHandle
		nextHandle++
		if int(nextHandle) > handleSpace {
			nextHandle = 1
		}
		if n == 0 || int(n) > handleSpace {
			continue
		}
		h := [4]byte{10, 254, byte(n >> 8), byte(n)}
		if _, used := nodeIDByHandle[h]; !used {
			return h, true
		}
	}
	return [4]byte{}, false
}

func oldestHandleLocked(set map[[4]byte]struct{}) [4]byte {
	var oldest [4]byte
	best := int64(-1)
	for h := range set {
		if t := handleLastUse[h]; best < 0 || t < best {
			oldest, best = h, t
		}
	}
	return oldest
}

func evictHandleLocked(h [4]byte) {
	id, ok := nodeIDByHandle[h]
	if !ok {
		return
	}
	var key [common.AddressLength]byte
	copy(key[:], id.GetBytes())
	delete(handleByNodeID, key)
	delete(nodeIDByHandle, h)
	delete(handleLastUse, h)
	if ip, ok := realIPByHandle[h]; ok {
		delete(handlesByIP[ip], h)
		if len(handlesByIP[ip]) == 0 {
			delete(handlesByIP, ip)
		}
	}
	delete(realIPByHandle, h)
	logger.GetLogger().Printf("peer handle %v evicted (nodeID %x)", h, id.GetBytes()[:6])
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

// Wire framing: MessageInitialization || uint32 big-endian body length || body,
// back to back on the stream.
//
// Frames are delimited by their length, never by a marker searched in the
// data (S1-01). Bodies are raw binary carrying sender-chosen bytes - OptData,
// contract code - so the old "<-END->" delimiter could be planted inside a
// transaction: every node relaying it had its messages cut in two and was
// penalised for the "violation", while the author went unpunished.
const frameHeaderLen = 8

func encodeFrame(body []byte) []byte {
	f := make([]byte, frameHeaderLen, frameHeaderLen+len(body))
	copy(f, common.MessageInitialization[:])
	binary.BigEndian.PutUint32(f[4:], uint32(len(body)))
	return append(f, body...)
}

// frameAssembler reassembles frames for one connection. Frames split across
// reads and several frames in one read are both handled.
type frameAssembler struct {
	topic [2]byte
	buf   []byte
	// skip counts body bytes of an over-long frame still to be dropped: they
	// are counted off, never buffered, so a declared length cannot make us
	// allocate.
	skip int64
	// broken is set by a wrong initialization marker. A length-framed stream
	// cannot be resynchronised after that, so all further input is dropped and
	// reported until the connection goes away.
	broken bool
}

// push consumes one read chunk and returns every complete message payload,
// plus whether a protocol violation was seen (over-long or empty frame, bad
// initialization marker, or input on a broken stream).
func (fa *frameAssembler) push(r []byte) (payloads [][]byte, violation bool) {
	if fa.broken {
		return nil, true
	}
	if fa.skip > 0 {
		n := min(fa.skip, int64(len(r)))
		fa.skip -= n
		r = r[n:]
	}
	fa.buf = append(fa.buf, r...)
	for len(fa.buf) >= frameHeaderLen {
		if !bytes.Equal(fa.buf[:4], common.MessageInitialization[:]) {
			logger.GetLogger().Println("wrong MessageInitialization", fa.buf[:4], "should be", common.MessageInitialization[:])
			fa.broken = true
			fa.buf = nil
			return payloads, true
		}
		size := int64(binary.BigEndian.Uint32(fa.buf[4:frameHeaderLen]))
		if size > int64(MaxMessageSizeForTopic(fa.topic)) {
			logger.GetLogger().Printf("error: too long message received on topic %c%c: %d bytes, cap is %d",
				fa.topic[0], fa.topic[1], size, MaxMessageSizeForTopic(fa.topic))
			violation = true
			rest := fa.buf[frameHeaderLen:]
			n := min(size, int64(len(rest)))
			fa.skip = size - n
			fa.buf = append([]byte(nil), rest[n:]...)
			continue
		}
		if size == 0 {
			violation = true
			fa.buf = fa.buf[frameHeaderLen:]
			continue
		}
		if int64(len(fa.buf)) < frameHeaderLen+size {
			break
		}
		end := frameHeaderLen + size
		payloads = append(payloads, fa.buf[frameHeaderLen:end:end])
		fa.buf = fa.buf[end:]
	}
	// Detach the remainder: returned payloads alias the old backing array.
	fa.buf = append([]byte(nil), fa.buf...)
	return payloads, violation
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
			ban := ReduceTrustRegisterPeer(realIP)
			PeersMutex.Unlock()
			if ban {
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
				ban := ReduceTrustRegisterPeer(realIP)
				PeersMutex.Unlock()
				if ban {
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
