package tcpip

import (
	"bytes"
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
	handleByNodeID = map[[common.AddressLength]byte][4]byte{}
	realIPByHandle = map[[4]byte][4]byte{}
	nodeIDByHandle = map[[4]byte]common.Address{}
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

// frameAssembler reassembles the wire framing (MessageInitialization header,
// "<-END->" trailer, fragmentation, over-long discard) for one connection.
// Mirrors the framing in StartNewConnection's receive loop.
type frameAssembler struct {
	topic      [2]byte
	buf        []byte
	discarding bool
}

// push consumes one read chunk and returns any complete message payloads
// (init marker stripped) plus whether the chunk was a protocol violation
// (over-long message or bad initialization marker).
func (fa *frameAssembler) push(r []byte) (payloads [][]byte, violation bool) {
	if fa.discarding {
		if len(r) >= 7 && bytes.Equal(r[len(r)-7:], []byte("<-END->")) {
			fa.discarding = false
			logger.GetLogger().Printf("resynchronised on topic %c%c after discarding an over-long message", fa.topic[0], fa.topic[1])
		}
		return nil, false
	}
	r = append(fa.buf, r...)
	if len(r) < 7 || !bytes.Equal(r[len(r)-7:], []byte("<-END->")) {
		fa.buf = r
	} else {
		fa.buf = nil
	}
	if int32(len(r)) > MaxMessageSizeForTopic(fa.topic) {
		logger.GetLogger().Printf("error: too long message received on topic %c%c: %d bytes, cap is %d",
			fa.topic[0], fa.topic[1], len(r), MaxMessageSizeForTopic(fa.topic))
		if len(r) < 7 || !bytes.Equal(r[len(r)-7:], []byte("<-END->")) {
			fa.discarding = true
		}
		fa.buf = nil
		return nil, true
	}
	if len(r) >= 7 && bytes.Equal(r[len(r)-7:], []byte("<-END->")) && len(r) > 4 {
		if !bytes.Equal(r[:4], common.MessageInitialization[:]) {
			logger.GetLogger().Println("wrong MessageInitialization", r[:4], "should be", common.MessageInitialization[:])
			return nil, true
		}
		return [][]byte{r[4:]}, false
	}
	return nil, false
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
