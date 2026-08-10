package tcpip

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

var bannedIP map[[4]byte]int64
var bannedIPMutex sync.RWMutex
var whiteListIPs map[[4]byte]bool
var blackListIPs map[[4]byte]bool

func init() {
	bannedIP = map[[4]byte]int64{}
	whiteListIPs = map[[4]byte]bool{}
	blackListIPs = map[[4]byte]bool{}
}

// NP-C1: whiteListIPs is guarded by bannedIPMutex (the same lock as bannedIP),
// since the two are always consulted together.
func AddWhiteListIPs(ip [4]byte) {
	bannedIPMutex.Lock()
	defer bannedIPMutex.Unlock()
	whiteListIPs[ip] = true
}

// AddBlackListIPs permanently bans ip (configured via BLACKLIST_IP in .env).
// A blacklisted IP is rejected on inbound accept, outbound dial and peer
// discovery, never expires, and takes precedence over the whitelist.
func AddBlackListIPs(ip [4]byte) {
	bannedIPMutex.Lock()
	defer bannedIPMutex.Unlock()
	blackListIPs[ip] = true
}

// isWhitelisted reports whether ip is whitelisted, taking the read lock.
func isWhitelisted(ip [4]byte) bool {
	bannedIPMutex.RLock()
	defer bannedIPMutex.RUnlock()
	return whiteListIPs[ip]
}

func IsIPBanned(ip [4]byte) bool {
	bannedIPMutex.Lock()
	defer bannedIPMutex.Unlock()
	if blackListIPs[ip] {
		return true
	}
	if whiteListIPs[ip] {
		return false
	}
	if hbanned, ok := bannedIP[ip]; ok {
		if hbanned > common.GetCurrentTimeStampInSecond() {
			return true
		}
		delete(bannedIP, ip) // NP-M1: evict the expired ban so the map does not grow unboundedly
	}
	return false
}

func BanIP(ip [4]byte) {
	// internal IP should not be banned || bytes.Equal(ip[:2], InternalIP[:2])
	if isWhitelisted(ip) {
		return
	}
	bannedIPMutex.Lock()
	// NP-M1: opportunistically evict already-expired bans so the map self-trims
	// even for IPs that are never re-checked.
	nowTs := common.GetCurrentTimeStampInSecond()
	for k, exp := range bannedIP {
		if exp <= nowTs {
			delete(bannedIP, k)
		}
	}
	logger.GetLogger().Println("BANNING ", ip)
	bannedIP[ip] = common.GetCurrentTimeStampInSecond() + common.BannedTimeSeconds
	bannedIPMutex.Unlock()
	pruneRateLimits(ip)
	if PeersMutex.TryLock() {
		defer PeersMutex.Unlock()
		if _, ok := validPeersConnected[ip]; ok {
			delete(validPeersConnected, ip)
		}
		if _, ok := nodePeersConnected[ip]; ok {
			delete(nodePeersConnected, ip)
		}
		tcpConns := tcpConnections[NonceTopic]
		tcpConn, ok := tcpConns[ip]
		if ok {
			CloseAndRemoveConnection(tcpConn)
			return
		}
		tcpConns = tcpConnections[TransactionTopic]
		tcpConn, ok = tcpConns[ip]
		if ok {
			CloseAndRemoveConnection(tcpConn)
			return
		}
		tcpConns = tcpConnections[SyncTopic]
		tcpConn, ok = tcpConns[ip]
		if ok {
			CloseAndRemoveConnection(tcpConn)
			return
		}
	}
}

func ReduceAndCheckIfBanIP(ip [4]byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	PeersMutex.Lock()
	defer PeersMutex.Unlock()
	select {
	case <-ctx.Done():
		// Handle timeout
		logger.GetLogger().Println("ReduceAndCheckIfBanIP: timeout in sending")

	default:
		if _, ok := validPeersConnected[ip]; ok {
			ReduceTrustRegisterPeer(ip)
		}
		if _, ok := validPeersConnected[ip]; !ok {
			logger.GetLogger().Println("not trusted ip", ip)
			BanIP(ip)
		}
	}
}

// GetConnectedPeersInfo returns info about all connected peers
func GetConnectedPeersInfo() []map[string]interface{} {
	PeersMutex.RLock()
	defer PeersMutex.RUnlock()

	peers := []map[string]interface{}{}
	seen := map[[4]byte]bool{}

	for ip, trust := range nodePeersConnected {
		if bytes.Equal(ip[:], MyIP[:]) {
			continue
		}
		if seen[ip] {
			continue
		}
		seen[ip] = true

		validTrust := 0
		if t, ok := validPeersConnected[ip]; ok {
			validTrust = t
		}

		// Check which topics this peer is connected on
		topics := []string{}
		for topic, conns := range tcpConnections {
			if _, ok := conns[ip]; ok {
				switch topic {
				case TransactionTopic:
					topics = append(topics, "transactions")
				case NonceTopic:
					topics = append(topics, "nonce")
				case SelfNonceTopic:
					topics = append(topics, "self-nonce")
				case SyncTopic:
					topics = append(topics, "sync")
				}
			}
		}

		peers = append(peers, map[string]interface{}{
			"ip":         formatIP(ip),
			"trustLevel": trust,
			"validTrust": validTrust,
			"isNodePeer": trust > 1,
			"topics":     topics,
		})
	}

	return peers
}

// GetBannedPeersInfo returns info about all banned peers
func GetBannedPeersInfo() []map[string]interface{} {
	bannedIPMutex.RLock()
	defer bannedIPMutex.RUnlock()

	now := common.GetCurrentTimeStampInSecond()
	banned := []map[string]interface{}{}

	for ip, expiration := range bannedIP {
		if expiration > now {
			banned = append(banned, map[string]interface{}{
				"ip":            formatIP(ip),
				"banExpiration": expiration,
				"remainingTime": expiration - now,
			})
		}
	}

	return banned
}

// GetWhitelistedIPs returns list of whitelisted IPs
func GetWhitelistedIPs() []string {
	bannedIPMutex.RLock()
	defer bannedIPMutex.RUnlock()
	ips := []string{}
	for ip := range whiteListIPs {
		ips = append(ips, formatIP(ip))
	}
	return ips
}

func formatIP(ip [4]byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

// MaxMessageSizeForTopic returns the per-topic inbound message-size cap in bytes,
// replacing the single global MaxMessageSizeBytes at the receive-loop check.
// Unknown topics get the tightest cap. Shrinks the buffering DoS surface for
// Nonce/SelfNonce/Sync/RPC. TransactionTopic keeps the full global cap because
// tx-gossip (up to MaxTransactionsPerBlock txs) and sync "bx" recovery (up to
// MaxNumberTransactionInChunk txs) are sent as un-chunked batches — a tighter
// cap would reject legitimate batches and get honest peers banned.
func MaxMessageSizeForTopic(topic [2]byte) int32 {
	switch topic {
	case NonceTopic, SelfNonceTopic:
		return common.MaxMsgSizeSmall
	case TransactionTopic:
		return common.MaxMessageSizeBytes
	case SyncTopic:
		return common.MaxMsgSizeSync
	case RPCTopic:
		return common.MaxMsgSizeRPC
	default:
		return common.MaxMsgSizeSmall
	}
}

type rateWindow struct {
	windowStart int64 // unix seconds
	count       int
}

var (
	msgRate       = map[[4]byte]*rateWindow{}
	msgRateMutex  sync.Mutex
	connRate      = map[[4]byte]*rateWindow{}
	connRateMutex sync.Mutex
)

// allowInWindow records one event at `now` and reports whether the running count
// stays within `limit` over a `windowSecs` sliding window (reset when the window
// elapses). Pure/deterministic given its inputs.
func allowInWindow(w *rateWindow, now int64, limit int, windowSecs int64) bool {
	if now-w.windowStart >= windowSecs {
		w.windowStart = now
		w.count = 0
	}
	w.count++
	return w.count <= limit
}

// AllowMessageFromIP reports whether ip may send another message now, throttling
// at MessageRateLimit per MessageRateWindowSeconds. Whitelisted IPs always pass
// and are not counted.
func AllowMessageFromIP(ip [4]byte) bool {
	if isWhitelisted(ip) {
		return true
	}
	now := common.GetCurrentTimeStampInSecond()
	msgRateMutex.Lock()
	defer msgRateMutex.Unlock()
	w, ok := msgRate[ip]
	if !ok {
		w = &rateWindow{windowStart: now}
		msgRate[ip] = w
	}
	return allowInWindow(w, now, common.MessageRateLimit, common.MessageRateWindowSeconds)
}

// AllowConnectionFromIP reports whether ip may make another connection attempt
// now, throttling at ConnectionRateLimit per ConnectionRateWindowSeconds.
// Whitelisted IPs always pass.
func AllowConnectionFromIP(ip [4]byte) bool {
	if isWhitelisted(ip) {
		return true
	}
	now := common.GetCurrentTimeStampInSecond()
	connRateMutex.Lock()
	defer connRateMutex.Unlock()
	w, ok := connRate[ip]
	if !ok {
		w = &rateWindow{windowStart: now}
		connRate[ip] = w
	}
	return allowInWindow(w, now, common.ConnectionRateLimit, common.ConnectionRateWindowSeconds)
}

// pruneRateLimits drops an IP's rate/reconnection state — called when it is banned,
// to bound long-run map growth.
func pruneRateLimits(ip [4]byte) {
	msgRateMutex.Lock()
	delete(msgRate, ip)
	msgRateMutex.Unlock()
	connRateMutex.Lock()
	delete(connRate, ip)
	connRateMutex.Unlock()
}
