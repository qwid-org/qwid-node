package tcpip

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"
)

var bannedIP map[[4]byte]int64
var bannedIPMutex sync.RWMutex
var whiteListIPs map[[4]byte]bool

func init() {
	bannedIP = map[[4]byte]int64{}
	whiteListIPs = map[[4]byte]bool{}
}

// NP-C1: whiteListIPs is guarded by bannedIPMutex (the same lock as bannedIP),
// since the two are always consulted together.
func AddWhiteListIPs(ip [4]byte) {
	bannedIPMutex.Lock()
	defer bannedIPMutex.Unlock()
	whiteListIPs[ip] = true
}

// isWhitelisted reports whether ip is whitelisted, taking the read lock.
func isWhitelisted(ip [4]byte) bool {
	bannedIPMutex.RLock()
	defer bannedIPMutex.RUnlock()
	return whiteListIPs[ip]
}

func IsIPBanned(ip [4]byte) bool {
	bannedIPMutex.RLock()
	defer bannedIPMutex.RUnlock()
	if whiteListIPs[ip] {
		return false
	}
	if hbanned, ok := bannedIP[ip]; ok {
		if hbanned > common.GetCurrentTimeStampInSecond() {
			return true
		}
	}
	return false
}

func BanIP(ip [4]byte) {
	// internal IP should not be banned || bytes.Equal(ip[:2], InternalIP[:2])
	if isWhitelisted(ip) {
		return
	}
	bannedIPMutex.Lock()
	logger.GetLogger().Println("BANNING ", ip)
	bannedIP[ip] = common.GetCurrentTimeStampInSecond() + common.BannedTimeSeconds
	bannedIPMutex.Unlock()
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
