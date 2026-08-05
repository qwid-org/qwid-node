package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wonabru/qwid-node/logger"
	nonceService "github.com/wonabru/qwid-node/services/nonceService"
	syncServices "github.com/wonabru/qwid-node/services/syncService"
	"github.com/wonabru/qwid-node/services/transactionServices"
	"github.com/wonabru/qwid-node/tcpip"
)

// bootstrapRetryInterval is how often the node checks whether it still has a way
// into the network.
const bootstrapRetryInterval = 15 * time.Second

// parsePeerIPs extracts bootstrap peer addresses from the command line. Flags
// (anything starting with "-") are skipped; every remaining argument may hold one
// address or a comma-separated list, so both of these work:
//
//	mining 1.2.3.4
//	mining 1.2.3.4,5.6.7.8 9.10.11.12
//
// An unparsable address is an error rather than a silent skip: a typo in the only
// way back into the network should not look like success.
func parsePeerIPs(args []string) ([][4]byte, error) {
	var out [][4]byte
	seen := map[[4]byte]bool{}

	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		for _, field := range strings.Split(arg, ",") {
			field = strings.TrimSpace(field)
			if field == "" {
				continue
			}
			ip, err := parseIPv4(field)
			if err != nil {
				return nil, err
			}
			if seen[ip] {
				continue
			}
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out, nil
}

func parseIPv4(s string) ([4]byte, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return [4]byte{}, fmt.Errorf("nieprawidłowy adres IP %q: oczekiwano czterech części", s)
	}
	var ip [4]byte
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return [4]byte{}, fmt.Errorf("nieprawidłowa część adresu IP %q w %q", p, s)
		}
		ip[i] = byte(n)
	}
	return ip, nil
}

// dialer serializes redial attempts so a peer that is slow or unreachable does
// not accumulate one blocked goroutine per retry interval. Each
// StartSubscribing* call runs until its connection ends, so without this a peer
// that never answers would leak goroutines for as long as the node runs.
type dialer struct {
	mu       sync.Mutex
	inFlight map[string]bool
}

func newDialer() *dialer {
	return &dialer{inFlight: map[string]bool{}}
}

// run starts fn in the background unless a call with the same key is still
// running. Reports whether it started one.
func (d *dialer) run(key string, fn func()) bool {
	d.mu.Lock()
	if d.inFlight[key] {
		d.mu.Unlock()
		return false
	}
	d.inFlight[key] = true
	d.mu.Unlock()

	go func() {
		defer func() {
			d.mu.Lock()
			delete(d.inFlight, key)
			d.mu.Unlock()
		}()
		fn()
	}()
	return true
}

// connectToPeer opens the nonce, sync and transaction subscriptions to one peer.
func (d *dialer) connectToPeer(ip [4]byte) {
	if tcpip.IsIPBanned(ip) {
		logger.GetLogger().Printf("bootstrap peer %v is banned, skipping", ip)
		return
	}
	d.run(fmt.Sprintf("N%v", ip), func() { nonceService.StartSubscribingNonceMsg(ip) })
	d.run(fmt.Sprintf("B%v", ip), func() { syncServices.StartSubscribingSyncMsg(ip) })
	d.run(fmt.Sprintf("T%v", ip), func() { transactionServices.StartSubscribingTransactionMsg(ip) })
}

// needsBootstrap reports whether the node has lost its way into the network.
// Peer discovery travels inside 'hi' messages, which need a live connection to
// arrive — so once every connection drops, nothing reconnects on its own and the
// command-line peers are the only route back.
func needsBootstrap() bool {
	return tcpip.GetPeersCount() == 0 || len(tcpip.GetPeersConnected(tcpip.SyncTopic)) == 0
}

// keepBootstrapPeersConnected re-dials the command-line peers whenever the node
// has no usable connection left. It never gives up: a node that is down for an
// hour must rejoin by itself when the link comes back.
func keepBootstrapPeersConnected(peers [][4]byte, d *dialer) {
	if len(peers) == 0 {
		logger.GetLogger().Println("no bootstrap peers given on the command line - " +
			"this node cannot rejoin the network on its own if every connection drops")
		return
	}
	for {
		time.Sleep(bootstrapRetryInterval)
		if !needsBootstrap() {
			continue
		}
		logger.GetLogger().Printf("no usable peer connection - re-dialling %d bootstrap peer(s) from the command line", len(peers))
		for _, ip := range peers {
			d.connectToPeer(ip)
		}
	}
}
