package syncServices

import (
	"bytes"
	"runtime/debug"
	"sync"
	"time"

	"github.com/wonabru/qwid-node/logger"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/blocks"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/message"
	"github.com/wonabru/qwid-node/services"
	nonceServices "github.com/wonabru/qwid-node/services/nonceService"
	"github.com/wonabru/qwid-node/services/transactionServices"
	"github.com/wonabru/qwid-node/statistics"
	"github.com/wonabru/qwid-node/tcpip"
	"github.com/wonabru/qwid-node/transactionsPool"
)

var err error

// clampHeaderSpan bounds [bHeight, eHeight] so eHeight-bHeight <= NumberOfHashesInBucket
// and bHeight <= eHeight, matching the legitimate sync batch size, so a malicious peer
// cannot request an enormous header range. NP-M13.
func clampHeaderSpan(bHeight, eHeight int64) (int64, int64) {
	if eHeight < bHeight {
		eHeight = bHeight
	}
	if eHeight-bHeight > common.NumberOfHashesInBucket {
		eHeight = bHeight + common.NumberOfHashesInBucket
	}
	return bHeight, eHeight
}

var (
	connectingPeers      = make(map[[6]byte]bool)
	connectingPeersMutex sync.Mutex
	syncProcessMutex     sync.Mutex
)

// peerHeightClaim tracks a peer's claimed height with timestamp
type peerHeightClaim struct {
	height    int64
	blockHash []byte
	timestamp time.Time
}

var (
	peerHeightClaims      = make(map[[4]byte]peerHeightClaim)
	peerHeightClaimsMutex sync.RWMutex
	// MaxHeightJumpWithoutConsensus - if a peer claims height more than this ahead,
	// require multiple peers to confirm before syncing
	MaxHeightJumpWithoutConsensus int64 = 4
	// MinPeersForLargeSync - minimum peers that must agree on height for large syncs.
	// NP-H13: must be >= 2 so a single malicious peer cannot drive a large sync to
	// a fabricated height.
	MinPeersForLargeSync = 2
	// ClaimExpiryDuration - how long before a height claim expires
	ClaimExpiryDuration = 30 * time.Second
	// SyncStallTimeout - how long the local height may stay put while syncing
	// before the sync is treated as stalled. A dropped connection can lose either
	// our "bt" request for a block's transactions or the peer's "bx" answer, and
	// nothing in the protocol retries on its own, so the node would wait forever.
	SyncStallTimeout = 45 * time.Second
	// SyncStallRewind - how many blocks to give back when a stall is detected.
	// Rewinding makes the next batch overlap what we already hold, which re-runs
	// the missing-transaction census and re-sends the request. Kept small: the
	// blocks are re-applied from the peer within a round or two.
	SyncStallRewind int64 = 2
)

// recordPeerHeightClaim stores a peer's height claim
func recordPeerHeightClaim(addr [4]byte, height int64, blockHash []byte) {
	peerHeightClaimsMutex.Lock()
	defer peerHeightClaimsMutex.Unlock()
	peerHeightClaims[addr] = peerHeightClaim{
		height:    height,
		blockHash: blockHash,
		timestamp: time.Now(),
	}
}

// shouldSyncToHeight determines if we should sync based on peer claims
// Returns true if sync should proceed, and the validated target height
func shouldSyncToHeight(claimedHeight int64, localHeight int64) (bool, int64) {
	peerHeightClaimsMutex.RLock()
	defer peerHeightClaimsMutex.RUnlock()

	heightDiff := claimedHeight - localHeight
	if heightDiff <= 0 {
		return false, localHeight
	}

	// For small height differences, trust single peer
	if heightDiff <= MaxHeightJumpWithoutConsensus {
		return true, claimedHeight
	}

	// For large height differences, require multiple peers to agree
	now := time.Now()
	peersAtOrAboveHeight := 0
	maxConfirmedHeight := localHeight

	for _, claim := range peerHeightClaims {
		// Skip expired claims
		if now.Sub(claim.timestamp) > ClaimExpiryDuration {
			continue
		}
		if claim.height >= claimedHeight {
			peersAtOrAboveHeight++
		}
		if claim.height > maxConfirmedHeight {
			maxConfirmedHeight = claim.height
		}
	}

	if peersAtOrAboveHeight >= MinPeersForLargeSync {
		logger.GetLogger().Printf("Large sync approved: %d peers confirm height >= %d", peersAtOrAboveHeight, claimedHeight)
		return true, claimedHeight
	}

	// Not enough peers confirm - only sync up to a safe limit. One batch worth of
	// blocks (NumberOfHashesInBucket, the span clampHeaderSpan already allows) so
	// a node that is tens of thousands of blocks behind a single peer still
	// catches up in reasonable time. This only rate-limits: every block is fully
	// verified regardless, so a larger step grants a malicious peer nothing.
	safeHeight := localHeight + common.NumberOfHashesInBucket
	if safeHeight < claimedHeight {
		logger.GetLogger().Printf("Large height claim %d not confirmed by enough peers (%d/%d), limiting to %d",
			claimedHeight, peersAtOrAboveHeight, MinPeersForLargeSync, safeHeight)
		return true, safeHeight
	}

	return true, claimedHeight
}

// networkHeight derives the height the network is at from the live peer height
// claims. With a single live peer we take its claim; with two or more we take
// the second highest, so one lying peer can neither stall our block production
// by claiming an impossible height nor pull the target down by claiming a low
// one. With no live claims we fall back to the HEIGHT_OF_NETWORK hint, which
// keeps a solo/genesis node producing.
func networkHeight() int64 {
	peerHeightClaimsMutex.RLock()
	defer peerHeightClaimsMutex.RUnlock()

	now := time.Now()
	best, second := int64(0), int64(0)
	live := 0
	for _, claim := range peerHeightClaims {
		if now.Sub(claim.timestamp) > ClaimExpiryDuration {
			continue
		}
		live++
		if claim.height > best {
			second = best
			best = claim.height
		} else if claim.height > second {
			second = claim.height
		}
	}
	switch {
	case live == 0:
		return common.CurrentHeightOfNetwork
	case live == 1:
		return best
	default:
		return second
	}
}

// requestHeadersFromPeersAhead asks every peer whose live claim is above height
// for the next batch, and reports how many requests went out and how many live
// claims exist.
//
// Rewinding on its own does not restart a stalled sync. A batch is requested in
// exactly one place — when WE receive a peer's 'hi' and see it is ahead of us
// (the "hi" case below). Our own 'hi' only announces our height; it asks for
// nothing. So if a peer's 'hi' stops reaching us, the node can rewind forever
// with nothing to import. This is the active push that does not wait for one.
func requestHeadersFromPeersAhead(height int64) (sent int, live int) {
	type target struct {
		addr   [4]byte
		height int64
	}
	targets := []target{}

	peerHeightClaimsMutex.RLock()
	now := time.Now()
	for addr, claim := range peerHeightClaims {
		if now.Sub(claim.timestamp) > ClaimExpiryDuration {
			continue
		}
		live++
		if claim.height > height {
			targets = append(targets, target{addr: addr, height: claim.height})
		}
	}
	peerHeightClaimsMutex.RUnlock()

	// shouldSyncToHeight takes the same lock, so it is called only after release.
	for _, t := range targets {
		ok, validated := shouldSyncToHeight(t.height, height)
		if !ok {
			continue
		}
		SendGetHeaders(t.addr, validated)
		sent++
	}
	return sent, live
}

// updateSyncTarget refreshes the network height used to decide whether this node
// is still behind and therefore must not produce blocks.
func updateSyncTarget() {
	nh := networkHeight()
	common.SetSyncTarget(nh)
	// HeightMax answers "how high is the network" for the stats/UI and for the
	// rewind-step heuristic. Feed it the consensus-filtered peer height, not the
	// throttled per-round sync target: the latter is only ever a batch ahead of
	// us, which made a node 100k blocks behind look all but synced.
	if nh > common.GetHeightMax() {
		common.SetHeightMax(nh)
	}
}

// cleanupExpiredClaims removes old height claims
func cleanupExpiredClaims() {
	peerHeightClaimsMutex.Lock()
	defer peerHeightClaimsMutex.Unlock()
	now := time.Now()
	for addr, claim := range peerHeightClaims {
		if now.Sub(claim.timestamp) > ClaimExpiryDuration {
			delete(peerHeightClaims, addr)
		}
	}
}

func OnMessage(addr [4]byte, m []byte) {

	h := common.GetHeight()

	//logger.GetLogger().Println("New message nonce from:", addr)
	//common.BlockMutex.Lock()
	//defer common.BlockMutex.Unlock()
	defer func() {
		if r := recover(); r != nil {
			debug.PrintStack()
			logger.GetLogger().Println("recover (sync Msg)", r)
		}

	}()

	isValid, amsg := message.CheckValidMessage(m)
	if isValid == false {
		logger.GetLogger().Println("sync msg validation fails")
		tcpip.ReduceAndCheckIfBanIP(addr)
		return
	}
	tcpip.ValidRegisterPeer(addr)
	switch string(amsg.GetHead()) {
	case "hi": // getheader

		txn := amsg.(message.TransactionsMessage).GetTransactionsBytes()
		var topicip [6]byte
		var ip4 [4]byte
		if tcpip.GetPeersCount() < common.MaxPeersConnected {
			peers := txn[[2]byte{'P', 'P'}]
			peersConnectedNN := tcpip.GetPeersConnected(tcpip.NonceTopic)
			peersConnectedBB := tcpip.GetPeersConnected(tcpip.SyncTopic)
			peersConnectedTT := tcpip.GetPeersConnected(tcpip.TransactionTopic)

			for _, ip := range peers {
				copy(ip4[:], ip)
				copy(topicip[2:], ip)
				copy(topicip[:2], tcpip.NonceTopic[:])
				if bytes.Equal(ip4[:], addr[:]) {
					continue
				}
				connectingPeersMutex.Lock()
				copy(topicip[:2], tcpip.NonceTopic[:])
				if _, ok := peersConnectedNN[topicip]; !ok && !tcpip.IsIPBanned(ip4) && !connectingPeers[topicip] {
					connectingPeers[topicip] = true
					go func(pip [4]byte, key [6]byte) {
						nonceServices.StartSubscribingNonceMsg(pip)
						connectingPeersMutex.Lock()
						delete(connectingPeers, key)
						connectingPeersMutex.Unlock()
					}(ip4, topicip)
				}
				copy(topicip[:2], tcpip.SyncTopic[:])
				if _, ok := peersConnectedBB[topicip]; !ok && !tcpip.IsIPBanned(ip4) && !connectingPeers[topicip] {
					connectingPeers[topicip] = true
					go func(pip [4]byte, key [6]byte) {
						StartSubscribingSyncMsg(pip)
						connectingPeersMutex.Lock()
						delete(connectingPeers, key)
						connectingPeersMutex.Unlock()
					}(ip4, topicip)
				}
				copy(topicip[:2], tcpip.TransactionTopic[:])
				if _, ok := peersConnectedTT[topicip]; !ok && !tcpip.IsIPBanned(ip4) && !connectingPeers[topicip] {
					connectingPeers[topicip] = true
					go func(pip [4]byte, key [6]byte) {
						transactionServices.StartSubscribingTransactionMsg(pip)
						connectingPeersMutex.Lock()
						delete(connectingPeers, key)
						connectingPeersMutex.Unlock()
					}(ip4, topicip)
				}
				connectingPeersMutex.Unlock()
				if tcpip.GetPeersCount() > common.MaxPeersConnected {
					break
				}
			}
		}
		lastOtherHeight := common.GetInt64FromByte(txn[[2]byte{'L', 'H'}][0])
		lastOtherBlockHashBytes := txn[[2]byte{'L', 'B'}][0]

		// Record this peer's height claim for consensus tracking
		recordPeerHeightClaim(addr, lastOtherHeight, lastOtherBlockHashBytes)
		// Refresh the network height before any IsSyncing decision below, so the
		// decision uses what peers actually report instead of the static
		// HEIGHT_OF_NETWORK hint.
		updateSyncTarget()

		// Periodically cleanup expired claims
		go cleanupExpiredClaims()

		if common.IsBehindNetwork() {
			common.IsSyncing.Store(true)
		}

		if lastOtherHeight == h {
			services.AdjustShiftInPastInReset(lastOtherHeight)
			lastBlockHashBytes, err := blocks.LoadHashOfBlock(h)
			if err != nil {
				logger.GetLogger().Println("cannot load block hash at height", h, ":", err)
				return
			}
			if !bytes.Equal(lastOtherBlockHashBytes, lastBlockHashBytes) {
				SendGetHeaders(addr, lastOtherHeight)
			}
			if !common.IsBehindNetwork() {
				common.IsSyncing.Store(false)
			}
			return
		} else if lastOtherHeight < h {
			services.AdjustShiftInPastInReset(lastOtherHeight)
			if !common.IsBehindNetwork() {
				common.IsSyncing.Store(false)
			}
			return
		}

		// When others claim a longer chain - validate before syncing
		shouldSync, validatedHeight := shouldSyncToHeight(lastOtherHeight, h)
		if !shouldSync {
			logger.GetLogger().Printf("Ignoring height claim %d from %v - not validated", lastOtherHeight, addr)
			return
		}

		common.IsSyncing.Store(true)
		SendGetHeaders(addr, validatedHeight)
		return
	case "sh":
		// Serialize sync batch processing — only one "sh" handler at a time
		syncProcessMutex.Lock()
		defer syncProcessMutex.Unlock()
		// Re-read height after acquiring lock since another batch may have advanced it
		h = common.GetHeight()

		txn := amsg.(message.TransactionsMessage).GetTransactionsBytes()
		blcks := []blocks.Block{}
		indices := []int64{}
		for k, tx := range txn {
			for _, t := range tx {
				if k == [2]byte{'I', 'H'} {
					index := common.GetInt64FromByte(t)
					indices = append(indices, index)
				} else if k == [2]byte{'H', 'V'} {
					block := blocks.Block{
						BaseBlock:          blocks.BaseBlock{},
						TransactionsHashes: nil,
						BlockHash:          common.Hash{},
					}
					block, err := block.GetFromBytes(t)
					if err != nil {
						logger.GetLogger().Println("cannot unmarshal header:", err)
						return
					}
					blcks = append(blcks, block)
				}
			}
		}
		hmax := common.GetHeightMax()
		if len(indices) == 0 || len(blcks) == 0 {
			logger.GetLogger().Println("empty blocks received from peer - possible fake height claim")
			tcpip.ReduceAndCheckIfBanIP(addr)
			// Exit sync if we have no progress
			if !common.IsBehindNetwork() {
				common.IsSyncing.Store(false)
			}
			return
		}
		if indices[len(indices)-1] <= h {
			logger.GetLogger().Println("shorter other chain")
			// Peer claimed higher but sent lower blocks - suspicious
			if !common.IsBehindNetwork() {
				common.IsSyncing.Store(false)
			}
			return
		}
		if indices[0] > h+1 {
			logger.GetLogger().Println("too far blocks from peer - gap in chain")
			// Don't ban, but exit sync if this was the only claim
			if !common.IsBehindNetwork() {
				common.IsSyncing.Store(false)
			}
			return
		}
		// check blocks
		was := false
		hashesMissingAll := [][]byte{}
		lastGoodBlock := indices[0]
		// verifiedUpTo is the highest new block in this batch that passed
		// verification. Blocks past it must not be applied: this phase checks the
		// whole batch against pre-batch state, while state a block introduces
		// (validator pubkeys via ProcessBlockPubKey, for one) only lands when that
		// block is applied. It stays at h when nothing new verified.
		verifiedUpTo := h
		// completeUpTo is the top of the contiguous run starting at our own tip for
		// which we hold every transaction, i.e. how far this batch can be verified
		// at all. It stays at h when nothing new is complete.
		completeUpTo := h
		merkleTries := map[int64]*transactionsPool.MerkleTree{}

		// First pass, cheap hash lookups only: detect a fork against the part of
		// the batch we already have, and take a census of the transactions we are
		// missing across the WHOLE batch. Verifying a block whose transactions are
		// absent yields failures that look like consensus violations but are only
		// missing data, so nothing may be verified before this pass is done.
		for i := 0; i < len(blcks); i++ {
			index := indices[i]
			if index <= 0 {
				continue
			}
			block := blcks[i]
			if index <= h {
				hashOfMyBlockBytes, err := blocks.LoadHashOfBlock(index)
				if err != nil {
					services.AdjustShiftInPastInReset(hmax)
					common.ShiftToPastMutex.RLock()
					services.ResetAccountsAndBlocksSync(index - common.ShiftToPastInReset)
					common.ShiftToPastMutex.RUnlock()
					logger.GetLogger().Println("cannot load block hash at index", index, "- reset done")
					return
				}
				if bytes.Equal(block.BlockHash.GetBytes(), hashOfMyBlockBytes) {
					lastGoodBlock = index
					continue
				}
				logger.GetLogger().Printf("Block hash mismatch at index %d - potential fork detected", index)
				services.AdjustShiftInPastInReset(hmax)
				common.ShiftToPastMutex.RLock()
				services.ResetAccountsAndBlocksSync(index - common.ShiftToPastInReset)
				common.ShiftToPastMutex.RUnlock()
				logger.GetLogger().Println("fork detected at index", index, "- reset done")
				return
			}
			hashesMissing := blocks.IsAllTransactions(block)
			if len(hashesMissing) > 0 {
				logger.GetLogger().Printf("Block %d is missing %d transactions", index, len(hashesMissing))
				hashesMissingAll = append(hashesMissingAll, hashesMissing...)
				continue
			}
			if index == completeUpTo+1 {
				completeUpTo = index
			}
		}

		// Ask for everything this batch needs in one round trip, so the next batch
		// can be verified and applied whole instead of crawling forward one block
		// per message.
		if len(hashesMissingAll) > 0 {
			logger.GetLogger().Printf("Sync incomplete - requesting %d missing transactions from peer in chunks", len(hashesMissingAll))
			maxChunk := common.MaxNumberTransactionInChunk
			for i := 0; i < len(hashesMissingAll); i += maxChunk {
				end := i + maxChunk
				if end > len(hashesMissingAll) {
					end = len(hashesMissingAll)
				}
				chunk := hashesMissingAll[i:end]
				logger.GetLogger().Printf("Sending bt chunk %d-%d of %d to %v", i, end, len(hashesMissingAll), addr)
				transactionServices.SendGT(addr, chunk, "bt")
				time.Sleep(500 * time.Millisecond)
			}
			if completeUpTo <= h {
				logger.GetLogger().Println("Waiting for missing transactions before continuing sync")
				return
			}
			// Do not stand still while the peer answers: the blocks we do hold form
			// a contiguous run from our tip, so they can be applied right away.
			logger.GetLogger().Printf("Requested missing transactions - applying the complete run up to %d meanwhile", completeUpTo)
		}

		for i := 0; i < len(blcks); i++ {
			header := blcks[i].GetHeader()
			index := indices[i]

			if index <= 0 || index <= h {
				continue
			}
			if index > completeUpTo {
				break
			}
			block := blcks[i]
			oldBlock := blocks.Block{}
			// parentFromPeer records where oldBlock came from; `was` is flipped inside
			// the else branch, so it cannot answer that question after the fact.
			parentFromPeer := was
			if was {
				oldBlock = blcks[i-1]
				logger.GetLogger().Printf("Using previous block from received blocks for index %d", index)
			} else {
				oldBlock, err = blocks.LoadBlock(index - 1)
				if err != nil {
					logger.GetLogger().Printf("ERROR: Failed to load previous block for index %d: %v", index-1, err)
					return
				}
				was = true
				logger.GetLogger().Printf("Loaded previous block from storage for index %d", index)
			}

			// Special logging for second block
			if index == 1 {
				logger.GetLogger().Printf("=== Processing second block in sync service ===")
				logger.GetLogger().Printf("Current height: %d", h)
				logger.GetLogger().Printf("Second block hash: %x", block.BlockHash.GetBytes())
				logger.GetLogger().Printf("Second block previous hash: %x", block.GetHeader().PreviousHash.GetBytes())
				logger.GetLogger().Printf("Genesis block hash: %x", oldBlock.BlockHash.GetBytes())
				logger.GetLogger().Printf("Is initial sync: %v", h == 0)
				logger.GetLogger().Printf("Block verification path: %s", "sync")
				logger.GetLogger().Printf("Block source: %s", func() string {
					if was {
						return "from received blocks"
					}
					return "from storage"
				}())

				// Check if block exists in storage
				storedBlock, err := blocks.LoadBlock(1)
				if err == nil {
					logger.GetLogger().Printf("Second block already in storage - Hash: %x", storedBlock.BlockHash.GetBytes())
					logger.GetLogger().Printf("Second block in storage previous hash: %x", storedBlock.GetHeader().PreviousHash.GetBytes())
					if !bytes.Equal(storedBlock.BlockHash.GetBytes(), block.BlockHash.GetBytes()) {
						logger.GetLogger().Printf("WARNING: Second block hash mismatch between received and stored")
						logger.GetLogger().Printf("Stored hash: %x", storedBlock.BlockHash.GetBytes())
						logger.GetLogger().Printf("Received hash: %x", block.BlockHash.GetBytes())
					}
				} else {
					logger.GetLogger().Printf("No second block found in storage")
				}
			}

			// Add detailed logging for block hash verification
			logger.GetLogger().Printf("block %d hash: %x", index, block.BlockHash.GetBytes())
			logger.GetLogger().Printf("Verifying block %d previous hash: %x", index, block.GetHeader().PreviousHash.GetBytes())
			logger.GetLogger().Printf("Previous block %d hash: %x", index-1, oldBlock.BlockHash.GetBytes())
			logger.GetLogger().Printf("Previous block %d previous hash: %x", index-1, oldBlock.GetHeader().PreviousHash.GetBytes())
			if !bytes.Equal(block.GetHeader().PreviousHash.GetBytes(), oldBlock.BlockHash.GetBytes()) {
				logger.GetLogger().Printf("ERROR: Block %d previous hash mismatch - Expected: %x, Got: %x",
					index,
					oldBlock.BlockHash.GetBytes(),
					block.GetHeader().PreviousHash.GetBytes())
			}

			if header.Height != index {
				logger.GetLogger().Printf("ERROR: Height mismatch - Block header height: %d, Expected index: %d", header.Height, index)
				services.AdjustShiftInPastInReset(hmax)
				common.ShiftToPastMutex.RLock()
				services.ResetAccountsAndBlocksSync(index - common.ShiftToPastInReset)
				common.ShiftToPastMutex.RUnlock()
				logger.GetLogger().Println("height mismatch - reset done")
				return
			}

			logger.GetLogger().Printf("Performing base block verification for block %d", index)
			merkleTrie, err := blocks.CheckBaseBlock(block, oldBlock, false)
			defer merkleTrie.Destroy()
			if err != nil {
				logger.GetLogger().Printf("ERROR: Base block verification failed for block %d: %v", index, err)
				// A block verified here may depend on state that an earlier block of
				// this same batch only writes when it is applied - a validator pubkey
				// registered by ProcessBlockPubKey being the common case, without
				// which oracle proof authentication cannot check a signature. So when
				// we already have a verified prefix, stop the batch and apply it
				// rather than declaring a fork: the next round re-checks this block
				// against the state the prefix produced.
				if verifiedUpTo > h {
					logger.GetLogger().Printf("stopping batch at block %d - applying verified blocks up to %d first", index, verifiedUpTo)
					break
				}
				// Only blame the peer when the parent came from its own batch, i.e.
				// the blocks it sent are internally inconsistent. When the parent
				// came from our storage the mismatch is our own fork, and banning
				// here would ban the honest peer we need to recover from it.
				if parentFromPeer {
					tcpip.ReduceAndCheckIfBanIP(addr)
				} else {
					logger.GetLogger().Printf("parent block %d came from local storage - treating as own fork, not banning %v", index-1, addr)
				}
				services.AdjustShiftInPastInReset(hmax)
				common.ShiftToPastMutex.RLock()
				services.ResetAccountsAndBlocksSync(index - common.ShiftToPastInReset)
				common.ShiftToPastMutex.RUnlock()
				logger.GetLogger().Println("block verification failed at index", index, ":", err, "- reset done")
				return

			}
			merkleTries[index] = merkleTrie
			verifiedUpTo = index
		}

		if verifiedUpTo <= h {
			logger.GetLogger().Println("nothing new could be verified in this batch")
			return
		}
		common.IsSyncing.Store(true)
		logger.GetLogger().Println("Starting final block processing and fund transfers")

		defer func() {
			if !common.IsBehindNetwork() {
				common.IsSyncing.Store(false)
			}
		}()
		common.BlockMutex.Lock()
		defer common.BlockMutex.Unlock()
		// Re-read height after acquiring lock — another goroutine may have advanced it
		h = common.GetHeight()
		was = false
		for i := 0; i < len(blcks); i++ {
			block := blcks[i]
			index := indices[i]
			if index > verifiedUpTo {
				// Beyond the verified prefix: these blocks were never checked, or
				// were checked against state that only exists once this prefix is
				// applied. The next sync round picks them up.
				logger.GetLogger().Printf("Stopping at block %d - beyond the verified prefix (up to %d)", index, verifiedUpTo)
				break
			}
			if block.GetHeader().Height <= lastGoodBlock || index <= h {
				logger.GetLogger().Printf("Skipping already verified block %d", index)
				continue
			}

			logger.GetLogger().Printf("Processing final verification and fund transfer for block %d", index)
			oldBlock := blocks.Block{}
			if was == true {
				oldBlock = blcks[i-1]
			} else {
				oldBlock, err = blocks.LoadBlock(index - 1)
				if err != nil {
					logger.GetLogger().Printf("ERROR: Failed to load previous block for index %d: %v", index-1, err)
					return
				}
				was = true
			}

			err := blocks.CheckBlockAndTransferFunds(&block, oldBlock, merkleTries[index], false)
			if err != nil {
				logger.GetLogger().Printf("ERROR: Fund transfer failed for block %d: %v", index, err)
				hashesMissing := blocks.IsAllTransactions(block)
				if len(hashesMissing) > 0 {
					logger.GetLogger().Printf("Detected %d missing transactions during fund transfer", len(hashesMissing))
					maxChunk := common.MaxNumberTransactionInChunk
					for j := 0; j < len(hashesMissing); j += maxChunk {
						end := j + maxChunk
						if end > len(hashesMissing) {
							end = len(hashesMissing)
						}
						transactionServices.SendGT(addr, hashesMissing[j:end], "bt")
						time.Sleep(500 * time.Millisecond)
					}
				}
				services.ResetAccountsAndBlocksSync(oldBlock.GetHeader().Height)
				return
			}

			logger.GetLogger().Printf("Storing block %d", index)
			err = block.StoreBlock()
			if err != nil {
				logger.GetLogger().Printf("ERROR: Failed to store block %d: %v", index, err)
				services.ResetAccountsAndBlocksSync(oldBlock.GetHeader().Height)
				return
			}

			logger.GetLogger().Println("Sync New Block success -------------------------------------", block.GetHeader().Height)
			err = account.StoreAccounts(block.GetHeader().Height)
			if err != nil {
				logger.GetLogger().Println(err)
			}

			err = account.StoreStakingAccounts(block.GetHeader().Height)
			if err != nil {
				logger.GetLogger().Println(err)
			}
			common.SetHeight(block.GetHeader().Height)

			sm := statistics.GetStatsManager()
			sm.UpdateStatistics(block, oldBlock)

		}

	case "gh":
		logger.GetLogger().Printf("Received gh (get headers) request from %v", addr)
		txn := amsg.(message.TransactionsMessage).GetTransactionsBytes()

		bHeight := common.GetInt64FromByte(txn[[2]byte{'B', 'H'}][0])
		eHeight := common.GetInt64FromByte(txn[[2]byte{'E', 'H'}][0])
		bHeight, eHeight = clampHeaderSpan(bHeight, eHeight) // NP-M13: bound the requested span
		logger.GetLogger().Printf("gh request: bHeight=%d, eHeight=%d, sending headers to %v", bHeight, eHeight, addr)
		SendHeaders(addr, bHeight, eHeight)
	default:
	}
}
