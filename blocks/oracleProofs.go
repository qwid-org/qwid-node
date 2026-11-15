package blocks

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/oracles"
	"github.com/qwid-org/qwid-node/pubkeys"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/wallet"
)

// oracleSubmission is the authenticated content of one validator's oracle nonce
// transaction: its height and the signed price. (RAND comes from RANDAO,
// S4-06; the nonce's former rand slot is ignored.)
type oracleSubmission struct {
	height int64
	price  int64
}

// oracleOptDataMinLen is the smallest OptData that carries oracle values:
// 8-byte height + 32-byte parent hash + 8-byte price + 8-byte rand.
const oracleOptDataMinLen = 8 + common.HashLength + 16

// verifiedDecoder decodes one embedded oracle proof and returns the decoded
// nonce transaction only if it deserializes and its signature verifies.
type verifiedDecoder func(proof []byte) (*transactionsDefinition.Transaction, error)

type oracleProofAuthorizer func(id int, sender common.Address) bool

// extractOracleSubmission pulls the delegated id and signed (height, price)
// out of a decoded oracle nonce transaction. It does not check the
// signature; that is the decoder's responsibility.
func extractOracleSubmission(tx *transactionsDefinition.Transaction) (uint8, oracleSubmission, error) {
	id, err := account.IntDelegatedAccountFromAddress(tx.TxData.Recipient)
	if err != nil || id <= 0 || id >= 256 {
		return 0, oracleSubmission{}, fmt.Errorf("oracle proof recipient is not a delegated account")
	}
	if tx.TxData.Amount != 0 {
		return 0, oracleSubmission{}, fmt.Errorf("oracle nonce transaction must have zero amount")
	}
	if len(tx.TxData.OptData) < oracleOptDataMinLen {
		return 0, oracleSubmission{}, fmt.Errorf("oracle nonce OptData too short: %d", len(tx.TxData.OptData))
	}
	o := tx.TxData.OptData[8+common.HashLength:]
	return uint8(id), oracleSubmission{
		height: tx.Height,
		price:  common.GetInt64FromByte(o[:8]),
	}, nil
}

// authenticateOracleProofs is the testable core: the decoder (which verifies
// signatures) is injected. It builds the set of authenticated submissions from
// the proofs and then confirms every embedded price triple is backed by one of
// them.
// counts says whether a proof's price counts (proofCounts); one that does not
// stays embedded but is left out of the price data. nil counts every proof.
func authenticateOracleProofs(blockHeight int64, proofs [][]byte, priceData []byte, decode verifiedDecoder, counts func(*transactionsDefinition.Transaction) bool) error {
	subs := make(map[uint8]oracleSubmission)
	seen := make(map[uint8]bool)
	for _, pb := range proofs {
		tx, err := decode(pb)
		if err != nil {
			return err
		}
		// Freshness: the submission cannot be from the future and must be within
		// the oracle window, matching the block-side aggregation filter.
		if tx.Height > blockHeight || blockHeight > tx.Height+common.OraclesHeightDistance {
			return fmt.Errorf("oracle proof height %d not fresh for block %d", tx.Height, blockHeight)
		}
		id, sub, err := extractOracleSubmission(tx)
		if err != nil {
			return err
		}
		if seen[id] {
			return fmt.Errorf("duplicate oracle proof for delegated id %d", id)
		}
		seen[id] = true
		if counts != nil && !counts(tx) {
			continue // embedded, but its price does not count (second signature)
		}
		subs[id] = sub
	}
	if err := matchOracleData(subs, priceData); err != nil {
		return err
	}
	// S4-06: and nothing embedded may be left out. Without this a producer
	// could embed a proof (counting its signer's stake towards the 2/3) while
	// dropping the value it disliked from the median.
	if !bytes.Equal(priceData, encodeOracleData(subs)) {
		return fmt.Errorf("oracle data is not exactly the values of the embedded proofs")
	}
	return nil
}

// encodeOracleData is the canonical price data for a set of submissions:
// ascending delegated id, one (id, height, price) triple per non-zero price -
// the layout ParsePriceData reads and GeneratePriceData writes.
func encodeOracleData(subs map[uint8]oracleSubmission) (priceData []byte) {
	ids := make([]int, 0, len(subs))
	for id := range subs {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	priceData = []byte{}
	for _, i := range ids {
		sub := subs[uint8(i)]
		if sub.price > 0 {
			priceData = append(priceData, uint8(i))
			priceData = append(priceData, common.GetByteInt64(sub.height)...)
			priceData = append(priceData, common.GetByteInt64(sub.price)...)
		}
	}
	return priceData
}

// oracleDataFromProofs derives the canonical price data from embedded proofs;
// the producer uses it so its data and proofs can never disagree.
func oracleDataFromProofs(proofs [][]byte, decode verifiedDecoder) (priceData []byte, err error) {
	subs := make(map[uint8]oracleSubmission)
	for _, pb := range proofs {
		tx, err := decode(pb)
		if err != nil {
			return nil, err
		}
		id, sub, err := extractOracleSubmission(tx)
		if err != nil {
			return nil, err
		}
		if _, dup := subs[id]; dup {
			return nil, fmt.Errorf("duplicate oracle proof for delegated id %d", id)
		}
		subs[id] = sub
	}
	return encodeOracleData(subs), nil
}

// OracleDataFromProofs is oracleDataFromProofs for proofs this node collected
// and verified on receipt.
func OracleDataFromProofs(proofs [][]byte) (priceData []byte, err error) {
	return oracleDataFromProofs(proofs, decodeProof)
}

// matchOracleData requires every (id, height, price) entry embedded in the
// block's price data to be backed by an authenticated submission with the
// identical id, height, and price. This is what stops a producer from putting
// fabricated oracle values (attributed to other validators) into a block.
func matchOracleData(subs map[uint8]oracleSubmission, priceData []byte) error {
	priceMap, _, _, err := oracles.ParsePriceData(priceData)
	if err != nil {
		return err
	}
	for id, po := range priceMap {
		sub, ok := subs[id]
		if !ok {
			return fmt.Errorf("price entry for delegated id %d has no signed proof", id)
		}
		if sub.height != po.Height || sub.price != po.Price {
			return fmt.Errorf("price entry for delegated id %d does not match its signed proof", id)
		}
	}
	return nil
}

// sigNamesAtProofHeight resolves the signature-scheme configuration recorded
// in the chain at the given height, using the in-memory blocks first: during
// batched sync the block at that height may belong to the same not-yet-stored
// batch, in which case only newBlock and its parent are at hand. Falling back
// to the parent's config in that gap is no worse than the pre-fix global
// config, and the sync loop's stop-batch-and-apply-prefix recovery covers it.
func sigNamesAtProofHeight(height int64, newBlock, lastBlock Block) (string, string, bool, bool, error) {
	if height >= newBlock.GetHeader().Height {
		return newBlock.GetSigNames()
	}
	if height == lastBlock.GetHeader().Height {
		return lastBlock.GetSigNames()
	}
	if b, err := LoadBlock(height); err == nil {
		return b.GetSigNames()
	}
	return lastBlock.GetSigNames()
}

// proofPauseFlags are the pause flags an embedded oracle proof is verified
// under: the PRIMARY slot is paused when the containing block's parent pauses
// it, and the secondary slot never is.
//
// A primary pause is the chain's verdict that the scheme may be broken
// (schemeBroken). Verifying proofs with no pause gate at all let whoever can
// forge that scheme - and may produce a block - fabricate the nonces of the
// other validators after the pause: two thirds of the stake "voting" for any
// scheme change, un-pausing the broken scheme included, or any price (audit
// 2026-11-12 F-CONS-06). The parent's own header is read, so the verdict is
// the same on every node and in every mode, and a block that pauses the
// primary still counts the proofs signed before it.
//
// The secondary is not gated: its liveness is derived from the primary's
// (GetSigNames), and headers from the era when both schemes were live would
// read as a paused spare, re-judging the proofs of that era by today's rule -
// the chain once stopped exactly so.
func proofPauseFlags(lastBlock Block) (bool, bool) {
	enc1, err := FromBytesToEncryptionConfig(lastBlock.GetHeader().Encryption1, true)
	if err != nil {
		return false, false
	}
	return enc1.IsPaused, false
}

// proofCounts reports whether a decoded proof's vote and price count in a
// block built on lastBlock.
//
//   - Pause gate (F-CONS-06): with the primary paused, a primary-signed proof
//     does not count.
//   - Second signature (audit 2026-11-14): with the primary live, a validator
//     holding an eligible spare key (pubkeys.SecondFactorKeysAsOf) counts only
//     when its nonce is signed with the primary AND carries a second
//     signature by one of those spare keys. A validator without one counts
//     with its single signature - after a replacement of the spare scheme
//     nobody holds an eligible key for a while, and the chain must keep its
//     price and its votes.
//
// A proof that does not count leaves its block valid; it is left out of the
// price and the vote tally.
func proofCounts(tx *transactionsDefinition.Transaction, lastBlock Block) bool {
	primaryPaused, _ := proofPauseFlags(lastBlock)
	sig := tx.GetSignature().GetBytes()
	if len(sig) == 0 {
		return false
	}
	if primaryPaused {
		return sig[0] != 0
	}
	sigName, sigName2, _, _, err := lastBlock.GetSigNames()
	if err != nil {
		return false
	}
	len2, err := oqs.PubKeyLength(sigName2)
	if err != nil {
		return true // no known spare scheme: no second factor to require
	}
	eligible := pubkeys.SecondFactorKeysAsOf(tx.GetSenderAddress(), false, len2, lastBlock.GetHeader().Height)
	if len(eligible) == 0 {
		return true
	}
	if sig[0] != 0 {
		return false
	}
	sig2, msg, ok := transactionsDefinition.NonceSecondSignature(*tx)
	if !ok || len(sig2) < 2 || sig2[0] != 1 {
		return false
	}
	for _, pk := range eligible {
		if wallet.Verify(msg, sig2, pk.GetBytes(), sigName, sigName2, false, false) {
			return true
		}
	}
	return false
}

// filterPausedProofs drops the proofs a block built on lastBlock must not
// carry under proofPauseFlags, so a producer never builds a block validators
// reject.
func filterPausedProofs(proofs [][]byte, lastBlock Block) [][]byte {
	out := make([][]byte, 0, len(proofs))
	for _, pb := range proofs {
		tx, err := decodeProof(pb)
		if err != nil || !proofCounts(tx, lastBlock) {
			continue
		}
		out = append(out, pb)
	}
	return out
}

func AuthenticateOracleProofs(newBlock, lastBlock Block) error {
	if err := oracleProofBudgetError(newBlock.BaseBlock.OracleProofs); err != nil {
		return err
	}
	blockHeight := newBlock.GetHeader().Height
	// Resolving a config re-validates the scheme against liboqs (a keypair
	// generation), so cache it per height for the duration of this block check —
	// proofs cluster on a handful of heights.
	type sigNames struct {
		sigName, sigName2   string
		isPaused, isPaused2 bool
	}
	cache := map[int64]sigNames{}
	counts := func(tx *transactionsDefinition.Transaction) bool { return proofCounts(tx, lastBlock) }
	return authenticateOracleProofs(blockHeight, newBlock.BaseBlock.OracleProofs, newBlock.BaseBlock.PriceOracleData, func(pb []byte) (*transactionsDefinition.Transaction, error) {
		var tx transactionsDefinition.Transaction
		decoded, _, err := tx.GetFromBytes(pb)
		if err != nil {
			return nil, fmt.Errorf("cannot decode oracle proof: %w", err)
		}
		names, ok := cache[decoded.Height]
		if !ok {
			sigName, sigName2, isPaused, isPaused2, err := sigNamesAtProofHeight(decoded.Height, newBlock, lastBlock)
			if err != nil {
				return nil, fmt.Errorf("cannot resolve signature schemes for oracle proof at height %d: %w", decoded.Height, err)
			}
			names = sigNames{sigName, sigName2, isPaused, isPaused2}
			cache[decoded.Height] = names
		}
		isPaused, isPaused2 := proofPauseFlags(lastBlock)
		if !decoded.VerifyNonce(names.sigName, names.sigName2, isPaused, isPaused2) {
			return nil, fmt.Errorf("oracle proof signature verification failed")
		}
		return &decoded, nil
	}, counts)
}

// authorizeOracleProofSigners binds every delegated id named by a proof to the
// operational account selected by the staking snapshot. Signature validity is
// checked separately by AuthenticateOracleProofs; keeping this check in the
// stake-dependent phase makes it use the parent state during block application.
func authorizeOracleProofSigners(proofs [][]byte, decode verifiedDecoder, authorize oracleProofAuthorizer) error {
	for _, pb := range proofs {
		tx, err := decode(pb)
		if err != nil {
			return err
		}
		id, _, err := extractOracleSubmission(tx)
		if err != nil {
			return err
		}
		if !authorize(int(id), tx.GetSenderAddress()) {
			return fmt.Errorf("oracle proof signer is not the authorized operator for delegated id %d", id)
		}
	}
	return nil
}

// AuthorizeOracleProofSigners validates proof authority against the current
// staking snapshot. It must be called while that snapshot represents the
// proof-carrying block's parent.
func AuthorizeOracleProofSigners(proofs [][]byte) error {
	return authorizeOracleProofSigners(proofs, func(pb []byte) (*transactionsDefinition.Transaction, error) {
		var tx transactionsDefinition.Transaction
		decoded, rest, err := tx.GetFromBytes(pb)
		if err != nil {
			return nil, fmt.Errorf("cannot decode oracle proof for authorization: %w", err)
		}
		if len(rest) != 0 {
			return nil, fmt.Errorf("oracle proof has %d trailing bytes", len(rest))
		}
		return &decoded, nil
	}, account.IsTop128StakingNode)
}

// AuthorizedOracleProofs keeps the proofs whose signer is, in the current
// staking snapshot, the operator of the delegated account they name - the
// rule validators apply in AuthorizeOracleProofSigners. A producer must
// filter by it: a proof stays in the store for OraclesHeightDistance blocks,
// and if a stake change hands its delegated account to another operator
// meanwhile, the block carrying it is rejected. Every candidate then carries
// the same stale proof, no block is accepted, the height never moves on, and
// the proof never ages out - the chain halts for good.
func AuthorizedOracleProofs(proofs [][]byte, lastBlock Block) [][]byte {
	return FitOracleProofs(filterAuthorizedOracleProofs(filterPausedProofs(proofs, lastBlock), decodeProof, account.IsTop128StakingNode))
}

// FitOracleProofs keeps proofs, in order, while their encoding fits
// common.MaxOracleProofBudgetBytes, so the block carrying them fits the nonce
// topic it is broadcast on (common.MaxMsgSizeNonce). Leaving a proof out is
// always allowed: the price data lists exactly the embedded proofs.
func FitOracleProofs(proofs [][]byte) [][]byte {
	used := int64(4) // the count prefix
	out := make([][]byte, 0, len(proofs))
	for _, pb := range proofs {
		need := int64(len(pb)) + 4
		if used+need > int64(common.MaxOracleProofBudgetBytes) {
			logger.GetLogger().Println("leaving out an oracle proof: the block's proof budget is full")
			continue
		}
		used += need
		out = append(out, pb)
	}
	return out
}

// oracleProofBudgetError is the consensus rule behind FitOracleProofs (audit
// 2026-11-15): a block's encoded oracle proofs - count prefix and each
// length-prefixed proof - must fit common.MaxOracleProofBudgetBytes, so every
// valid block fits the nonce topic it is broadcast on. Checked before any
// proof is decoded or verified.
func oracleProofBudgetError(proofs [][]byte) error {
	used := int64(4)
	for _, pb := range proofs {
		used += int64(len(pb)) + 4
	}
	if used > int64(common.MaxOracleProofBudgetBytes) {
		return fmt.Errorf("oracle proofs take %d bytes, over the block's budget of %d", used, common.MaxOracleProofBudgetBytes)
	}
	return nil
}

func filterAuthorizedOracleProofs(proofs [][]byte, decode verifiedDecoder, authorize oracleProofAuthorizer) [][]byte {
	out := make([][]byte, 0, len(proofs))
	for _, pb := range proofs {
		tx, err := decode(pb)
		if err != nil {
			continue
		}
		id, _, err := extractOracleSubmission(tx)
		if err != nil {
			continue
		}
		if !authorize(int(id), tx.GetSenderAddress()) {
			logger.GetLogger().Println("leaving out the oracle proof of delegated account", id,
				"- its signer no longer operates it")
			continue
		}
		out = append(out, pb)
	}
	return out
}
