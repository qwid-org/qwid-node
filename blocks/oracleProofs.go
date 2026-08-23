package blocks

import (
	"fmt"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/oracles"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// oracleSubmission is the authenticated content of one validator's oracle nonce
// transaction: the delegated-account height plus the signed price/rand values.
type oracleSubmission struct {
	height int64
	price  int64
	rand   int64
}

// oracleOptDataMinLen is the smallest OptData that carries oracle values:
// 8-byte height + 32-byte parent hash + 8-byte price + 8-byte rand.
const oracleOptDataMinLen = 8 + common.HashLength + 16

// verifiedDecoder decodes one embedded oracle proof and returns the decoded
// nonce transaction only if it deserializes and its signature verifies.
type verifiedDecoder func(proof []byte) (*transactionsDefinition.Transaction, error)

type oracleProofAuthorizer func(id int, sender common.Address) bool

// extractOracleSubmission pulls the delegated id and signed (height, price,
// rand) out of a decoded oracle nonce transaction. It does not check the
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
		rand:   common.GetInt64FromByte(o[8:16]),
	}, nil
}

// authenticateOracleProofs is the testable core: the decoder (which verifies
// signatures) is injected. It builds the set of authenticated submissions from
// the proofs and then confirms every embedded price/rand triple is backed by
// one of them.
func authenticateOracleProofs(blockHeight int64, proofs [][]byte, priceData, randData []byte, decode verifiedDecoder) error {
	subs := make(map[uint8]oracleSubmission)
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
		if _, dup := subs[id]; dup {
			return fmt.Errorf("duplicate oracle proof for delegated id %d", id)
		}
		subs[id] = sub
	}
	return matchOracleData(subs, priceData, randData)
}

// matchOracleData requires every (id, height, value) entry embedded in the
// block's price/rand data to be backed by an authenticated submission with the
// identical id, height, and value. This is what stops a producer from putting
// fabricated oracle values (attributed to other validators) into a block.
func matchOracleData(subs map[uint8]oracleSubmission, priceData, randData []byte) error {
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
	randMap, _, _, err := oracles.ParseRandData(randData)
	if err != nil {
		return err
	}
	for id, ro := range randMap {
		sub, ok := subs[id]
		if !ok {
			return fmt.Errorf("rand entry for delegated id %d has no signed proof", id)
		}
		if sub.height != ro.Height || sub.rand != ro.Rand {
			return fmt.Errorf("rand entry for delegated id %d does not match its signed proof", id)
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

// AuthenticateOracleProofs verifies that the oracle values embedded in a block
// are each backed by a signature-verified, fresh oracle nonce transaction.
//
// Each proof is verified with the signature-scheme configuration in force at
// the proof's own signing height (taken from block headers), not the node's
// current global config: around a scheme change a block legitimately embeds
// proofs signed under the previous scheme, and a node that has already adopted
// the new scheme would otherwise be permanently unable to verify that block.
func AuthenticateOracleProofs(newBlock, lastBlock Block) error {
	blockHeight := newBlock.GetHeader().Height
	// Resolving a config re-validates the scheme against liboqs (a keypair
	// generation), so cache it per height for the duration of this block check —
	// proofs cluster on a handful of heights.
	type sigNames struct {
		sigName, sigName2   string
		isPaused, isPaused2 bool
	}
	cache := map[int64]sigNames{}
	return authenticateOracleProofs(blockHeight, newBlock.BaseBlock.OracleProofs, newBlock.BaseBlock.PriceOracleData, newBlock.BaseBlock.RandOracleData, func(pb []byte) (*transactionsDefinition.Transaction, error) {
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
		if !decoded.Verify(names.sigName, names.sigName2, names.isPaused, names.isPaused2) {
			return nil, fmt.Errorf("oracle proof signature verification failed")
		}
		return &decoded, nil
	})
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
