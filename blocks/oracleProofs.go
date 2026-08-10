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

// AuthenticateOracleProofs verifies that the oracle values embedded in a block
// are each backed by a signature-verified, fresh oracle nonce transaction.
func AuthenticateOracleProofs(blockHeight int64, proofs [][]byte, priceData, randData []byte) error {
	return authenticateOracleProofs(blockHeight, proofs, priceData, randData, func(pb []byte) (*transactionsDefinition.Transaction, error) {
		var tx transactionsDefinition.Transaction
		decoded, _, err := tx.GetFromBytes(pb)
		if err != nil {
			return nil, fmt.Errorf("cannot decode oracle proof: %w", err)
		}
		if !decoded.Verify(common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2()) {
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
