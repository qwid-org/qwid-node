package blocks

import (
	"bytes"
	"fmt"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// Signature-scheme governance, decided from the chain alone (S4-05, S3-06).
//
// A validator's vote travels in every nonce it signs (after the oracle
// values), and those nonces are embedded in the block as OracleProofs. So the
// tally is taken from the block itself - signatures checked in CheckBaseBlock
// (AuthenticateOracleProofs), signers bound to their delegated accounts and
// stake weighed against the parent's staking snapshot in VerifyStakeDependent.
// Every node, live or syncing, reaches the same verdict. The old tally used
// each node's own map of the nonces it happened to receive, and was skipped
// entirely while syncing.
//
// A vote counts while the voter keeps sending it, within the proof freshness
// window (OraclesHeightDistance); a validator silent for that long does not
// vote.

// proofVotes returns the two scheme votes carried by an oracle nonce.
func proofVotes(tx *transactionsDefinition.Transaction) (vote1, vote2 []byte, err error) {
	if len(tx.TxData.OptData) < oracleOptDataMinLen {
		return nil, nil, fmt.Errorf("nonce carries no vote data")
	}
	vote1, rest, err := common.BytesWithLenToBytes(tx.TxData.OptData[oracleOptDataMinLen:])
	if err != nil {
		return nil, nil, err
	}
	vote2, _, err = common.BytesWithLenToBytes(rest)
	if err != nil {
		return nil, nil, err
	}
	return vote1, vote2, nil
}

// tallyEncryptionVotes sums the stake of the proofs voting for exactly want
// in the given slot. A proof without readable vote data simply does not vote.
func tallyEncryptionVotes(proofs [][]byte, primary bool, want []byte, decode verifiedDecoder, stakeOf func(id int) int64) (int64, error) {
	staked := int64(0)
	seen := map[uint8]bool{}
	for _, pb := range proofs {
		tx, err := decode(pb)
		if err != nil {
			return 0, err
		}
		id, _, err := extractOracleSubmission(tx)
		if err != nil {
			return 0, err
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		v1, v2, err := proofVotes(tx)
		if err != nil {
			continue
		}
		v := v1
		if !primary {
			v = v2
		}
		if len(v) > 0 && bytes.Equal(v, want) {
			staked += stakeOf(int(id))
		}
	}
	return staked, nil
}

// voteThresholdMet: pausing the live scheme needs a third of the stake, every
// other change - replacing a scheme, un-pausing one - two thirds.
func voteThresholdMet(parent, next oqs.ConfigEnc, staked, total int64) bool {
	if staked <= 0 || total <= 0 {
		return false
	}
	if next.SigName == parent.SigName && next.IsPaused && !parent.IsPaused {
		return staked*3 >= total
	}
	return staked*3 >= total*2
}

// parentSlotConfig is the parent's config of one slot, with the secondary's
// pause flag derived from the primary's exactly as GetSigNames does.
func parentSlotConfig(parent Block, primary bool) (oqs.ConfigEnc, error) {
	h := parent.GetHeader()
	if primary {
		return FromBytesToEncryptionConfig(h.Encryption1, true)
	}
	cfg, err := FromBytesToEncryptionConfig(h.Encryption2, false)
	if err != nil {
		return cfg, err
	}
	_, _, _, paused2, err := parent.GetSigNames()
	cfg.IsPaused = paused2
	return cfg, err
}

// checkEncryptionChangeShape validates one header slot against the parent's
// config and reports whether it proposes a change. Nothing here reads the
// node's own config or sync mode.
func checkEncryptionChangeShape(newBytes []byte, parent Block, primary bool) (bool, error) {
	parentBytes := parent.GetHeader().Encryption1
	if !primary {
		parentBytes = parent.GetHeader().Encryption2
	}
	if bytes.Equal(newBytes, parentBytes) {
		return false, nil
	}
	next, err := oqs.FromBytesToEncryptionConfig(newBytes)
	if err != nil {
		return false, err
	}
	if !oqs.VerifyEncConfig(next) {
		return false, fmt.Errorf("encryption config %q does not match the scheme", next.SigName)
	}
	cur, err := parentSlotConfig(parent, primary)
	if err != nil {
		return false, err
	}
	if next.SigName == cur.SigName && next.IsPaused == cur.IsPaused {
		return false, nil
	}
	other, err := parentSlotConfig(parent, !primary)
	if err != nil {
		return false, err
	}
	if next.SigName == other.SigName {
		return false, fmt.Errorf("both slots cannot hold %q", next.SigName)
	}
	if next.SigName != cur.SigName {
		if !cur.IsPaused {
			return false, fmt.Errorf("pause %q before replacing it with %q", cur.SigName, next.SigName)
		}
		if !next.IsPaused {
			return false, fmt.Errorf("replacement scheme %q has to start paused", next.SigName)
		}
	}
	return true, nil
}

func encryptionChangeAuthorised(proofs [][]byte, parent Block, want []byte, primary bool, height int64, total int64, decode verifiedDecoder, stakeOf func(id int) int64) error {
	next, err := oqs.FromBytesToEncryptionConfig(want)
	if err != nil {
		return err
	}
	cur, err := parentSlotConfig(parent, primary)
	if err != nil {
		return err
	}
	staked, err := tallyEncryptionVotes(proofs, primary, want, decode, stakeOf)
	if err != nil {
		return err
	}
	if !voteThresholdMet(cur, next, staked, total) {
		return fmt.Errorf("not enough stake votes for %q (paused=%v) at height %d: %d of %d",
			next.SigName, next.IsPaused, height, staked, total)
	}
	return nil
}

// decodeProof decodes an embedded oracle proof without re-checking its
// signature; callers run after AuthenticateOracleProofs has done that.
func decodeProof(pb []byte) (*transactionsDefinition.Transaction, error) {
	var tx transactionsDefinition.Transaction
	decoded, rest, err := tx.GetFromBytes(pb)
	if err != nil {
		return nil, fmt.Errorf("cannot decode oracle proof: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("oracle proof has %d trailing bytes", len(rest))
	}
	return &decoded, nil
}

func stakeOfDelegated(id int) int64 {
	_, staked, _ := account.GetStakedInDelegatedAccount(id)
	return staked
}

// VerifyEncryptionVotes rejects a block whose header changes a signature
// scheme without enough stake voting for it in the block's own proofs. It
// must run against the parent's staking snapshot (VerifyStakeDependent).
func VerifyEncryptionVotes(newBlock, lastBlock Block) error {
	for _, primary := range []bool{true, false} {
		want := newBlock.GetHeader().Encryption1
		if !primary {
			want = newBlock.GetHeader().Encryption2
		}
		changed, err := checkEncryptionChangeShape(want, lastBlock, primary)
		if err != nil {
			return err
		}
		if !changed {
			continue
		}
		if err := encryptionChangeAuthorised(newBlock.BaseBlock.OracleProofs, lastBlock, want, primary,
			newBlock.GetHeader().Height, account.GetStakedInAllDelegatedAccounts(), decodeProof, stakeOfDelegated); err != nil {
			return err
		}
	}
	return nil
}

// EncryptionChangeAuthorised lets a producer check its own vote before
// putting it in a header, so it never builds a block validators must reject.
// The staking state must be the parent's.
func EncryptionChangeAuthorised(proofs [][]byte, lastBlock Block, want []byte, primary bool, height int64) bool {
	changed, err := checkEncryptionChangeShape(want, lastBlock, primary)
	if err != nil || !changed {
		return false
	}
	return encryptionChangeAuthorised(proofs, lastBlock, want, primary, height,
		account.GetStakedInAllDelegatedAccounts(), decodeProof, stakeOfDelegated) == nil
}
