package voting

import (
	"errors"
	"fmt"
	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"sync"
)

type Votes struct {
	Values []byte `json:"values"`
	Height int64  `json:"height"`
	Staked int64  `json:"staked"`
}

var (
	VotesEncryption1     = make(map[uint8]Votes)
	VotesEncryption2     = make(map[uint8]Votes)
	AfterReset           = false
	VotesEncryptionMutex = sync.Mutex{}
)

func SaveVotesEncryption1(value []byte, height int64, delegatedAccount common.Address, staked int64) error {
	if len(value) == 0 {
		return nil
	}
	id, err := common.GetIDFromDelegatedAccountAddress(delegatedAccount)
	if err != nil {
		return err
	}

	// Delegated accounts are 1..255. The lower bound matters as much as the
	// upper one: GetIDFromDelegatedAccountAddress returns an int16, so the two
	// leading address bytes from 0x8000 up arrive negative, sail past an
	// `id >= 256` check and index uint8(id) — an arbitrary other account's
	// slot. The network path rejects such ids earlier (IsTop128StakingNode
	// bounds-checks), so this is the last line of defence rather than a live
	// hole, and it has to hold on its own.
	if id < 1 || id >= 256 {
		return fmt.Errorf("delegated account is invalid: %d", id)
	}
	VotesEncryptionMutex.Lock()
	defer VotesEncryptionMutex.Unlock()

	po, exists := VotesEncryption1[uint8(id)]
	// AC-M4: only replace with a strictly newer height; `<=` allowed a second
	// vote at the same height to overwrite the first.
	if !exists || po.Height < height {
		VotesEncryption1[uint8(id)] = Votes{
			Values: value,
			Height: height,
			Staked: staked,
		}
	} else {
		return errors.New("invalid height in voting, 1")
	}

	return nil
}

func SaveVotesEncryption2(value []byte, height int64, delegatedAccount common.Address, staked int64) error {
	if len(value) == 0 {
		return nil
	}
	id, err := common.GetIDFromDelegatedAccountAddress(delegatedAccount)
	if err != nil {
		return err
	}

	// See SaveVotesEncryption1: the lower bound rejects ids that wrapped
	// negative through int16 and would otherwise index another account's slot.
	if id < 1 || id >= 256 {
		return fmt.Errorf("delegated account is invalid: %d", id)
	}
	VotesEncryptionMutex.Lock()
	defer VotesEncryptionMutex.Unlock()
	logger.GetLogger().Println("Delegated Account ", id, " staked: ", account.Int64toFloat64(staked))
	po, exists := VotesEncryption2[uint8(id)]
	// AC-M4: only replace with a strictly newer height (see SaveVotesEncryption1).
	if !exists || po.Height < height {
		VotesEncryption2[uint8(id)] = Votes{
			Values: value,
			Height: height,
			Staked: staked,
		}
	} else {
		return errors.New("invalid height in voting, 2")
	}

	return nil
}

func ResetLastVoting() {
	VotesEncryptionMutex.Lock()
	defer VotesEncryptionMutex.Unlock()
	// AC-M5: iterate 0..255 inclusive. The previous `uint8 < 255` loop skipped
	// index 255 (and `<= 255` would wrap forever), so use an int counter.
	for i := 0; i < 256; i++ {
		delete(VotesEncryption1, uint8(i))
		delete(VotesEncryption2, uint8(i))
	}
	AfterReset = true
}

func GenerateEncryption1Data(height int64) ([]byte, [][]byte, int64) {
	valueData := make([]byte, 0)
	values := [][]byte{}
	staked := int64(0)
	toRemove := []uint8{}
	VotesEncryptionMutex.Lock()
	defer VotesEncryptionMutex.Unlock()
	for i, po := range VotesEncryption1 {

		if height <= po.Height+common.VotingHeightDistance && len(po.Values) > 0 {
			valueData = append(valueData, i)
			valueData = append(valueData, common.GetByteInt64(po.Height)...)
			valueData = append(valueData, common.BytesToLenAndBytes(po.Values[:])...)
			values = append(values, po.Values[:])
			staked += po.Staked
		} else {
			toRemove = append(toRemove, i)
		}
	}

	for _, i := range toRemove {
		delete(VotesEncryption1, i)
	}
	return valueData, values, staked
}

func GenerateEncryption2Data(height int64) ([]byte, [][]byte, int64) {
	valueData := make([]byte, 0)
	values := [][]byte{}
	staked := int64(0)
	toRemove := []uint8{}
	VotesEncryptionMutex.Lock()
	defer VotesEncryptionMutex.Unlock()
	for i, po := range VotesEncryption2 {
		if height <= po.Height+common.VotingHeightDistance && len(po.Values) > 0 {
			valueData = append(valueData, i)
			valueData = append(valueData, common.GetByteInt64(po.Height)...)
			valueData = append(valueData, common.BytesToLenAndBytes(po.Values[:])...)
			values = append(values, po.Values[:])
			staked += po.Staked
		} else {
			toRemove = append(toRemove, i)
		}
	}

	for _, i := range toRemove {
		delete(VotesEncryption2, i)
	}
	return valueData, values, staked
}

// one has to think what happens when verification is not on current block than GetStakedInDelegatedAccount should depend on height
func VerifyEncryptionForPausing(height int64, totalStaked int64, primary bool) bool {
	staked := int64(0)
	if primary {
		_, _, staked = GenerateEncryption1Data(height)
	} else {
		_, _, staked = GenerateEncryption2Data(height)
	}

	// An empty tally authorises nothing, and neither does an unmeasurable one.
	// The ratio below cannot express either case: with totalStaked at zero it
	// reads `0 < 0`, which is false, so a signature-scheme change was approved
	// on zero votes; a non-positive total makes the threshold a fraction of
	// nothing, which no tally should be able to clear.
	if staked <= 0 || totalStaked <= 0 {
		logger.GetLogger().Println("pausing not authorised - staked:", staked,
			"total staked:", totalStaked)
		return false
	}

	// 1/3 for pausing (use integer arithmetic to avoid float32 precision loss)
	if staked*3 < totalStaked {
		logger.GetLogger().Println("staked:", account.Int64toFloat64(staked), "total staked", account.Int64toFloat64(totalStaked))
		return false
	}

	return true
}

// one has to think what happens when verification is not on current block than GetStakedInDelegatedAccount should depend on height
func VerifyEncryptionForReplacing(height int64, totalStaked int64, primary bool) bool {
	staked := int64(0)
	if primary {
		_, _, staked = GenerateEncryption1Data(height)
	} else {
		_, _, staked = GenerateEncryption2Data(height)
	}

	// See VerifyEncryptionForPausing: neither an empty tally nor a non-positive
	// total can authorise anything, and the ratio alone expresses neither.
	if staked <= 0 || totalStaked <= 0 {
		logger.GetLogger().Println("replacement not authorised - staked:", staked,
			"total staked:", totalStaked)
		return false
	}

	// 2/3 for replacing (use integer arithmetic to avoid float32 precision loss)
	if staked*3 < totalStaked*2 {
		logger.GetLogger().Println("staked:", account.Int64toFloat64(staked), "total staked", account.Int64toFloat64(totalStaked))
		return false
	}

	return true
}
