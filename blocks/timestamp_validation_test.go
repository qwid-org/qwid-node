package blocks

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wonabru/qwid-node/common"
)

func timestampBlock(height, timestamp int64) Block {
	return Block{BaseBlock: BaseBlock{
		BaseHeader:     BaseHeader{Height: height},
		BlockTimeStamp: timestamp,
	}}
}

func TestValidateBlockTimestampFutureLimit(t *testing.T) {
	now := common.GetCurrentTimeStampInSecond()
	parent := timestampBlock(100, now-1)

	assert.NoError(t, validateBlockTimestamp(timestampBlock(101, now+common.MaxBlockForwardInTime), parent, true))
	assert.Error(t, validateBlockTimestamp(timestampBlock(101, now+common.MaxBlockForwardInTime+2), parent, true))
}

func TestValidateBlockTimestampHistoricalCheckIgnoresWallClock(t *testing.T) {
	parent := timestampBlock(100, 1_000)
	assert.NoError(t, validateBlockTimestamp(timestampBlock(101, 1_010), parent, false))
}

// After a chain halt longer than MaxBlockTimeInterval (node restart, network
// outage) the only block a producer can build is stamped with the current time,
// which is necessarily more than MaxBlockTimeInterval after its parent. Bounding
// that gap on its own bricks the chain permanently: no successor is ever valid
// again. A gap that stays within the wall clock must be accepted.
func TestValidateBlockTimestampAcceptsGapAfterChainHalt(t *testing.T) {
	now := common.GetCurrentTimeStampInSecond()
	parent := timestampBlock(100, now-common.MaxBlockTimeInterval-3_000)

	assert.NoError(t, validateBlockTimestamp(timestampBlock(101, now), parent, true))
}

// The same relaxation must hold on the sync path, otherwise a node replaying the
// chain from genesis rejects the block that restarted it after the outage.
func TestValidateBlockTimestampAcceptsGapAfterChainHaltWhenSyncing(t *testing.T) {
	parent := timestampBlock(100, 1_000)

	assert.NoError(t, validateBlockTimestamp(timestampBlock(101, 1_000+common.MaxBlockTimeInterval+3_000), parent, false))
}

// A large gap that also claims a time the wall clock has not reached is still
// rejected — including on the sync path, where the "too far in future" rule is
// otherwise skipped.
func TestValidateBlockTimestampRejectsGapIntoTheFuture(t *testing.T) {
	now := common.GetCurrentTimeStampInSecond()
	parent := timestampBlock(100, now-1)

	assert.Error(t, validateBlockTimestamp(timestampBlock(101, now+common.MaxBlockTimeInterval), parent, false))
}
