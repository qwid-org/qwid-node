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
