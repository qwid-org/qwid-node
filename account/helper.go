package account

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/qwid-org/qwid-node/common"
	"math"
	"sync"
)

func Int64toFloat64(value int64) float64 {
	return float64(value) * math.Pow10(-int(common.Decimals))
}

func Int64toFloat64ByDecimals(value int64, decimals uint8) float64 {
	return float64(value) * math.Pow10(-int(decimals))
}

var StakingRWMutex sync.RWMutex

func IntDelegatedAccountFromAddress(a common.Address) (int, error) {
	n := binary.BigEndian.Uint16(a.GetBytes())
	if n < 1 {
		return -1, fmt.Errorf("this is not correct delegated account")
	}
	for _, b := range a.GetBytes()[2:] {
		if b != 0 {
			return -1, fmt.Errorf("this is not correct delegated account")
		}
	}
	da := common.GetDelegatedAccountAddress(int16(n))
	if bytes.Equal(da.GetBytes(), a.GetBytes()) {
		return int(n), nil
	}
	return -1, fmt.Errorf("wrongly formated delegated account")
}
