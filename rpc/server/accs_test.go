package serverrpc

import (
	"testing"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/common"
	"github.com/stretchr/testify/assert"
)

// TestHandleACCSRoundTrip verifies that handleACCS finds a stake in a delegated
// account outside the old 1..4 range (here id 5) and encodes it in a form the UI
// clients decode: 4-byte little-endian count, then length-prefixed blobs of
// marshaled StakingAccount + 8-byte locked amount.
func TestHandleACCSRoundTrip(t *testing.T) {
	for i := 0; i < 256; i++ {
		account.StakingAccounts[i] = account.StakingAccountsType{
			AllStakingAccounts: make(map[[common.AddressLength]byte]account.StakingAccount),
		}
	}

	var addr [common.AddressLength]byte
	addr[0] = 0xDA
	var da [common.AddressLength]byte
	del5 := common.GetDelegatedAccountAddress(5)
	copy(da[:], del5.GetBytes())
	account.StakingAccounts[5].AllStakingAccounts[addr] = account.StakingAccount{
		StakedBalance:    common.MinStakingForNode,
		StakingRewards:   0,
		DelegatedAccount: da,
		Address:          addr,
	}

	var reply []byte
	handleACCS(addr[:], &reply)

	// Decode exactly as the UI clients do.
	if !assert.GreaterOrEqual(t, len(reply), 4) {
		return
	}
	count := int(common.GetInt32FromByte(reply[:4]))
	assert.Equal(t, 1, count, "the stake in delegated account 5 must be returned")

	b := reply[4:]
	blob, _, err := common.BytesWithLenToBytes(b)
	assert.NoError(t, err)
	if !assert.GreaterOrEqual(t, len(blob), 8) {
		return
	}
	var parsed account.StakingAccount
	assert.NoError(t, parsed.Unmarshal(blob[:len(blob)-8]))
	assert.Equal(t, common.MinStakingForNode, parsed.StakedBalance)

	pda := common.Address{}
	pda.Init(parsed.DelegatedAccount[:])
	id, err := account.IntDelegatedAccountFromAddress(pda)
	assert.NoError(t, err)
	assert.Equal(t, 5, id, "decoded delegated account id must be 5")
}
