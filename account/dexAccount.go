package account

import (
	"bytes"
	"fmt"
	"github.com/qwid-org/qwid-node/common"
)

type DexAccount struct {
	Balances   map[[common.AddressLength]byte]CoinTokenDetails `json:"balances"`
	CoinPool   int64                                           `json:"coin_pool"`
	TokenPool  int64                                           `json:"token_pool"`
	TokenPrice int64                                           `json:"token_price"`
	//TokenDetails stateDB.TokenInfo                               `json:"token_details"`
	TokenAddress common.Address `json:"token_address"`
}

type CoinTokenDetails struct {
	CoinBalance  int64 `json:"coin_balance"`
	TokenBalance int64 `json:"token_balance"`
}

func (ctb CoinTokenDetails) Marshal() []byte {
	b := common.GetByteInt64(ctb.CoinBalance)
	b = append(b, common.GetByteInt64(ctb.TokenBalance)...)
	return b
}

func (ctb CoinTokenDetails) Unmarshal(b []byte) CoinTokenDetails {
	ctb.CoinBalance = common.GetInt64FromByte(b[:8])
	ctb.TokenBalance = common.GetInt64FromByte(b[8:16])
	return ctb
}

// Marshal converts DexAccount to a binary format.
func (da DexAccount) Marshal() []byte {

	var buffer bytes.Buffer

	buffer.Write(common.GetByteInt64(da.CoinPool))
	buffer.Write(common.GetByteInt64(da.TokenPool))
	buffer.Write(common.GetByteInt64(da.TokenPrice))
	//bytesTd, err := common.Marshal(da.TokenDetails, common.TokenDetailsDBPrefix)
	//if err != nil {
	//	return nil
	//}
	//// Address length and Address
	//buffer.Write(common.BytesToLenAndBytes(bytesTd))
	// Address length and Address
	buffer.Write(da.TokenAddress.GetBytes())
	// StakingDetails count
	buffer.Write(common.GetByteInt64(int64(len(da.Balances))))

	// StakingDetails
	for addr, details := range da.Balances {
		buffer.Write(addr[:])
		buffer.Write(details.Marshal())
	}

	return buffer.Bytes()
}

// Unmarshal decodes StakingAccount from a binary format.
func (da *DexAccount) Unmarshal(data []byte) error {

	buffer := bytes.NewBuffer(data)
	// Ensure there's enough data
	if buffer.Len() < 8*3+common.AddressLength {
		return fmt.Errorf("insufficient data for dex accounts unmarshaling")
	}

	da.CoinPool = common.GetInt64FromByte(buffer.Next(8))
	da.TokenPool = common.GetInt64FromByte(buffer.Next(8))
	da.TokenPrice = common.GetInt64FromByte(buffer.Next(8))
	//toBytes, leftb, err := common.BytesWithLenToBytes(buffer.Bytes())
	//if err != nil {
	//	return err
	//}
	//
	//err = common.Unmarshal(toBytes, common.TokenDetailsDBPrefix, &(da.TokenDetails))
	//if err != nil {
	//	return err
	//}
	// Address
	copy(da.TokenAddress.ByteValue[:], buffer.Next(common.AddressLength))

	detailsCount := common.GetInt64FromByte(buffer.Next(8))
	da.Balances = make(map[[common.AddressLength]byte]CoinTokenDetails, detailsCount)
	addrb20 := [20]byte{}
	for i := int64(0); i < detailsCount; i++ {
		// Ensure there's enough data for the key and the detail count
		if buffer.Len() < 16+common.AddressLength {
			return fmt.Errorf("insufficient data for key and detail count at detail %d", i)
		}
		copy(addrb20[:], buffer.Next(common.AddressLength))
		details := CoinTokenDetails{}
		details = details.Unmarshal(buffer.Next(16))
		da.Balances[addrb20] = details
	}
	return nil
}
