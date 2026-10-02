package blocks

import (
	"math/big"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/params"
)

// evmChainConfig is the EVM configuration of this chain: every protocol change
// of AllEthashProtocolChanges, with the CHAINID opcode answering the QWID chain
// id instead of that config's 1337 (S6-06). With 1337, EIP-712 signatures and
// any contract replay protection could not tell QWID from every other chain
// using the development id.
func evmChainConfig() *params.ChainConfig {
	c := *params.AllEthashProtocolChanges
	c.ChainID = big.NewInt(int64(common.GetChainID()))
	return &c
}
