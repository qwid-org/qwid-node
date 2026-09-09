package vm

import (
	"math/big"
	"sync/atomic"

	"github.com/qwid-org/qwid-node/common"
)

// QWID oracle precompiles.
//
// The chain's consensus carries two oracle values in every block header —
// PriceOracle (BTC/USD, median of staked-node submissions, verified by oracle
// proofs) and RandOracle (median-derived randomness) — but until these
// precompiles existed no smart contract could read them: the only "randomness"
// reachable from the EVM was PREVRANDAO (the parent block hash, producer-
// influenceable), and the price was not reachable at all.
//
// The evaluator (blocks/evaluate.go) calls SetQwidOracles with the CURRENT
// block's values before every EVM run, so a contract reads exactly what
// consensus sealed into the block containing its transaction — deterministic
// across all nodes. Values are held in package atomics because the
// PrecompiledContract interface is stateless (Run(input)); block application is
// serialized under common.BlockMutex, so the pair cannot tear between
// transactions of different blocks.
//
// ABI: input is ignored; the return is one 32-byte big-endian EVM word holding
// the int64 value (negative values, which consensus never produces, clamp to
// zero rather than wrapping into a huge uint256). From Solidity:
//
//	(bool ok, bytes memory out) = address(0x100).staticcall("");
//	uint256 price = abi.decode(out, (uint256)); // BTC/USD * 10^8? — the raw consensus int64
//
// NOTE for lottery-style contracts: RandOracle is public the moment the block
// exists, so it must be combined with commit-reveal or consumed from a block
// AFTER the commitment — reading it in the same transaction that placed a bet
// gives the bettor no advantage only if the bet was committed earlier.
var (
	// QwidPriceOracleAddress is 0x…0100 — far above the standard Ethereum
	// precompiles (0x01..0x09) and below nothing this fork uses.
	QwidPriceOracleAddress = common.BytesToVMAddress([]byte{1, 0})
	// QwidRandOracleAddress is 0x…0101.
	QwidRandOracleAddress = common.BytesToVMAddress([]byte{1, 1})
)

// QwidOracleGas is the fixed cost of reading an oracle value — a cheap
// in-memory read, priced like the cheapest standard precompiles.
const QwidOracleGas = 100

var (
	qwidPriceOracleValue atomic.Int64
	qwidRandOracleValue  atomic.Int64
)

// SetQwidOracles publishes the oracle values of the block whose transactions
// are about to be evaluated. Called by blocks/evaluate.go before every EVM run.
func SetQwidOracles(price, rand int64) {
	qwidPriceOracleValue.Store(price)
	qwidRandOracleValue.Store(rand)
}

// qwidOracleWord encodes an int64 oracle value as a 32-byte EVM word.
func qwidOracleWord(v int64) []byte {
	if v < 0 {
		v = 0
	}
	return common.LeftPadBytes(new(big.Int).SetInt64(v).Bytes(), 32)
}

type qwidPriceOracle struct{}

func (c *qwidPriceOracle) RequiredGas(input []byte) uint64 { return QwidOracleGas }
func (c *qwidPriceOracle) Run(input []byte) ([]byte, error) {
	return qwidOracleWord(qwidPriceOracleValue.Load()), nil
}

type qwidRandOracle struct{}

func (c *qwidRandOracle) RequiredGas(input []byte) uint64 { return QwidOracleGas }
func (c *qwidRandOracle) Run(input []byte) ([]byte, error) {
	return qwidOracleWord(qwidRandOracleValue.Load()), nil
}

// init registers the oracle precompiles in EVERY fork set this EVM can select
// (evm.precompile chooses by chain rules), and appends their addresses to the
// active-precompile lists. This init runs AFTER contracts.go's (files
// initialize in name order), so the lists built there are extended, not
// rebuilt.
func init() {
	for _, m := range []map[common.Address]PrecompiledContract{
		PrecompiledContractsHomestead,
		PrecompiledContractsByzantium,
		PrecompiledContractsIstanbul,
		PrecompiledContractsBerlin,
	} {
		m[QwidPriceOracleAddress] = &qwidPriceOracle{}
		m[QwidRandOracleAddress] = &qwidRandOracle{}
	}
	// Append the addresses only if the list-building init in contracts.go did
	// not already pick them up from the maps — file-init order is a toolchain
	// detail this must not depend on, and a duplicate here would warm the same
	// address twice in Berlin access lists.
	appendUnique := func(list []common.Address) []common.Address {
		for _, want := range []common.Address{QwidPriceOracleAddress, QwidRandOracleAddress} {
			present := false
			for _, a := range list {
				if a == want {
					present = true
					break
				}
			}
			if !present {
				list = append(list, want)
			}
		}
		return list
	}
	PrecompiledAddressesHomestead = appendUnique(PrecompiledAddressesHomestead)
	PrecompiledAddressesByzantium = appendUnique(PrecompiledAddressesByzantium)
	PrecompiledAddressesIstanbul = appendUnique(PrecompiledAddressesIstanbul)
	PrecompiledAddressesBerlin = appendUnique(PrecompiledAddressesBerlin)
}
