# Smart contract artefacts

`contract.sol` is the reference token used by the DEX tests. The compiled
artefacts are checked in so `go test ./blocks/` runs without solc installed:

| File | What it is |
|------|------------|
| `contract.bin` | creation bytecode — this is what a deployment transaction carries in `TxData.OptData` |
| `contract.bin-runtime` | deployed runtime code |
| `contract.abi` | ABI |

## Compiling

```sh
solc --optimize --bin --bin-runtime -o out --overwrite contract.sol
```

Default settings. No `--evm-version` flag is needed: the interpreter implements
`PUSH0` (EIP-3855), the only instruction a Shanghai target adds over the Merge
instruction set this node is built on.

That was not always true. `opPush0` existed in `core/evm/instructions.go` but was
never wired into the jump table, so `PUSH0` executed as an undefined opcode and
any contract compiled with default settings failed at deployment with
`invalid opcode: PUSH0` — on a live chain, with no hint about the cause. The
artefacts here are deliberately built with defaults so that regression is caught
by `go test ./blocks/` rather than by the first person trying to deploy.

## Token registration

`blocks.IsTokenToRegister` only treats deployed code as a token — and therefore
as tradeable on the protocol DEX — when the creation bytecode contains all five
selectors below. `contract.sol` is written to satisfy them; note that
`transfer` takes `int64`, not the ERC-20 `uint256`, so its selector differs from
the usual `a9059cbb`.

| Selector | Signature |
|----------|-----------|
| `06fdde03` | `name()` |
| `95d89b41` | `symbol()` |
| `313ce567` | `decimals()` |
| `70a08231` | `balanceOf(address)` |
| `6afd307b` | `transfer(address,int64)` |

`blocks/sc_endtoend_test.go` deploys `contract.bin` through the real interpreter
and exercises mint, transfer, the insufficient-balance revert and the
minter-only restriction, so a compiler upgrade that drops a selector or emits an
unsupported opcode fails the test suite rather than the chain.
