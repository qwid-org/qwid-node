# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

QWID-Node is a quantum-resistant blockchain node written in Go 1.23.6. It features post-quantum cryptography (Falcon-512 and MAYO-5), proof-of-synergy consensus, EVM smart contracts, staking, DEX, and voting systems.

## Build & Run Commands

```bash
# Set CGO flags (required for RocksDB on macOS - adjust paths for your system)
export CGO_CFLAGS="-isystem $HOME/local/include"
export CGO_LDFLAGS="-L$HOME/local/lib -L/usr/local/intelpython3/lib -lrocksdb -lstdc++ -lm -lz -lsnappy -llz4 -lzstd -lbz2 -lpthread -ldl"

# Install dependencies
go get ./...

# Generate a new wallet (asks the node at <node_ip>, default 127.0.0.1, which
# signature schemes are in force; without a node it falls back to the defaults,
# right only for a chain that never changed them, e.g. preparing a genesis)
go run cmd/generateNewWallet/main.go [node_ip]

# Run mining node (requires peer IP); -log enables logging, -pprof starts
# the loopback-only profiler on 127.0.0.1:6060
go run cmd/mining/main.go <peer_ip>

# Run GUI wallet (requires Qt5)
go run cmd/gui/main.go

# Run Web UI (alternative to Qt GUI)
go run cmd/webui/main.go                    # localhost:8080
go run cmd/webui/main.go <node_ip>          # custom node IP
go run cmd/webui/main.go <node_ip> <port>   # custom node IP and port

# Run Public Wallet Website (multi-user, prompts for password)
go run cmd/website/main.go <node_ip> <port> <wallet_num>
go run cmd/website/main.go 127.0.0.1 9090 0

# Run tests
go test ./...
go test ./account         # single package
go test -v ./wallet       # verbose output
```

## Required System Dependencies

- RocksDB v10.4.2 (build from source, install with `make static_lib && sudo make install-static`)
- liboqs 0.13.0 for post-quantum cryptography (release tag, not a commit)
- Qt5 for GUI (qtbase5-dev) - optional, only for GUI wallet
- ZMQ (libzmq3-dev)
- Compression libs: libsnappy, liblz4, libzstd, libbz2

## Architecture

### Core Packages

| Package | Purpose |
|---------|---------|
| `cmd/mining/` | Mining node entry point |
| `cmd/gui/` | Qt-based wallet GUI |
| `cmd/webui/` | Web-based wallet UI (HTTP server) |
| `cmd/website/` | Multi-user public wallet website (HTTP server, sessions, user registry) |
| `account/` | Account, staking, and DEX state management |
| `blocks/` | Block creation, processing, and proof-of-synergy consensus |
| `core/evm/` | Ethereum Virtual Machine implementation |
| `core/stateDB/` | Contract state persistence |
| `crypto/oqs/` | Post-quantum crypto bindings (Falcon-512, MAYO-5) |
| `database/` | RocksDB abstraction layer |
| `services/transactionServices/` | Transaction validation and P2P distribution |
| `services/syncService/` | Blockchain synchronization with peers |
| `tcpip/` | Custom P2P networking |
| `transactionsPool/` | Memory pool with Merkle tree verification |
| `wallet/` | Wallet creation, encryption, and key management |
| `rpc/` | JSON-RPC interface for wallet-node communication |
| `voting/` | Encryption scheme voting system |
| `oracles/` | Price and randomness oracles |

### Key Data Types (in `common/`)

- **Address**: 20 bytes, account identifier
- **Hash**: 32 bytes (Blake2b), used for txs/blocks/merkle
- **Signature**: Variable (Falcon-512: 752 bytes, MAYO-5: 964 bytes)

### Database Prefix System

RocksDB uses 2-byte prefixes: `BI` (blocks), `TT` (transactions), `AC` (accounts), `SA` (staking), `DA` (DEX), `PK` (public keys), `HB` (headers), `BH` (blocks by height), `EV` (EVM state snapshots, store-on-change), `HS`/`HR` (per-account sent/received tx-history index), `SC` (state commit marker: state root after a height, written last after all its snapshots; startup accepts a height only if it exists and matches the loaded state), `PJ` (pubkey registration journal, undone on rewind), `PR` (pubkey registration height - the historical key registry: block application reads keys as of the parent block via `pubkeys.*AsOf`, never the live registry; no record = height 0; a ninth byte 1 marks a voidable registration), `PB` (heights of the blocks that marked a signature scheme as broken; trimmed on rewind), `PS` (signature schemes the chain replaced, with the replacing block's height; trimmed on rewind).

State-size invariants: account snapshots must stay O(number of accounts) — per-account transaction history lives in the `HS`/`HR` index (`account/txHistory.go`) with only `SentCount`/`ReceivedCount` counters in state (a rewind restores the counters; re-applied txs overwrite the index tail). Staking detail entries older than `common.StakingDetailsRetentionBlocks` fold into one aggregate at key 0. Accounts/staking snapshots are written once per sync batch (per block on the live path), so snapshot heights have gaps — the highest stored height comes from a `prefix+"LAST"` meta key (`account/heightMeta.go`), never from contiguity-assuming search.

### Block header commitments

`BaseHeader` carries `BodyHash` (timestamp, reward percentage, supply, oracle
values and proofs) and `StateRoot` (`blocks.ComputeStateRoot`: canonical hash
of accounts, staking, DEX and EVM state **after the parent block**), both
covered by the producer's signature. Validators recompute `BlockHeaderHash`,
`BodyHash` and `StateRoot` before applying a block. Proof-of-synergy (whitepaper 3.3.3, audit 2026-11-12 F-CONS-01): the lottery
is the hash of the BLOCK NONCE, carried in `SignatureMessage` -
`blocks.NonceMessage(block second, operator, delegated account, parent's RandMix,
height)` - checked by `blocks.CheckLottery` against the difficulty in integers
(`validProof`). Nothing the producer chooses (signature, RandCommit, reward
share, transactions, embedded proofs) enters it: one ticket per account per
second. `BlockHeaderHash` and `BlockHash` exclude the header signature. A
producer stamps the earliest winning second of the last 5 s, never a future one
(`blocks.WinningSecond`); its delegated account needs the node minimum staked
for `MinNumberOfBlocksInStake` blocks (`ProducerStakeMatured`). A block's time
may be at most `MaxBlockForwardInTime` (15 s) ahead of the validator's clock on
EVERY path, sync included; live nodes hold a block from the near future until
its second and leave one stamped more than 15 s ago to sync
(`nonceService.liveAdoption`). Two blocks at one height on the same parent:
earlier second, then smaller ticket, then smaller hash (`BetterAtEqualHeight`);
sync rewinds one block to take a better competing tip. Signature-scheme votes are
counted from the signed nonces embedded in the block (`OracleProofs`) against
the parent's stake (`blocks/encryptionVote.go`). Every consensus threshold (price, pause,
replace, un-pause) divides by the stake that can vote -
`account.GetStakedInEligibleDelegatedAccounts`, the delegated accounts
`IsTop128StakingNode` admits - never by all staked coins, which counted stake
below the node minimum or outside the top 128 as a permanent vote against. Un-pausing a scheme (which
makes it active and pauses the other) additionally needs two thirds of the
stake held by operators with a key of it registered by the parent block
(`checkUnpauseKeyQuorum`), and the producer must hold one too
(`checkPauseLeavesRegisteredKey`); producers apply the same rules before
proposing (`EncryptionChangeAuthorised`). Oracle data must be exactly
the values of the embedded proofs. Producers embed only proofs whose signer still
operates its delegated account (`blocks.AuthorizedOracleProofs`): a stake that
moves operatorship would otherwise leave a stale proof in every candidate and
halt the chain. A price that cannot be established (proofs
carry at most 2/3 of the stake) is the parent's carried forward, never 0. The price is the STAKE-weighted median of the embedded
submissions (`oracles.stakeWeightedMedian`, audit 2026-11-12 F-CONS-02; at an
exact half split, the midpoint of the two prices) - each delegated account no
longer counts once, which let a few minimum-stake accounts set the price.

RAND is a RANDAO accumulator (`blocks/randao.go`, S4-06), not the validators'
proposals: each block carries its producer's `RandReveal` (the seed behind the
commitment it made in its previous block, required while that is younger than
`RandaoCommitExpiry`), a new `RandCommit`, and `RandMix` = hash of the parent's
mix, the height and the reveal; `RandOracle` derives from `RandMix`. The live
commitment is staking state (`StakingAccount.RandCommit/RandCommitHeight`,
in the state root). Seeds are derived, never stored: `wallet.RandaoSeed(height)`
from the BIP39 seed (or the primary secret key). `RandOracleData` must be empty
and the nonce's rand slot is zero and ignored.

P2P frames are length-prefixed: `MessageInitialization || uint32 BE length ||
body` (`tcpip.encodeFrame` / `frameAssembler`), never delimiter-based.

### Dual Signature System

Transactions use two post-quantum signature schemes:
1. Primary: Falcon-512 (pub: 897B, sig: 752B)
2. Secondary: MAYO-5 (pub: 5554B, sig: 964B)

### Concurrency Patterns

- RWMutex protects account/state maps
- Package-level singletons: `account.Accounts`, `common.IsSyncing`
- Services run as background goroutines
- P2P messages routed via channels

### Network Ports

Open these TCP ports: 19023 (transactions), 18023 (nonce), 17023 (self-nonce), 16023 (sync)

Internal ports (localhost only): 19009 (wallet-node RPC), 8000 (Qt requirements)

### Genesis handshake

Sync peers exchange their genesis block hash in the `hi` message under the `GB`
tag, and a node refuses to sync with a peer whose hash differs — the peer is
dropped, its advertised peers are not dialled, and, most importantly, its height
claim is not recorded (an unrecorded claim cannot inflate `networkHeight()` and
send the stall watchdog rewinding the chain).

The genesis block's `StateRoot` holds `GenesisConfigDigest` - a hash of the
whole `genesis.json` minus its signature (consensus parameters, staking
allocation, genesis transactions) - so the genesis hash, and with it `GB`,
differs whenever two nodes' genesis configs differ in any byte.

`ChainID` (int16, 23) is checked one layer down in `message.BaseMessage`, but it
only says "some QWID chain": two networks started from different genesis configs
share it. `ChainID` cannot itself be widened to the genesis hash — most
importantly, it is part of the signed bytes of every transaction
(`transactionsDefinition/baseTransaction.go`), so changing its width invalidates
every existing signature. The EVM's CHAINID opcode answers the same number
(`blocks.evmChainConfig`, S6-06; it used to be the development id 1337). The EVM
runs the Merge instruction set and `params.Rules` reports every fork through
the Merge as active, matching it.

**A peer that sends no `GB` tag is rejected in the `hi` sync message.** The
genesis check does not run in other sync message types (`gh`, `sh`
at `services/syncService/onmessage.go`), so only the `hi` path is guarded. Nodes
running v0.1.2 or earlier will not sync via `hi` with upgraded ones, but might
exchange other sync messages if an upgraded node initiates them. Upgrade every
node in one pass; a gradual rollout partitions the network along version lines
while both halves look healthy from the inside.

The `GB` tag is unauthenticated and a genesis hash is public, so this guards
against accidents and misconfiguration (a testnet reset, the wrong
`genesis.json`) rather than a deliberate attacker, who can simply echo back
whatever hash we send. A rejection is logged at most once per peer address
per ten minutes (`shouldLogRejection` in `onmessage.go`), with a `WARNING:`
prefix — otherwise `hi`'s roughly-once-a-second broadcast, combined with the
peer reconnecting after every drop, would log the same rejection forever.

## Configuration

Runtime config in `~/.qwid/.env`:
```
DELEGATED_ACCOUNT=1          # Staking account (1-254, use 1 for genesis node)
REWARD_PERCENTAGE=200        # Operator reward (0-500, where 500=50%)
NODE_IP=<your_external_ip>
WHITELIST_IP=<optional_ip>   # IP to EXEMPT from banning/rate-limiting (never banned)
BLACKLIST_IP=<optional_ips>  # Comma-separated IPs to PERMANENTLY ban (no inbound/outbound/discovery connections; overrides whitelist)
HEIGHT_OF_NETWORK=<current_height>  # Sync target while the local chain is BELOW it: this value
                                    # overrides the height derived from peers. Once the local
                                    # height reaches it, the live peer view takes over
                                    # (common.GetSyncTarget / IsBehindNetwork), so a stale value
                                    # cannot pin the target below the real network height. Set it
                                    # at or above the true network height - a value that is too
                                    # low lets the node declare itself synced early and fork.
                                    # Peer height claims up to this value also count as
                                    # operator-confirmed: they skip the multi-peer consensus
                                    # throttle in shouldSyncToHeight, so a node with a single
                                    # peer syncs toward it at full speed (blocks are still
                                    # fully verified).
COMPRESS_BX=true             # Optional, default OFF. Enables flate compression of large bx sync answers (sent as
                             # bz messages) on the SERVING node; receivers always understand bz. ~25% fewer wire
                             # bytes for a few ms CPU per answer.
MIN_PEERS_FOR_LARGE_SYNC=3   # Optional, integer >= 1, default 3. How many live peers must confirm a large height
                             # claim before syncing straight to it (claims within HEIGHT_OF_NETWORK skip the check).
                             # The effective quorum is capped at the number of actually connected sync peers, so a
                             # two-node network syncs at full speed with the default; set 1 to always trust a single
                             # peer's claim (blocks are fully verified regardless — this only rate-limits sync).
RPC_BIND_ADDRESS=<host>      # Optional. wallet<->node RPC bind host; default 127.0.0.1 (loopback only, NP-C4). Override only if wallet/UI runs on a different host — exposes unauthenticated RPC (e.g. TRAN).
NODE_IP_SELF_NONCE=<ip>      # IP the node uses to connect to ITSELF on the self-nonce topic (port 17023).
                             # UNSET DOES NOT MEAN LOOPBACK: it falls back to NODE_IP, i.e. the node dials its
                             # own EXTERNAL address (tcpip/recieverTcpService.go:90). That only works where the
                             # router supports hairpin NAT. Behind CGNAT — mobile internet in particular — the
                             # connection can never be made and the node never receives its own nonce. Set it to
                             # 127.0.0.1 on any host that cannot reach its own public address.
```

Service/web env vars (read by `cmd/website` / `cmd/explorer` handlers, not from `.env`):
```
BIND_ADDRESS=127.0.0.1               # HTTP listener bind host; default all interfaces. Set loopback behind a TLS reverse proxy (WH-M6/M12).
TRUST_PROXY=true                     # Trust X-Forwarded-For only when behind a trusted proxy (else clients spoof IPs past rate limits).
CORS_ALLOWED_ORIGINS=<origins>       # Comma-separated allowlist; only these origins are reflected. Default: none.
COOKIE_INSECURE=true                 # Local HTTP dev only; unset in prod so the session cookie is Secure.
SMTP_USER / SMTP_PASS                # SES SMTP credentials (IAM, not an email address). Without them the contact form returns 503.
SMTP_HOST=<ses-endpoint>             # Default email-smtp.us-east-1.amazonaws.com (N. Virginia, matches the domain MX). Region-specific — SES SMTP credentials are not portable between regions.
SMTP_PORT=587                        # Default 587 (STARTTLS).
CONTACT_TO=support@qwid.org          # Where the contact form delivers.
CONTACT_FROM=support@qwid.org        # Envelope + From: sender. MUST be an identity verified in SES, or SES rejects the message. Never SMTP_USER — the visitor's address goes in Reply-To.
```

Security defaults from the remediation: the wallet<->node RPC binds loopback-only (port 19009, keep firewalled); password minimum is 8 chars on password-change, website-registration and CLI wallet-generator flows. Gas: the EVM runs on exactly the declared gas; `MinGasUsage()` is the validation floor (DEX ops include `DexTokenCallGas`), `GasUsageEstimate()` is what wallets declare (10x the floor for contract calls/deploys, capped at `MaxGasUsage`). The web UI session idles out after 30 min (`POST /api/logout` ends it). Signed RPC requests carry a replay guard (time + nonce, `common.NewRPCGuard`) between the request and the signature; the node accepts each guard once, within 60 s of its clock — build requests only through `wallet.SignRPCRequest`. The node refuses (RPC `TRAN`, `checkOperatorIntent`) a local stake flagged "Intend to be an Operator" into any delegated account other than its own `DELEGATED_ACCOUNT` - the largest operational stake becomes the operator, so such a stake takes the account from the node producing for it; a local guard, not consensus. DEX arithmetic is in whole base units, never floats (`blocks/dexMath.go`, audit 2026-11-12): a buy of d tokens pays `ceil(coinPool*d/(tokenPool-d))`, a sell receives `floor(coinPool*d/(tokenPool+d))`, so `coinPool*tokenPool` never decreases; an order the pool cannot price (empty side, whole-pool buy, result beyond int64) is skipped. `DexAccount.TokenPrice` is coin base units per ONE WHOLE token (price x 10^8, saturating; it used to be price x 10^(8+token decimals)) and is informational - trades are computed from the pools. Contract return words are read in full (`common.Int64FromSCWord`); a token balance beyond int64 fails the order, and a token declaring more than `blocks.MaxTokenDecimals` (18) decimals is not registered for the DEX. DEX buy/sell orders may carry a signed coin limit (`transactionsDefinition.DexOrderOptData`, OptData 16 bytes); an order whose limit the trade would break is skipped (fee paid), not a block error. Check/apply parity (audit 2026-11-12 full, F-TX-03/04): a transaction that passes `CheckBlockTransfers` must not fail in `ProcessTransaction` - a failure there invalidates a block every node already received, at no cost to the sender. So: a negative `Amount` is valid only as an unstake (delegated account 1..255) or a reward withdrawal (256..511); the owner's stake/unstake rules live in one place, `account.StakeChangeRefusal` (pacing, locks, non-zero amount), used by the block check and by `Stake`/`Unstake`, and a second own staking operation of one sender in a block is refused by the check; a multisig approval of nothing / of an expired main transaction, a multisig settlement the account can no longer pay, and an escrow/multisig policy change that cannot apply are NOT block errors - the transaction stays, its fee paid, without effect; a DEX order must leave the sender's other spend of the block covered (`blockReservedSpend`) or it is skipped. When adding a rule to `ProcessTransaction`, add it to the check too or make its failure non-fatal. An escrow or multisig account cannot pay a locked stake into another account (`thirdPartyLockRefusal`, F-TX-01): that moved its coins at once, past the delay and the approvals. Token templates (`smartContracts/contract.sol`, website, webui) require `amount > 0` in `transfer` and `mint` - balances are `int64` and a negative transfer took the receiver's tokens (F-SC-01); tokens deployed from the old template stay vulnerable. A sync `sh` batch must list consecutive ascending heights (`batchIndicesConsecutive`, F-SYNC-01). EVM runs use one interpreter configuration (`blocks.evmExecutionConfig`) with KECCAK256 preimage recording OFF; preimages are not part of EVM snapshots (F-EVM-01, they grew the state 69 MB per cheap transaction). The per-identity key limit (`MaxKeysPerIdentity`) is checked in `Verify` and, counting the block's own registrations, in `CheckBlockTransfers`. A key bound to ANOTHER identity yields to a registration signed with that key itself (self-registration, committed spare, recovery reveal) and is never taken by one vouched for by another key (`Verify` refuses it; in the same block `registerPubKey` drops it); a takeover is journalled (`takeoverMark`) and undone on rewind (F-KEY-01). The escrow and multisig pools are chain state: local bans do not apply to them, and a persisted entry reloads when its signed original is in the confirmed DB, without re-verifying its signature (F-POOL-02); a transaction its block would hold in a full pool is refused by the block check (`heldPoolOf`, `FreeSlots`, F-POOL-01). An embedded oracle proof signed with the PRIMARY scheme does not count when the containing block's parent has the primary paused (`proofPauseFlags`; producers filter with `AuthorizedOracleProofs(proofs, lastBlock)`); the secondary is never gated (F-CONS-06).

Recovery phrases — exactly which flows produce one:
- **CLI generator** (`go run cmd/generateNewWallet/main.go [node_ip]`): creates a wallet **from** a fresh 24-word BIP39 phrase (shown once, three words typed back to confirm), and restores a wallet from an existing phrase. The phrase is read without echo and stored encrypted in the wallet file.
- **Qt GUI** (`cmd/gui`): restores from a phrase, and displays the stored phrase after the wallet password is re-entered (WH-C5).
- **Web UI** (`cmd/webui` "Create New Wallet") and **public website** (`cmd/website` registration): create wallets with **random** keys and **no** recovery phrase — the phrase must never cross HTTP (design decision 3). The encrypted wallet file plus its password is the only backup, and both handlers say so in their creation response.
- Wallets created before this feature have no phrase and never can, since a post-quantum secret key cannot be encoded as one (CW-M2) — back up their encrypted wallet file instead.
- Public-key registration has exactly ONE channel: a transaction carrying the pubkey (`TxData.Pubkey`), signed with that key and sent **manually** by the operator; `ProcessBlockPubKey` registers it on every node when its block is applied. Nothing self-registers and nonce transactions never carry keys. After a voted scheme change the node derives its new key and logs an operator instruction. Nonces and block headers are signed only with a registered key of a live scheme (`services.SigningSlot`); a node holding none sends no nonces and produces no blocks, but keeps following the chain - an unverifiable signature would read as a forgery and get it banned.
- **Spare rule (consensus, from height 0; replaced the dual-key rule):** until an identity has a way out of a broken scheme - a commitment to its spare key's ADDRESS (`SpareCommit`, in force or pending) or both a primary and a secondary key registered (validators keep the latter: they must sign at once when the primary is paused) - the only transaction it may send is a key registration (`Transaction.IsKeyRegistration`). Publishing both keys up front widened the attack surface for nothing: the spare's public key now stays unpublished until needed. Opening an account is ONE registration: the key the address comes from (of a live scheme), `Recipient` = `common.RecoveryCommitAddress` (the explicit marker, audit 2026-11-12 P-05), `OptData` = the spare key's address (20 bytes) followed by the recovery commitment C (20 bytes, absent without a phrase) - build it with `transactionsDefinition.CommitmentRegistration`; the commitments that OPEN an account apply at once - opening means no key of the identity was registered by the parent block (`blocks.opensAccount`). An identity that already published a key gets no such shortcut, even for its first commitments: they mature like any change (audit 2026-11-12 P-02). **Committed spare:** a pure registration of exactly the key whose address was committed, signed by that key itself, is authorised by the match (pause-exempt) - the way out when the identity's registered key belongs to a paused scheme. **A paused scheme authorises no new key** otherwise: its signature is what a forger makes. **Voidable keys (consensus, audit 2026-11-12 P-01):** a key that joins an identity on ANOTHER key's signature is marked voidable (`blocks.keyRegistrationVoidable`); a block that marks a scheme as broken (`blocks.schemeBroken`) voids every such key registered less than `RecoveryCommitMaturityBlocks` before it (`pubkeys.VoidedAsOf`) - the signature may have been forged, exactly the reasoning that voids unmatured commitments. Never voidable: the key that derives the identity, a key registered by a recovery/address reveal, and the committed spare. A voided key stays in the address list but no `*AsOf` reader returns it (`pubkeys.LoadAddresses` alone is raw); it can be registered again through a path that needs no broken signature. So a validator should commit to its spare's address when opening its account, or register the spare more than a maturity period before any pause - a spare registered later by the primary's signature does not outlive a pause of that primary, and the pausing block's producer must hold one that does (`checkPauseLeavesRegisteredKey`). The former stranded-identity escape hatch let a forger attach its own spare to a victim and was removed. The only other pause exemption is an UNPUBLISHED key registering itself. A wallet created while the primary is paused takes its address from the LIVE scheme's key (`Wallet.SetMainAddressFromLiveScheme`, webui, website and CLI generator, which reads the schemes from the node); the webui refuses a first registration from a paused scheme (`planRegistration`). Wallets mirror the rules in `wallet.SendRefusal`. Nodes sign nonces and headers only with THEIR OWN key registered in a live slot (`services.SigningSlot` compares key bytes: Falcon-512 and Falcon-padded-512 share a key length). In genesis, the operator's spare comes from `operator_pub_key_2` (optional, `omitempty`) and/or `pub_key_2` of its staking entry (`storeGenesisSecondaryKey`).
- **Recovery commitment (hash-only key recovery):** a key registration sent to `common.RecoveryCommitAddress` sets the identity's commitments (P-05: an explicit marker - no other transaction does, and nothing else may be sent there): `OptData` = spare key address (20 bytes) ‖ recovery commitment `C = H160(S_n)` (20 bytes, optional), where `S_n = H(seed ‖ main address ‖ n)` comes from the BIP39 phrase (`wallet.RecoverySecret`; never from secret keys, never stored). The latest commitment wins but matures only after `RecoveryCommitMaturityBlocks`, and a block that marks a scheme as broken (pausing the live primary, or replacing the spare; `blocks.schemeBroken`) voids unmatured ones - including changes still held in the escrow or multisig pool (`blocks.voidHeldCommitmentRegistrations`, P-04; journalled, so a rewind returns them) - replacing an already-paused primary or un-pausing does not, so commitments set with the live spare right after a break survive the changes that follow it. A paused scheme can never set one. A commitment change is held like a transfer: from an escrow account it takes effect only when the escrow delay ends (cancellable until then), from a multisig account only once approved; its maturity counts from that settlement (`blocks.settleCommitment`). A reveal is never held - its authority is the phrase-derived secret, and an escrow cancellation could be signed by whoever broke the identity's schemes. Recovery runs in two phases, neither of which needs a working signature scheme of the identity:
  1. **bind** to `common.RecoveryBindAddress` from any funded account: `identity ‖ tag(S) ‖ H(identity ‖ newKey ‖ nextC ‖ S)`. Binds are keyed by (identity, tag, payload) (`common.RecoveryBindKey`, audit 2026-11-12 P-03): the tag is public in the mempool, so a bind copied with another payload sits beside the owner's instead of blocking it, and the reveal looks up the bind with exactly its own payload. A repeated bind keeps the first (its age cannot be reset). Someone who learns S from a reveal in the mempool can make a valid bind, but it is `RecoveryBindDelayBlocks` from being usable and the owner's reveal consumes the commitment first.
  2. **reveal** to `common.RecoveryRevealAddress` from the identity, signed by the new key (pause-exempt): `S ‖ nextC` plus the new pubkey. It is valid once the bind is at least `RecoveryBindDelayBlocks` old.
  The reveal registers the key and installs `nextC` immediately. **Address opening** (`Transaction.IsAddressReveal`, OptData longer than 52 bytes: `next ‖ spare ‖ LB(oldScheme) ‖ LB(oldPub) ‖ LB(oldSig)`): an account with NO registered key and no commitments is opened by revealing the key its address is the hash of, with that key's signature over `common.AddressOpenMessage` (checked by scheme name through liboqs; the scheme must be one in force or one the chain retired - `pubkeys.SchemeRetiredAsOf`, record `PS`, P-08 - never an arbitrary liboqs scheme) and a matured bind keyed by `tag(oldPub)`; it registers a new key and sets both commitments at once. `recoverKey prepare` picks this mode by itself. Commitments and binds live in `account.Accounts` (snapshotted, in the state root). CLI: `cmd/recoverKey prepare|bind|reveal`.
- A phrase-less wallet meeting a chain-voted signature-scheme change **refuses** to generate a replacement key, on both the load path (`loadWalletFromStruct`) and the live path (`AddNewEncryptionToActiveWallet`), rather than silently replacing its staked identity with a random one. Block processing continues; the node just cannot sign under the new scheme until the operator restores the wallet.
- The CLI generator refuses to overwrite an occupied wallet number in either mode unless the operator types a confirmation naming that wallet number.

Genesis config: `~/.qwid/genesis/config/genesis.json` (copy from `genesis/config/genesis_internal_tests.json`)

## Network Constants

- Chain ID: 23
- Block interval: 10 seconds
- Max transactions per block: 5000
- Max transaction pool: 50,000
- Max gas per block: 13,700,000
- Max peers: 6
- Decimals: 8
- Minimum staking for node: 100,000,000,000,000 (1,000,000 QWD with 8 decimals)
- Minimum staking for user: 100,000,000,000 (1,000 QWD with 8 decimals)
- Oracles update interval: every 6 blocks (~1 minute)
- Voting window: every 60 blocks (~10 minutes)
- Max transaction delay (escrow): 60,480 blocks (~1 week)

## Commit Convention

Use task identifiers in commits (e.g., `OB-55 description`).
