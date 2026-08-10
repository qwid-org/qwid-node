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

# Generate a new wallet
go run cmd/generateNewWallet/main.go

# Run mining node (requires peer IP)
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

- RocksDB v10.2.1 (build from source, install with `make static_lib && sudo make install-static`)
- liboqs (commit 8ee6039) for post-quantum cryptography
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

RocksDB uses 2-byte prefixes: `BI` (blocks), `TT` (transactions), `AC` (accounts), `SA` (staking), `DA` (DEX), `PK` (public keys), `HB` (headers), `BH` (blocks by height), `EV` (EVM state snapshots, store-on-change), `HS`/`HR` (per-account sent/received tx-history index).

State-size invariants: account snapshots must stay O(number of accounts) — per-account transaction history lives in the `HS`/`HR` index (`account/txHistory.go`) with only `SentCount`/`ReceivedCount` counters in state (a rewind restores the counters; re-applied txs overwrite the index tail). Staking detail entries older than `common.StakingDetailsRetentionBlocks` fold into one aggregate at key 0. Accounts/staking snapshots are written once per sync batch (per block on the live path), so snapshot heights have gaps — the highest stored height comes from a `prefix+"LAST"` meta key (`account/heightMeta.go`), never from contiguity-assuming search.

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
RPC_BIND_ADDRESS=<host>      # Optional. wallet<->node RPC bind host; default 127.0.0.1 (loopback only, NP-C4). Override only if wallet/UI runs on a different host — exposes unauthenticated RPC (e.g. TRAN).
NODE_IP_SELF_NONCE=<ip>      # Optional. IP for the self-nonce connection; unset = default local behaviour.
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

Security defaults from the remediation: the wallet<->node RPC binds loopback-only (port 19009, keep firewalled); password minimum is 8 chars on password-change and website-registration flows.

Recovery phrases — exactly which flows produce one:
- **CLI generator** (`go run cmd/generateNewWallet/main.go`): creates a wallet **from** a fresh 24-word BIP39 phrase (shown once, three words typed back to confirm), and restores a wallet from an existing phrase. The phrase is read without echo and stored encrypted in the wallet file.
- **Qt GUI** (`cmd/gui`): restores from a phrase, and displays the stored phrase after the wallet password is re-entered (WH-C5).
- **Web UI** (`cmd/webui` "Create New Wallet") and **public website** (`cmd/website` registration): create wallets with **random** keys and **no** recovery phrase — the phrase must never cross HTTP (design decision 3). The encrypted wallet file plus its password is the only backup, and both handlers say so in their creation response.
- Wallets created before this feature have no phrase and never can, since a post-quantum secret key cannot be encoded as one (CW-M2) — back up their encrypted wallet file instead.
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
