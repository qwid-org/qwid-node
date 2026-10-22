# Node go QWID

![CI](https://github.com/qwid-org/qwid-node/actions/workflows/ci.yml/badge.svg)

Works for Ubuntu 24.04 and Go 1.25.13. The build toolchain is pinned in `go.mod`
(`toolchain go1.25.13`; the language floor stays at 1.23.6), so with the default
`GOTOOLCHAIN=auto` any installed Go ≥ 1.23.6 fetches 1.25.13 automatically when
building.

Only one network interface should be with external public IP

Install prerequisites

    sudo apt update
    sudo apt install librocksdb-dev
    sudo apt install libpulse-dev
    sudo apt install libzmq3-dev
    sudo apt install pkg-config
    sudo apt install build-essential
    sudo apt install qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools
    sudo apt install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind
    sudo apt install nano git
    git config --global credential.helper store

Install RocksDB:

    git clone https://github.com/facebook/rocksdb.git
    cd rocksdb
    git checkout v10.4.2
    make static_lib
    sudo make install-static
    sudo ldconfig

Install OQS library:

    git clone https://github.com/open-quantum-safe/liboqs.git
    cd liboqs/
    git checkout 0.13.0
    
Compile OQS with `-DBUILD_SHARED_LIBS=ON` and install
    
    mkdir build && cd build
    cmake -S liboqs -GNinja -DOQS_BUILD_ONLY_LIB=ON -DBUILD_SHARED_LIBS=ON ..    
    ninja
    sudo ninja install
    cd ~/

Install Go 1.25.13 if not installed (matches the toolchain pinned in `go.mod`):

    wget https://go.dev/dl/go1.25.13.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.25.13.linux-amd64.tar.gz

Add on the end of ~/.bashrc

    export PATH=$PATH:/usr/local/go/bin

reload shell:

    bash

check instalation of go

    go version

Follow instruction from https://github.com/open-quantum-safe/liboqs-go.git in order to install go wrapper to oqs. Finally

    git clone --depth=1 https://github.com/open-quantum-safe/liboqs-go

Edit: liboqs-go/.config/liboqs-go.pc

and should be like this:

    LIBOQS_INCLUDE_DIR=/usr/local/include
    LIBOQS_LIB_DIR=/usr/local/lib
    
    Name: liboqs-go
    Description: Go bindings for liboqs, a C library for quantum resistant cryptography
    Version: 0.13.0-dev
    Cflags: -I${LIBOQS_INCLUDE_DIR}
    Ldflags: '-extldflags "-Wl,-stack_size -Wl,0x1000000"'
    Libs: -L${LIBOQS_LIB_DIR} -loqs

On the end of ~/.bashrc write this line:

    export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$HOME/liboqs-go/.config
    

Reload shell and dynamic libraries

    bash
    go clean -cache
    sudo ldconfig -v | grep oqs

Clone project source code

    git clone https://github.com/qwid-org/qwid-node.git
    cd qwid-node

install go modules

    go get ./...

    mkdir -p ~/.qwid/genesis/config

Copy genesis config file ex.:

    cp genesis/config/genesis_internal_tests.json ~/.qwid/genesis/config/genesis.json

Copy env file and change accordingly.

    cp .qwid/.env ~/.qwid/.env

Edit ~/.qwid/.env

    DELEGATED_ACCOUNT= any larger rather than 5 but less than 255
    REWARD_PERCENTAGE= any value 0 <= x <= 500    500 ==> means 50% reward to operator
    NODE_IP= your external IP
    WHITELIST_IP= (optional) an IP to EXEMPT from banning and rate-limiting (it is never banned) — e.g. a trusted peer or your own monitoring host. Leave unset to enforce the limits on every peer.
    HEIGHT_OF_NETWORK= current height of network, to speed up syncing. Can be any > 1 but less than blockchain number of mined blocks

Optional node settings (leave unset for the secure defaults):

    RPC_BIND_ADDRESS= host the internal wallet<->node RPC binds to. Defaults to 127.0.0.1 (loopback only). Only set this if you deliberately run the wallet/UI on a different host than the node, and understand it exposes unauthenticated RPC operations (e.g. TRAN) to that network.
    NODE_IP_SELF_NONCE= IP used for the self-nonce connection; leave unset for the default local behaviour.


In the case you are the first who run blockchain and generate genesis block you need to set in .env: DELEGATED_ACCOUNT=1. In other case if you join to other node which is running you can choose unique DELEGATED_ACCOUNT > 1 and < 255.

Ports TCP needed to be opened:

    TransactionTopic: 19023,
    NonceTopic:       18023,
    SelfNonceTopic:   17023,
    SyncTopic:        16023,

Internal port — bound to loopback (127.0.0.1) by default and must NOT be exposed to the public network:

    19009 - wallet <-> node RPC. Loopback-only unless you override RPC_BIND_ADDRESS (see above). Keep it firewalled.

To create account and manage wallet:

    go run cmd/generateNewWallet/main.go

Run Node:

    go run cmd/mining/main.go 178.182.254.9
 
Run GUI (requires Qt5):

    go run cmd/gui/main.go

Run Web UI (alternative to Qt GUI):

    go run cmd/webui/main.go [node_ip] [port]

Examples:

    go run cmd/webui/main.go                    # connects to 127.0.0.1, serves on port 8080
    go run cmd/webui/main.go 192.168.1.100      # connects to specific node IP
    go run cmd/webui/main.go 192.168.1.100 3000 # custom node IP and port

Then open http://localhost:8080 (or your custom port) in a web browser.

Web UI Features:
- **Wallet**: Load wallet, change password, create a new wallet — note that a wallet created here has **no** 24-word recovery phrase (the phrase never travels over HTTP); its encrypted file is the only backup. See "Wallet backup & recovery" below.
- **Account**: View balances, staking details, network stats
- **Send**: Send QWD with locked amounts, multi-sig, smart contract data
- **Staking**: Stake, unstake, withdraw rewards
- **History**: View sent and received transactions
- **Details**: Search by transaction hash, address, or block height
- **Escrow**: Configure transaction delay and multi-signature settings
- **Smart Contract**: Call smart contract view functions
- **Vote**: Vote on encryption algorithm changes
- **DEX**: Trade tokens, add/remove liquidity

Press Ctrl+C to stop the web server.

Run Public Wallet Website (multi-user):

    go run cmd/website/main.go <node_ip> <port> <wallet_num>

Examples:

    go run cmd/website/main.go 127.0.0.1 9090 0

Then open http://localhost:9090 in a web browser. Users register with username+password and each gets their own wallet.

Website Features:
- **Multi-user**: Each user registers and gets a unique quantum-resistant wallet. These wallets have **no** 24-word recovery phrase (it would have to cross the network) — the server-side encrypted wallet file and the user's password are the only way back in; see "Wallet backup & recovery"
- **Dashboard**: View balance, staking, rewards, network stats, receive address
- **Send**: Send QWD to any address or delegated account
- **Staking**: Stake, unstake, withdraw rewards to any delegated account
- **History**: View sent and received transaction history
- **DEX**: Browse tokens, view pool info, buy/sell tokens, manage liquidity
- **Explorer**: Search by transaction hash, block height, or account address
- **Settings**: Change password (see "Wallet backup & recovery" below)

User wallets are stored at `~/.qwid/website/users/<username>/`. The node operator's wallet (specified via CLI args) is used for RPC message signing.

Public website deployment (security)

When running `cmd/website` on a public host, terminate TLS at a reverse proxy and set:

    BIND_ADDRESS=127.0.0.1                  # bind the HTTP listener to loopback so plaintext HTTP is never exposed directly (put TLS on the proxy). Default: all interfaces.
    TRUST_PROXY=true                        # trust the X-Forwarded-For client IP — ONLY set this when actually behind a trusted proxy, otherwise clients can spoof their IP to evade rate limits.
    CORS_ALLOWED_ORIGINS=https://your.site  # comma-separated allowlist; only these origins are reflected in CORS responses. Default: none.
    COOKIE_INSECURE=true                    # ONLY for local HTTP development. Leave unset in production so the session cookie is marked Secure.
    SMTP_USER=... SMTP_PASS=...             # optional, for email features.

The read-only `cmd/explorer` also honours `BIND_ADDRESS` (defaults to all interfaces); restrict it the same way behind a proxy.

Wallet backup & recovery

Only two creation flows produce a wallet with a recovery phrase. Which flow you
used decides what your backup is:

| Creation flow | Recovery phrase? | Your only backup |
|---|---|---|
| `go run cmd/generateNewWallet/main.go` (CLI) | **yes**, 24 BIP39 words | the phrase (plus, optionally, the wallet file) |
| Qt GUI, "Restore keys from recovery phrase" | **yes** — it restores an existing phrase | the phrase |
| Web UI (`cmd/webui`), "Create New Wallet" button | **no** | the encrypted wallet file + its password |
| Public website (`cmd/website`) registration | **no** | the encrypted wallet file + its password |
| Any wallet created before this feature existed | **no**, and never can | the encrypted wallet file + its password |

- Wallets created by the **CLI generator** are generated **from a 24-word BIP39
  recovery phrase**. The phrase is shown once, before the wallet is created, and
  you must type three of its words back to continue. Keep it offline: it derives
  every key of the wallet, for the current signature schemes and any the chain
  votes in later.
- To restore on a clean machine, run `go run cmd/generateNewWallet/main.go` and
  pick the restore option. The same phrase always rebuilds the same addresses.
  Use a **free wallet number**: the generator refuses to overwrite an occupied
  one unless you type an explicit confirmation naming that wallet number, because
  overwriting destroys the keys in that file for good.
- The phrase is only ever handled by the CLI generator and the Qt GUI. It is
  never served over HTTP, so `/api/wallet/mnemonic` returns an explanation
  instead — and, for the same reason, **wallets created through the Web UI or
  the public website have no recovery phrase at all**. Their keys are random and
  exist in exactly one place: the AES-256-GCM / Argon2id-encrypted wallet file.
  Back that file up, with its password, or the funds are unrecoverable.
- Wallets created before this change have no phrase — a post-quantum secret key
  is far too large to encode as one (CW-M2). Back up their AES-256-GCM /
  Argon2id-encrypted wallet file instead.
- If the chain votes in a new signature scheme, a wallet **with** a phrase
  derives the new key from it automatically. A wallet **without** one refuses,
  loudly, instead of minting a random replacement identity: the node keeps
  following the chain but cannot sign under the new scheme until you restore the
  wallet from a phrase or a wallet-file backup.
- Passwords must be at least 8 characters on password-change and website-registration flows.

Encryption schemes summary:

    ┌───────────────────────────┬───────┬─────────┬───────────┬────────┬─────────┐
    │          schemat          │  pk   │   sig   │ verify µs │ ver/s  │ sign µs │
    ├───────────────────────────┼───────┼─────────┼───────────┼────────┼─────────┤
    │ ML-DSA-44                 │ 1312  │ 2420    │ 10,97     │ 91 183 │ 35,6    │
    ├───────────────────────────┼───────┼─────────┼───────────┼────────┼─────────┤
    │ MAYO-2                    │ 4912  │ 186     │ 13,43     │ 74 438 │ 49,2    │
    ├───────────────────────────┼───────┼─────────┼───────────┼────────┼─────────┤
    │ ML-DSA-65                 │ 1952  │ 3309    │ 17,92     │ 55 800 │ 55,5    │
    ├───────────────────────────┼───────┼─────────┼───────────┼────────┼─────────┤
    │ Falcon-padded-512         │ 897   │ 666     │ 23,71     │ 42 178 │ 138,3   │
    ├───────────────────────────┼───────┼─────────┼───────────┼────────┼─────────┤
    │ Falcon-512                │ 897   │ 752/656 │ 23,87     │ 41 901 │ 140,0   │
    ├───────────────────────────┼───────┼─────────┼───────────┼────────┼─────────┤
    │ ML-DSA-87                 │ 2592  │ 4627    │ 26,17     │ 38 207 │ 62,9    │
    ├───────────────────────────┼───────┼─────────┼───────────┼────────┼─────────┤
    │ SNOVA_37_17_2             │ 9842  │ 124     │ 32,36     │ 30 903 │ 185,3   │
    ├───────────────────────────┼───────┼─────────┼───────────┼────────┼─────────┤
    │ SNOVA_25_8_3              │ 2320  │ 165     │ 36,98     │ 27 044 │ 163,5   │
    ├───────────────────────────┼───────┼─────────┼───────────┼────────┼─────────┤
    │ OV-Ip-pkc                 │ 43576 │ 128     │ 38,58     │ 25 924 │ 13,9    │
    ├───────────────────────────┼───────┼─────────┼───────────┼────────┼─────────┤
    │ MAYO-1                    │ 1420  │ 454     │ 44,15     │ 22 652 │ 91,4    │
    ├───────────────────────────┼───────┼─────────┼───────────┼────────┼─────────┤
    │ SNOVA_24_5_4              │ 1016  │ 248     │ 45,33     │ 22 060 │ 228,2   │
    ├───────────────────────────┼───────┼─────────┼───────────┼────────┼─────────┤
    │ OV-Is-pkc                 │ 66576 │ 96      │ 45,67     │ 21 898 │ 14,8    │
    ├───────────────────────────┼───────┼─────────┼───────────┼────────┼─────────┤
    │ Falcon-1024               │ 1793  │ 1273    │ 46,67     │ 21 429 │ 277,7   │
    ├───────────────────────────┼───────┼─────────┼───────────┼────────┼─────────┤
    │ MAYO-3                    │ 2986  │ 681     │ 94,47     │ 10 585 │ 202,3   │
    ├───────────────────────────┼───────┼─────────┼───────────┼────────┼─────────┤
    │ SNOVA_37_8_4              │ 4112  │ 376     │ 136,28    │ 7 338  │ 643,5   │
    ├───────────────────────────┼───────┼─────────┼───────────┼────────┼─────────┤
    │ MAYO-5                    │ 5554  │ 964     │ 214,33    │ 4 666  │ 467,9   │
    └───────────────────────────┴───────┴─────────┴───────────┴────────┴─────────┘

## Oracles in smart contracts

Every QWID block seals two consensus oracle values: the price, a median of
staked-node submissions verified by oracle proofs, and RAND, the block's RANDAO
value built from the producers' committed-then-revealed seeds
(`docs/oracle-randomness-limitation.md`). Smart contracts read them through two
precompiled contracts:

| Precompile | Address | Value                           |
|---|---|---------------------------------|
| Price oracle | `0x0000000000000000000000000000000000000100` | QWD/USD (raw consensus `int64`) |
| RAND oracle  | `0x0000000000000000000000000000000000000101` | consensus randomness (`int64`)  |

On testnet temporary QWD/USD is replaced by BTC/USD just to show that flow is working.

Calling convention: input is ignored; the return value is one 32-byte word
holding the value sealed in the block that contains YOUR transaction
(deterministic on every node). A value of 0 means the oracle is not
established yet (e.g. the first blocks after genesis). Each read costs a
fixed 100 gas.

Solidity example:

    function priceQWDUSD() internal view returns (uint256 price) {
        (bool ok, bytes memory out) = address(0x100).staticcall("");
        require(ok && out.length == 32, "price oracle unavailable");
        price = abi.decode(out, (uint256));
    }

    function randomness() internal view returns (uint256 rand) {
        (bool ok, bytes memory out) = address(0x101).staticcall("");
        require(ok && out.length == 32, "rand oracle unavailable");
        rand = abi.decode(out, (uint256));
    }

**Randomness warning:** the RAND value of a block is public the moment the
block exists, and the block producer sees it first. Never settle a bet with
randomness from the same block the bet was placed in — close entries at a
chosen block height and draw only in a strictly LATER block.

A complete worked example — a QWD price-direction game using both oracles with
the commit-first randomness pattern — is in `smartContracts/oracleDemo.sol`
(library `QwidOracles` + contract `BtcUpDown`). A token that the node registers
for the DEX and that uses both oracles (mint/redeem at the oracle price, a prize
draw with RAND) is in `smartContracts/oracleToken.sol`. Compile with the official
static solc release and the `paris` EVM target, exactly as the web UI does:

    solc --evm-version paris --bin --abi smartContracts/oracleDemo.sol

## Tests and CI

With the prerequisites above installed, run the test suite:

    go test ./...

If you don't have Qt5 installed, skip the Qt-based commands (`cmd/gui`,
`cmd/sendingTransaction`), which need a full Qt build toolchain:

    go test $(go list ./... | grep -vE '/cmd/gui|/cmd/sendingTransaction')

Continuous integration (`.github/workflows/ci.yml`) runs `go build`, `go vet`
and `go test` on every push and pull request to `main` and `dev`. It builds
RocksDB v10.4.2 (static) and liboqs 0.13.0 (shared) from source into a cached
prefix, sets the matching `CGO_CFLAGS`/`CGO_LDFLAGS`/`PKG_CONFIG_PATH`, and
excludes the Qt commands.

## Key recovery after a signature-scheme change

Every QWID account holds two keys of two different post-quantum signature
schemes: a primary key and a spare key. Validators can vote to **pause** a
scheme that is presumed broken and to **replace** it with a new one. A paused
scheme can no longer approve anything, so you need a key of the new scheme,
registered on chain, before you can use your account under it.

### Before anything goes wrong

1. **Create your wallet with a recovery phrase** using the CLI generator, with
   your node running:

       go run cmd/generateNewWallet/main.go [node_ip]

   It asks the node which schemes are in force (default `127.0.0.1`). Write
   the 24 words down and keep them offline: the phrase is the only backup that
   can recreate your keys for any future scheme. Wallets created in the web UI
   or on the public website have **no** phrase and cannot use the recovery
   below.
2. **Register both keys.** In the web UI, on the Send tab, tick
   **Include Public Key**: the recipient (your own address) and the amount (0)
   are filled in for you. Send once to register the first key, then once more,
   in a later block, for the second. Until both keys are registered, the
   account can send nothing else.
3. **Your recovery commitment is set automatically** with your first
   registration: a hash of a secret derived from your phrase. It becomes
   effective after 60,480 blocks (about one week). If a scheme is paused as
   broken before then, the commitment is voided and you set it again with
   your next registration. You can see it as `recoveryCommit` in the web UI's
   public-key information.

On an **escrow** account a commitment change waits for the escrow delay (and
can be cancelled during it); on a **multi-signature** account it needs the
required approvals. Only then does its one-week maturity start.

### Case 1: the primary scheme was replaced, your spare key still works

This is the usual case and needs no recovery tool. In the web UI tick
**Include Public Key** and **Register Paused public key**, then send. The key
of the new scheme is registered, signed with your working spare key.

### Case 2: none of your registered keys works any more

For example, the new scheme was un-paused before you registered its key, so
your spare is paused too. You can still register a key of the current scheme
with the recovery tool, if:

- your wallet has a recovery phrase;
- your account had an effective recovery commitment (see above);
- your account has funds for the fee;
- a node is running, with your wallet file in `~/.qwid/wallet/<N>`.

Recovery takes two transactions, at least one hour apart. Signature schemes
play no part in it: what proves ownership is the secret derived from your
phrase.

1. **Prepare.** The tool derives your new key and the recovery secret from the
   phrase and prints the bind data:

       go run cmd/recoverKey/main.go prepare -wallet <N>

2. **Bind.** Send the printed data from any funded wallet `<P>` that has both
   keys registered and a working key: yours if it still can, or a friend's or
   operator's wallet on the same machine. The bind reveals nothing about your
   secret:

       go run cmd/recoverKey/main.go bind -wallet <P> -data <hex from step 1>

3. **Wait** at least 360 blocks (about one hour) after the bind is included
   in a block.

4. **Reveal.** This registers the new key under your account, even while its
   scheme is still paused, and sets your next recovery commitment:

       go run cmd/recoverKey/main.go reveal -wallet <N>

5. **Register your second key** in the web UI as in Case 1; it is now signed
   by the key you just recovered.

All commands accept `-node <ip>` (default `127.0.0.1`) and ask for the wallet
password. Someone who copies your revealed secret from the network cannot
redirect the recovery: only the first bind counts, and it names your new key.

### Restoring a wallet from its phrase

Run the generator with your node reachable and choose "restore":

    go run cmd/generateNewWallet/main.go [node_ip]

It finds the account your phrase already owns on chain, whichever scheme its
address came from, and creates keys for the schemes currently in force.

### Limits

- A wallet without a recovery phrase cannot be recovered this way: back up
  its wallet file.
- Without an effective recovery commitment, the recovery tool cannot help:
  the account must wait until one of its registered keys works again.
- An account that never registered a key, and whose address was made from a
  key of a scheme the chain no longer uses (for example, a wallet generated
  with default schemes after the chain changed them), cannot be opened at
  present.
