# Node go QWID

Works for Ubuntu 24.04 (gcc 11) and go1.23.6+

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
    git checkout v10.2.1
    make static_lib
    sudo make install-static
    sudo ldconfig

Install OQS library:

    git clone https://github.com/open-quantum-safe/liboqs.git
    cd liboqs/
    git checkout 8ee6039 
    
Compile OQS with `-DBUILD_SHARED_LIBS=ON` and install
    
    mkdir build && cd build
    cmake -S liboqs -GNinja -DOQS_BUILD_ONLY_LIB=ON -DBUILD_SHARED_LIBS=ON ..    
    ninja
    sudo ninja install
    cd ~/

Install go1.23.6 if not installed:

    wget https://go.dev/dl/go1.23.6.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.23.6.linux-amd64.tar.gz

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

    git clone https://github.com/wonabru/qwid-node.git
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
- **Wallet**: Load wallet, change password (see "Wallet backup & recovery" below — mnemonic backup is not available for post-quantum keys)
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
- **Multi-user**: Each user registers and gets a unique quantum-resistant wallet
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

- Post-quantum secret keys (Falcon-512 / MAYO-5) are far larger than a BIP39 mnemonic can encode, so **the mnemonic-phrase backup is not available** for real wallets — requesting it returns a clear error directing you here.
- Back up the **encrypted wallet file** instead. Node/CLI/GUI wallets live under `~/.qwid/`; website user wallets under `~/.qwid/website/users/<username>/`. The file is AES-256-GCM encrypted with an Argon2id-derived key from your password — keep a copy of the file and remember the password.
- Passwords must be at least 8 characters on password-change and website-registration flows.

