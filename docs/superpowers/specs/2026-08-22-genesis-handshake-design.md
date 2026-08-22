# Genesis handshake: refuse to sync with a peer from another chain

Date: 2026-08-22
Status: approved, not yet implemented

## Problem

A node will currently sync from any peer that speaks the protocol and carries the
right `ChainID`. `ChainID` is an `int16` — for this network, 23 — so it says only
"some QWID chain", not "*this* QWID chain". Two networks started from different
genesis configs (different operator keys, different staked balances, a testnet
reset) share that number and are, to the sync service, indistinguishable.

The damage is not limited to importing foreign blocks. `case "hi"` in
`services/syncService/onmessage.go` feeds every peer's claim into
`recordPeerHeightClaim`, which drives `networkHeight()`. A peer on a longer
foreign chain therefore inflates the height this node believes the network is at,
and the stall detector rewinds the local chain chasing a height no honest peer
can serve.

## Decisions

Two questions were settled before design:

**Scope of rejection: the peer, not the node.** A genesis mismatch drops that one
peer and the node keeps running with the rest. Halting the node was rejected
because it hands any stranger a way to stop it by connecting; a permanent IP ban
was rejected because a local misconfiguration would then cut off our own healthy
nodes for good.

**Peers that send no genesis hash are rejected.** This makes the check airtight
immediately, at the cost of a network split: nodes on v0.1.2 and earlier will not
sync with upgraded ones until they are upgraded too. This is acceptable only
because every testnet node is under our control. **The rollout is therefore a
coordinated upgrade, not a rolling one** — see Rollout.

## Design

### What identifies the network

The hash of block 0, read with `blocks.LoadHashOfBlock(0)` and cached once in a
package-level variable in `services/syncService`. It never changes for the life
of the process.

It is read from the database rather than recomputed from the genesis config,
because `genesis.CreateBlockFromGenesis` is not a pure function — it calls
`storeGenesisPubKey`, which writes to the database. It cannot be used merely to
answer "what would our genesis hash be".

Availability is guaranteed by startup order: `cmd/mining/main.go` runs
`genesis.InitGenesis(true)` (line 231, when `common.GetHeight() < 0`) before
`syncServices.InitSyncService()` (line 239). By the time any sync message can be
sent or received, block 0 is in the database.

### Wire format

A new two-byte tag `GB` in the `TransactionsBytes` map of the `hi` message,
carrying the 32-byte genesis hash.

The payload is a `map[[2]byte][][]byte` whose readers pick out the keys they know
(`LH` height, `LB` last block hash, `PP` peers). An unknown key is never touched,
so adding `GB` does not change how any existing parser reads the message. The
split described above comes from the *policy* of rejecting peers that omit `GB`,
not from the encoding.

### Where the check runs

In `case "hi"`, immediately after the existing `tcpip.IsSelfIP(addr)` guard and
**before** the peer-discovery block that dials the addresses in `PP`.

The placement is the substance of this design, not a detail. Today the handler
dials every peer advertised in `PP` *before* it reads `LH`/`LB`. A check placed
next to the height logic would let a foreign-genesis peer seed our peer table
first: we would reject its height and adopt its network. The check must sit above
peer discovery.

### What happens on mismatch

1. Do not dial any peer from its `PP` list.
2. Do not call `recordPeerHeightClaim` — this is the step that otherwise inflates
   `networkHeight()` and triggers the rewind.
3. Disconnect the peer.
4. Log once per peer address, at warning level, naming both hashes. This is a
   configuration error as often as it is a stranger, and the operator needs to
   see which is which.

No ban list entry, per the decision above.

### Absent `GB`

Treated exactly as a mismatch, with a distinct log message naming the peer as
running an unsupported version, so the two causes are told apart in the log.

## Testing

Unit tests in `services/syncService`:

- a `hi` carrying our own genesis hash is processed as today: height claim
  recorded, `PP` peers considered
- a `hi` carrying a different genesis hash records **no** height claim and dials
  **no** peer from `PP` — asserted on both, since either alone leaves the hole open
- a `hi` with no `GB` key behaves as the mismatch case
- `networkHeight()` is unmoved by a rejected peer's claim

The existing `self_peer_test.go` already builds `hi` messages and asserts on
`peerHeightClaims`; these follow its shape.

## Rollout

Because peers without `GB` are rejected, an upgraded node will not sync with a
v0.1.2 node in either direction. Upgrade every node in one pass rather than
gradually, or the network partitions along version lines while both halves look
healthy from the inside.

## Out of scope

- Changing `ChainID` itself to be the genesis hash. It is `int16`, it is part of
  the signed bytes of every transaction (`transactionsDefinition/baseTransaction.go`),
  and the EVM's exposed chain id (CHAINID opcode, `core/evm/eips.go`) is a separate
  value, currently hardcoded to 1337 in `params.AllEthashProtocolChanges`, regardless
  of `ChainID`. Widening `ChainID` would invalidate every existing signature and break
  wallet tooling that requires a numeric chain id. The genesis hash belongs beside
  `ChainID` in the handshake, not inside it.
- Applying the same check to the nonce and transaction topics. Sync is where a
  foreign chain does its damage; the other topics can follow later if needed.
