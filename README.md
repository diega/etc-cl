# etc-cl — a Proof-of-Work Consensus Layer

A consensus layer client that enables PoW chains to use the [Engine API](https://github.com/ethereum/execution-apis/tree/main/src/engine) for block synchronization and mining. It connects to an execution layer client as an out-of-process consensus driver.

Currently configured for **Ethereum Classic** (ETC, ChainID 61), but the architecture is chain-agnostic — only the `forks` crate carries chain-specific parameters.

## Why

Post-Merge execution layer clients removed PoW infrastructure (total difficulty tracking, ethash consensus in the beacon engine, difficulty-based fork choice). Running a PoW chain on a modern EL requires either maintaining a full parallel fork or separating consensus into an external process.

etc-cl takes the second approach: a lightweight CL that handles peer discovery, block download, PoW validation, and fork choice, then feeds validated blocks to a minimally-patched EL via the standard Engine API.

## Architecture

```
                ┌─────────────────────────────────────┐
                │             etc-cl (CL)             │
                │                                     │
  ETC peers ◄──►│  devp2p ──► sync ──► engine-api ────┼──► EL
  (eth/68)      │    │                    │           │    port 8551
                │  discv4              JWT auth       │    (authrpc)
                │  DNS-ENR                            │
                │         consensus  chain  forks     │
                │                                     │
                │         mining (optional) ──────────┼──► miners
                │                  port 8547          │    (getWork)
                └─────────────────────────────────────┘
```

The CL discovers peers via discv4 + DNS-ENR, downloads blocks over eth/68, validates headers (difficulty, ethash PoW, uncles), and submits them to the EL via `engine_newPayloadV2`. The EL executes transactions, applies mining rewards, and updates state. Fork choice is communicated via `engine_forkchoiceUpdatedV2` using heaviest-chain (max TD) selection.

### Crates

| Crate | Description |
|-------|-------------|
| `etc-cl` | Binary entry point, CLI, main event loop, peer request serving |
| `engine-api` | Engine API JSON-RPC client with JWT auth, payload/header bridge |
| `devp2p` | Full devp2p stack: ECIES transport, RLPx framing, discv4, DNS-ENR, eth/68, EIP-2124 fork filter |
| `sync` | Three-phase sync state machine (CatchUp, Pipeline, TipFollowing) |
| `consensus` | Ethash PoW verification, ETC difficulty calculation, uncle validation |
| `chain` | In-memory chain tracker with ring buffer (stateless, no persistence) |
| `forks` | Consensus-relevant fork activations and chain parameters |
| `eth-rpc` | Standard eth namespace JSON-RPC client (block/receipt/uncle fetches) |
| `serde-hex` | Shared hex serialization/deserialization modules for Ethereum types |
| `mining` | Mining coordinator: work generation, PoW verification, Stratum-style RPC |

### Stateless Design

The CL has no persistent database. Chain state is an in-memory ring buffer of the last 512 blocks (`ChainTracker`), used to derive safe (head - 24) and finalized (head - 400) hashes for FCU. On restart, the CL seeds from the EL's current head in seconds. The EL database is the single source of truth for all persisted state.

## Sync Strategy

Synchronization proceeds through three phases:

**CatchUp (EL-driven)** — The CL discovers the network's best block from peers, picks a target ~64 blocks behind the tip, and sends a `ForkchoiceUpdated` pointing to that target hash. The EL syncs to it using its own eth/68 implementation. This leverages the EL's optimized sync for the bulk of the chain. Exit: EL returns `VALID`.

**Pipeline (CL-driven)** — The CL fetches headers sequentially from one peer (192/batch), dispatches body requests to multiple peers in parallel (128/chunk), validates difficulty and ethash PoW via `spawn_blocking`, and submits blocks to the EL via `newPayloadV2` (batched). An FCU is sent every 64 blocks to anchor progress. Exit: header peer returns 0 headers.

**TipFollowing (real-time)** — The CL listens for `NewBlock` and `NewBlockHashes` from peers. Each block is individually verified and submitted to the EL. An orphan buffer handles blocks whose parent hasn't arrived yet, and the CL can fetch up to 16 ancestor headers in one request to resolve short reorgs. Accepted blocks are broadcast to other peers (full `NewBlock` to sqrt(n) peers, `NewBlockHashes` to the rest).

**Fallback:** if a peer's TD exceeds ours by more than ~1000 blocks' worth of average difficulty, TipFollowing drops back to Pipeline.

### Peer Request Serving

The CL responds to incoming `GetBlockHeaders`, `GetBlockBodies`, and `GetReceipts` requests from peers by proxying them to the EL via eth namespace RPC. This makes the node a full participant in the eth/68 network — not just a consumer. Requests are handled in spawned tasks with a concurrency limit (32 concurrent requests) to avoid overloading the EL. `GetPooledTransactions` is answered with an empty response — transaction gossip is handled entirely by the EL's own peer network.

## Engine API: Protocol Adaptations

The standard Engine API was designed for PoS. Running it for PoW required the following changes.

### Extended ExecutionPayload

Three optional fields carry PoW-specific data:

| Field | Type | Purpose |
|-------|------|---------|
| `difficulty` | `U256` (hex) | Block difficulty (absent in PoS) |
| `nonce` | `[u8; 8]` (hex) | Ethash nonce |
| `uncles` | `Vec<Header>` | Uncle headers (PoW-only concept) |

`withdrawals` is always `null` — ETC has no Shanghai fork (`ShanghaiTime: nil`).

Uncle headers use the standard `types.Header` JSON field names (`sha3Uncles`, `miner`, `mixHash`, `baseFeePerGas`).

### Field Remapping

| Payload field | PoW meaning |
|---|---|
| `prevRandao` | ethash `mixHash` (proof-of-work output) |
| `feeRecipient` | miner `coinbase` |
| `baseFeePerGas = "0x0"` | treated as `nil` by EL (pre-London blocks have no base fee) |

### Custom Method: `engine_getStatusInfoV1`

The standard Engine API has no way for the CL to learn the chain's fork schedule. This custom method returns the EL's network identity and [EIP-2124](https://eips.ethereum.org/EIPS/eip-2124) fork data:

```json
{
  "networkId": 1,
  "genesisHash": "0xd4e5...",
  "hash": "0xfc64ec04",
  "next": 0,
  "forkBlocks": [1150000, 2500000, ...]
}
```

The CL uses this to construct eth/68 `Status` messages, validate peers via EIP-2124 fork ID checksums, and reject connections from incompatible chains. **Required** — the node refuses to start without it.

### Mining Reward Delegation

Mining rewards are **not** computed by the CL. The EL detects PoW blocks (`difficulty > 0`) and applies the standard reward schedule (base reward + uncle inclusion/mining rewards) during block finalization. The CL only drives the flow: FCU with PayloadAttributes &rarr; GetPayloadV2 &rarr; seal with ethash &rarr; NewPayloadV2.

### Batch newPayload

During pipeline sync, multiple `engine_newPayloadV2` calls are sent in a single HTTP batch to reduce round-trip overhead.

## Required EL Modifications

etc-cl requires an EL that supports the following behaviors. Implementation details are left to the EL.

### Required API Surface

The CL calls the following methods on the EL. All are standard except `engine_getStatusInfoV1`.

**Engine API** (JWT-authenticated):

| Method | Usage |
|--------|-------|
| `engine_exchangeCapabilities` | Startup handshake. CL sends its capability list and verifies the EL supports `engine_getStatusInfoV1`. |
| `engine_getStatusInfoV1` | Custom method. Returns network identity and fork schedule (see below). |
| `engine_newPayloadV2` | Submit blocks for validation. Also called as a JSON-RPC batch during pipeline sync. |
| `engine_forkchoiceUpdatedV2` | Anchor fork choice. When called with `PayloadAttributes`, triggers block building for mining. |
| `engine_getPayloadV2` | Retrieve a block assembled by the EL (mining only). |

**Eth namespace** (standard HTTP RPC):

| Method | Usage |
|--------|-------|
| `eth_blockNumber` | Read current chain head number at startup. |
| `eth_getBlockByNumber` | Fetch blocks by number (startup seeding, TD lookups). |
| `eth_getBlockByHash` | Fetch blocks by hash (parent lookups, peer request serving). |
| `eth_getUncleByBlockHashAndIndex` | Fetch uncle headers for peer request serving. |
| `eth_getBlockReceipts` | Fetch receipts for peer request serving. |

The eth namespace methods are used to serve incoming `GetBlockHeaders`, `GetBlockBodies`, and `GetReceipts` requests from devp2p peers. Without them, the node can sync but cannot serve data to the network.

### 1. PoW fields in ExecutionPayload

`engine_newPayloadV2` and `engine_getPayloadV2` must handle three additional fields:

| Field | Type | Description |
|-------|------|-------------|
| `difficulty` | `QUANTITY` (hex U256) | Block difficulty. The EL must store this in the block header and use it to identify PoW blocks (`difficulty > 0`). |
| `nonce` | `DATA` (8 bytes, hex) | Ethash nonce. Stored in the block header. |
| `uncles` | `Array<Header>` | Uncle headers using standard `types.Header` JSON field names (`sha3Uncles`, `miner`, `mixHash`, `baseFeePerGas`). The EL must reconstruct the uncle list and compute `uncleHash` from them. |

The `prevRandao` payload field carries the ethash `mixHash`. `feeRecipient` carries the miner `coinbase`. `baseFeePerGas = "0x0"` must be treated as absent (pre-London blocks have no base fee). `withdrawals` is always `null`.

### 2. PoW fields in PayloadAttributes

`engine_forkchoiceUpdatedV2` with `PayloadAttributes` must accept one additional field:

| Field | Type | Description |
|-------|------|-------------|
| `uncles` | `Array<Header>` (optional) | Uncle candidates to include in the next block. Same format as `ExecutionPayload.uncles`. The EL includes these in the assembled block if they pass validation. |

This is only used during mining. Sync-only FCU calls send `PayloadAttributes = null`.

### 3. `engine_getStatusInfoV1`

A custom method the CL calls at startup to learn the chain's identity and fork schedule. Must return:

```json
{
  "networkId": 1,
  "genesisHash": "0xd4e5...",
  "hash": "0xbe46d57c",
  "next": 0,
  "forkBlocks": [1150000, 2500000, ...]
}
```

- `networkId` — the chain's network ID (used in devp2p `Status` messages)
- `genesisHash` — genesis block hash (used for peer validation)
- `hash`, `next` — current [EIP-2124](https://eips.ethereum.org/EIPS/eip-2124) fork ID
- `forkBlocks` — ordered list of all fork activation block numbers (used to construct the EIP-2124 fork filter for peer compatibility checks)

The CL refuses to start without this method.

### 4. Total difficulty tracking

The EL must accumulate total difficulty (TD) on block insertion and expose it via:

- `eth_getBlockByNumber` / `eth_getBlockByHash` — `totalDifficulty` field in the response (the CL reads this at startup to seed its chain tracker and to build the `eth/68` Status message for peers)

### 5. PoW consensus in beacon mode

When the beacon consensus engine receives a block with `difficulty > 0`, it must:

- **Apply mining rewards** — delegate block finalization to the PoW reward path (base reward, uncle inclusion rewards, uncle mining rewards, era-based reductions if applicable)
- **Validate gas limit** — use the pre-London gas limit bounds check (not EIP-1559 elasticity) for blocks before the EIP-1559 activation fork
- **Handle BaseFee=0 as nil** — when reconstructing blocks from payloads, treat `baseFeePerGas == 0` as the field being absent (pre-London blocks)

### 6. Chain config

The EL must have the target chain's fork schedule, consensus parameters, and chain ID configured. This is chain-specific and determines which EIPs/ECIPs activate at which block numbers.

---

Changes 1–3 are minimal and chain-agnostic. Changes 4–5 restore functionality removed post-Merge. Change 6 is chain-specific.

## Design Decisions

### Sync Constants

| Constant | Value | Rationale |
|----------|-------|-----------|
| `CATCHUP_OFFSET` | 64 blocks | CatchUp targets 64 blocks behind the network tip, then hands off to Pipeline. This lets the EL's optimized eth/68 sync handle the bulk of the chain while leaving a small gap for the CL to verify via pipeline. |
| `HEADER_BATCH_SIZE` | 192 | The de facto standard `GetBlockHeaders` batch size across eth/68 implementations. Larger batches reduce round-trips. |
| `BODY_CHUNK_SIZE` | 128 | Bodies are heavier than headers, so chunks are smaller. Each chunk goes to a different peer, enabling parallel body downloads across the peer set. |
| `FCU_INTERVAL` | 64 blocks | During pipeline sync, an FCU is sent every 64 blocks to anchor the EL's fork choice and commit progress. Also the batch size for `newPayloadV2` calls — after 64 blocks are submitted, the EL gets an FCU to advance its head. |
| `MAX_BUFFER_SIZE` | 2048 | Pipeline backpressure limit. If headers arrive faster than bodies, the buffer caps at 2048 to bound memory usage. At ~30KB/header this is ~60MB worst case. |
| `PIPELINE_FALLBACK_BLOCKS` | 1000 | During TipFollowing, if a peer's TD exceeds ours by more than ~1000 blocks' worth of average difficulty, the CL drops back to Pipeline. Dynamic threshold: `avg_difficulty_per_block * 1000`. |

### Chain Tracker Constants

| Constant | Value | Rationale |
|----------|-------|-----------|
| `SAFE_DEPTH` | 24 blocks | ETC mainnet has seen reorgs of 11+ blocks. The conventional 6-block threshold is insufficient; 24 gives comfortable margin against observed reorg depths. |
| `FINALIZED_DEPTH` | 400 blocks | ~87 minutes at ETC's ~13s block time. At this depth, a reorg would require sustained >50% hashrate for an extended period. This is a practical approximation of finality for Engine API consumers. |
| `RING_BUFFER_CAP` | 512 blocks | Must be ≥ `FINALIZED_DEPTH` (400) to have history for computing finalized hashes. 512 gives margin. The ring buffer is the CL's only "state" — O(1) memory, no persistence. |

### TipFollowing Constants

| Constant | Value | Rationale |
|----------|-------|-----------|
| `ORPHAN_TIMEOUT_SECS` | 60s | Orphan blocks (parent unknown) are kept for 60s while the CL tries to fetch ancestors. After that, they're evicted to prevent unbounded memory growth. |
| `REORG_ANCESTOR_LIMIT` | 16 | When resolving an orphan's ancestry, the CL fetches up to 16 headers in one request. Covers typical reorgs (1-3 blocks) with margin, without over-fetching. |
| `CATCHUP_MIN_PEERS` | 2 | CatchUp requires at least 2 available peers before syncing. The peer with the highest TD is chosen as the sync target. Each block is validated (PoW + EL newPayload) so a malicious target only wastes download time. Falls back to Pipeline with 1 peer after 30s (`CATCHUP_PEER_WAIT_SECS`). |

### Why devp2p in the CL

In post-Merge Ethereum, the CL uses libp2p and the EL handles devp2p independently. etc-cl takes a different approach: the CL runs its own devp2p/eth68 stack. This is necessary because the CL must discover, download, and validate blocks *before* the EL sees them. The EL still runs its own eth/68 network for transaction gossip and CatchUp sync.

### Why the EL Computes Mining Rewards

The CL deliberately does not implement mining reward logic. Reward schedules are complex (base reward + uncle inclusion reward + uncle mining reward) and vary across forks (e.g., ECIP-1017 era-based reduction for ETC). The EL already has this logic in its consensus engine. When the EL sees `difficulty > 0` in a payload, it delegates finalization to the PoW reward path. This avoids duplicating reward logic and ensures the EL's state transitions are authoritative.

### Why `ACCEPTED` is Valid During Sync but Not for Mining

During pipeline sync, the EL may return `ACCEPTED` instead of `VALID` for blocks whose parent hasn't been fully processed yet (async validation). The CL treats both as success during sync because blocks arrive in rapid succession and the EL may lag slightly behind. For locally mined blocks, only `VALID` is accepted — the EL built the block itself via `GetPayloadV2`, so it should be able to validate immediately. `ACCEPTED` for a mined block would indicate something is wrong.

## Limitations and Trade-offs

### Design Trade-offs

**Stateless CL, stateful EL.** The CL keeps no persistent state — it re-seeds from the EL on every restart. This eliminates crash recovery complexity and DB corruption risk, but means the CL cannot operate independently of the EL. If both crash, the EL's database is the recovery point.

**Safe/finalized are heuristic.** PoW has no protocol-level finality. The CL uses fixed depths (24 blocks for safe, 400 for finalized) as approximations. If the ring buffer doesn't cover that depth (e.g., right after startup), the CL sends `0x00...00` and the EL handles it gracefully.

**CatchUp delegates to the EL.** The first sync phase trusts the EL to sync via its own eth/68 peers. This is much faster than CL-driven sync for catching up thousands of blocks, but means the CL is idle during that phase. If the EL stalls, the CL waits.

**Single-peer header fetching.** Pipeline sync fetches headers from one peer at a time. Bodies are parallelized across multiple peers, but headers remain sequential. The CatchUp phase handles the bulk of sync, so this is acceptable.

### Validation Concessions

**Uncle validation is basic.** The CL validates uncle count (&le;2), depth (&le;7 blocks), and uncle hash integrity, but does not check for duplicate uncles across blocks. Maintaining a rolling set of recent uncle hashes would add statefulness for marginal benefit — the EL performs full validation in `newPayload`.

**MESS is fail-open.** The ECBP-1100 anti-reorg mechanism requires finding a common ancestor via EL RPC. If the ancestor lookup fails (EL error, block too deep), the reorg is allowed rather than stalling the node.

**Pipeline accepts ACCEPTED status.** During pipeline sync, the EL may return `ACCEPTED` (queued for async validation) instead of `VALID` for blocks whose parent hasn't been fully processed yet. The CL treats both as success. For locally mined blocks, only `VALID` is accepted since the EL built them and should validate immediately.

### Protocol Limitations

**No state sync from scratch.** The CL cannot bootstrap an EL with no data. The EL must handle its own state acquisition (via snap/fast sync during CatchUp, or from a pre-existing database).

**Pre-London base fee.** `baseFeePerGas = 0` is the sentinel for "no base fee" (pre-London blocks). The EL converts this to `nil` internally. This is a convention, not a protocol guarantee.

**devp2p in the CL.** Unlike PoS where the CL uses libp2p and the EL handles devp2p independently, this CL runs its own devp2p stack because it needs to fetch and validate blocks before the EL sees them. The EL still maintains its own eth/68 peer network for transaction gossip and CatchUp sync.

## Quick Start

### Prerequisites

- Rust toolchain (stable)
- A compatible EL (e.g., the patched go-ethereum fork, built with `make geth`)
- A JWT secret: `openssl rand -hex 32 > /tmp/jwt.hex`

### Run

**Terminal 1 — Execution Layer:**

```bash
geth --classic \
  --datadir /tmp/el-data \
  --authrpc.jwtsecret /tmp/jwt.hex \
  --authrpc.port 8551 \
  --http --http.port 8545 --http.api eth,net,web3
```

**Terminal 2 — Consensus Layer:**

```bash
cargo run --release -p etc-cl -- \
  --engine-endpoint http://localhost:8551 \
  --eth-endpoint http://localhost:8545 \
  --jwt-secret /tmp/jwt.hex \
  --datadir /tmp/cl-data \
  --listen 30304 \
  --dns-discovery "enrtree://AJE62Q4DUX4QMMXEHCSSCSC65TDHZYSMONSD64P3WULVLSF6MRQ3K@all.classic.blockd.info" \
  --log-level info
```

### Mining

```bash
cargo run --release -p etc-cl -- \
  --engine-endpoint http://localhost:8551 \
  --jwt-secret /tmp/jwt.hex \
  --eth-endpoint http://localhost:8545 \
  --mining \
  --mining-coinbase 0xYourAddress \
  --mining-port 8547
```

Miners connect to port 8547 using `eth_getWork` / `eth_submitWork` / `eth_submitHashrate`.

### Key Flags

| Flag | Required | Description |
|------|----------|-------------|
| `--engine-endpoint` | yes | EL Engine API URL (JWT-authenticated) |
| `--jwt-secret` | yes | Path to shared JWT secret file |
| `--eth-endpoint` | no | EL HTTP RPC (default: `http://localhost:8545`) |
| `--datadir` | no | Directory for node key and local data (default: `data`) |
| `--dns-discovery` | recommended | DNS discovery URL for peer bootstrap |
| `--bootnodes` | no | Comma-separated enode URLs |
| `--listen` | no | P2P listen port (default: 30303) |
| `--mining` | no | Enable mining mode |
| `--mining-coinbase` | if mining | Miner reward address |
| `--mining-host` | no | Mining RPC bind address (default: `127.0.0.1`) |
| `--mining-port` | no | Mining RPC port (default: `8547`) |
| `--mess-enabled` | no | Enable ECBP-1100 anti-reorg |
| `--log-level` | no | Log verbosity: `trace`, `debug`, `info`, `warn`, `error` (default: `info`) |
| `-C` / `--config` | no | Path to TOML configuration file |

CLI arguments take precedence over TOML config file values.

## Building and Testing

```bash
cargo build --release
cargo test
cargo clippy
```

## License

MIT
