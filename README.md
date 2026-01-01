# Performance Evaluation of Blockchain-Based Security Logging for Advanced Air Mobility Systems

Empirical comparison of **PostgreSQL (hash-chained)**, **Hyperledger Fabric (permissioned blockchain)**, and **Solana (public blockchain)** for tamper-evident security-event logging in Advanced Air Mobility (AAM) systems — eVTOLs, UAVs, and urban airspace operations.

> ### TL;DR
>
> Can a blockchain keep a **tamper-proof security log** for flying taxis and drones — and still be fast enough to raise real-time alerts? We replayed **157,501 real UAV cyberattack events** through three systems and timed every write.
>
> | System | P95 latency | Verdict |
> |---|---|---|
> | **PostgreSQL** (hash-chained DB) | **1.39 ms** | Fast enough for real-time **and** audit |
> | **Hyperledger Fabric** (permissioned) | **2,182 ms** · 22× slower | Audit trails only |
> | **Solana** (public chain) | **15,157 ms** · 152× slower | Too slow for either |
>
> **Bottom line:** blockchain can't hit the **<100 ms** real-time bar — but its multi-party trust is worth it for audit. So use **both**: PostgreSQL for live alerts, with a periodic blockchain *anchor* for tamper-proof, multi-party-verifiable audit (the [hybrid architecture](#recommended-hybrid-architecture)).
>
> <sub>Numbers are from a real run on **2025-12-19** (Apple M2). See [Experiment Design](#experiment-design) for how, and [Where the numbers come from](#where-the-numbers-come-from) for the data.</sub>

---

## What Are We Doing Here?

AAM is multi-stakeholder by nature — operators, regulators (FAA/EASA), vertiport managers, and insurers all need **tamper-evident** logs of security events (GPS spoofing, DoS, replay…), but **no single party should control the audit log**. Blockchain solves the trust problem but adds latency. This repo quantifies that trade-off end-to-end.

```mermaid
flowchart TB
    subgraph SRC["AAM / UAV Security Events"]
        direction LR
        E1["GPS Spoofing"]
        E2["GPS Jamming"]
        E3["DoS / De-auth"]
        E4["Replay"]
        E5["MITM"]
        E6["Evil Twin"]
    end

    SRC --> PARSER["Rust Data Parser<br/>normalize to SecurityEvent"]

    PARSER --> PG[("PostgreSQL<br/>Hash-Chained Log")]
    PARSER --> HLF{{"Hyperledger Fabric<br/>Permissioned"}}
    PARSER --> SOL{{"Solana<br/>Public"}}

    PG -->  R1["P95 1.39 ms<br/>real-time + audit"]
    HLF --> R2["P95 2,182 ms<br/>audit only"]
    SOL --> R3["P95 15,157 ms<br/>too slow"]

    style PG fill:#cfe8ff,stroke:#1f6feb
    style HLF fill:#e7d8ff,stroke:#8957e5
    style SOL fill:#ffd9d9,stroke:#d1242f
```

### Research Questions

We set out to answer three questions:

**RQ1 — Can blockchain keep up with real-time alerting?** *(target: P95 < 100 ms)*
→ **No.** Hyperledger Fabric is **22× over budget**, Solana **152×**. Only PostgreSQL clears the bar — with 72× headroom.

**RQ2 — How much load can each system take?**
→ PostgreSQL sustained **5,000+ TPS** at P95 < 12 ms. Fabric managed ~0.5 TPS via CLI (≈200–500 TPS with the SDK, per literature); Solana ~2 TPS once you wait for finality.

**RQ3 — Is blockchain's overhead actually worth it?**
→ **Only when you need multi-party trust.** A hash-chained database already detects tampering; blockchain adds *distributed* trust — no single party controls the log — at a steep latency cost. Worth it for regulator/insurer audit, overkill for one trusted operator.

---

## Experiment Design

**Goal:** measure the real cost of tamper-evident logging on each system under identical, realistic load.

**Dataset.** 157,501 normalized events from the Hassler et al. UAV cyberattack dataset (a real quadcopter testbed: DoS, replay, evil-twin) augmented with synthetic GPS-spoof / jam / MITM signatures from CICIoV2024. Mix: 66.5% benign + ~5.5% each of six attack types.

**What we measure.**
- **Latency** — submission → confirmation, as P50/P90/P95/P99. *P95 is the headline* (it's the AAM alerting SLO).
- **Throughput** — max sustained TPS before P95 degrades >2× or failures exceed 1%.
- **Security** — hash-chain integrity, tamper detection, unique IDs, endorsement/signature checks, finality.

**Test procedure** *(per system, 30-second windows, averaged over 3 runs):*

| Test | PostgreSQL | Hyperledger Fabric | Solana |
|---|---|---|---|
| Latency | 30,000 @ 1,000 TPS | 30 @ 1 TPS (CLI) | 300 @ 10 TPS |
| Throughput sweep | 1,000 → 2,000 → 5,000 TPS | max sustainable | max sustainable |
| Confirmation | synchronous commit | `AND(Org1, Org2)` endorsement + Raft ordering | finalized (~31 slots) |

**Environment.** Apple M2 (macOS) · Docker Desktop · Hyperledger Fabric 2.5.10 (3 Raft orderers, 2 orgs, LevelDB) · Solana test-validator · PostgreSQL 16 · Python 3.13 (asyncio, 20-connection pool) · Rust event parser.

### Where the numbers come from

Every figure in this README is from a measured run on **2025-12-19** (not estimates):

- **Summary** → [`results/EXPERIMENT_RESULTS.md`](results/EXPERIMENT_RESULTS.md) *(in the repo)*
- **Raw per-event latencies** → written to `results/blast_results.csv` during the run (~8.6 MB). It is **not shipped** in the repo to keep the clone lightweight — regenerate it by re-running `blast.py`, or request the original file.

To **reproduce**: PostgreSQL via [Quick Start](#quick-start) below; the full Fabric network via [`blockchain/hyperledger/README.md`](blockchain/hyperledger/README.md) (`./network.sh up createChannel deployCC`), then `python blast.py --target all`.

---

## Data Pipeline

Raw UAV telemetry and attack captures are normalized by a Rust parser into a fixed-size `SecurityEvent`, then replayed through a load tester (`blast.py`) against each system.

```mermaid
flowchart LR
    A["UAV Cyberattack Dataset<br/>Hassler et al. — 54,784 rows"] --> P["Rust Parser<br/>data_parser/"]
    B["CICIoV2024 synthetic<br/>GPS spoof / jam / MITM"] --> P
    P --> N["Normalized SecurityEvent<br/>157,501 events"]
    N --> LT["Load Tester<br/>blast.py — async, target TPS"]
    LT --> PG[("PostgreSQL")]
    LT --> HLF{{"Hyperledger Fabric"}}
    LT --> SOL{{"Solana"}}
```

**`SecurityEvent` structure** (normalized record):

```rust
struct SecurityEvent {
    timestamp_ms: i64,      // Detection time
    event_type:   u8,       // 0=Benign 1=GPSJam 2=MITM 3=Replay 4=GPSSpoof 5=DoS 6=EvilTwin
    confidence:   u8,       // Detection confidence (0-100)
    vehicle_id:   [u8; 32], // SHA-256 of vehicle ID
    data_hash:    [u8; 32], // SHA-256 of telemetry
}
```

**Attack distribution (157,501 events):** Benign 66.5% · GPS Jamming 5.6% · MITM 5.6% · Replay 5.5% · GPS Spoofing 5.5% · DoS 5.5% · Evil Twin 5.5%

---

## Systems Under Test

| System | Type | Tamper-evidence | Decentralization | Role in AAM |
|--------|------|-----------------|------------------|-------------|
| **PostgreSQL 16** | Centralized DB + hash chain | Hash chain (SHA-256) | single admin | Real-time alerting baseline |
| **Hyperledger Fabric 2.5** | Permissioned blockchain | Consensus + endorsement | known parties | Regulatory audit trail |
| **Solana (Anchor 0.30)** | Public blockchain | Consensus + Ed25519 | public | Reference public-chain bound |

---

## Key Results

### P95 Latency (ms)

```mermaid
xychart-beta
    title "P95 Latency — lower is better (linear scale)"
    x-axis ["PostgreSQL", "Hyperledger", "Solana"]
    y-axis "P95 Latency (ms)" 0 --> 16000
    bar [1.39, 2182, 15157]
```

> On a linear axis PostgreSQL's 1.39 ms bar is effectively invisible next to blockchain — that *is* the result: the gap spans four orders of magnitude. The 100 ms real-time threshold sits below the first gridline.

| Metric | PostgreSQL | Hyperledger | Solana |
|--------|-----------:|------------:|-------:|
| Min  | 0.53 | 2,109 | 14,580 |
| Avg  | 0.99 | 2,158 | 15,058 |
| P50  | 0.79 | 2,158 | 15,115 |
| P90  | 1.08 | 2,179 | 15,145 |
| **P95** | **1.39** | **2,182** | **15,157** |
| P99  | 5.79 | 2,274 | 15,177 |
| Max  | 44.15 | 2,274 | 15,181 |

### Requirements Assessment

| Requirement | PostgreSQL | Hyperledger | Solana |
|-------------|:----------:|:-----------:|:------:|
| Real-time (<100 ms P95) | PASS | FAIL | FAIL |
| Audit trail (<5 s P95)  | PASS | PASS | FAIL |
| Tamper evidence         | PASS | PASS | PASS |
| Decentralization        | FAIL | PASS | PASS |
| Regulatory compliance   | Partial | PASS | Partial |

No single system satisfies every requirement — which motivates the hybrid design.

---

## Recommended Hybrid Architecture

Real-time events land in PostgreSQL (sub-2 ms, 5,000+ TPS); a **Merkle root** is anchored to the blockchain every 5–10 minutes for immutable, multi-party-verifiable audit — cutting blockchain transaction volume by orders of magnitude while preserving cryptographic linkage to every event.

```mermaid
flowchart TB
    EV["Security Events<br/>GPS Spoof, DoS, ..."] --> PG

    subgraph RT["Real-Time Layer"]
        PG[("PostgreSQL<br/>Hash-Chain")] --> AL["Real-Time Alerts<br/>P95 < 2 ms"]
    end

    PG -. "Merkle root anchor<br/>every 5–10 min" .-> HLF

    subgraph AUD["Audit Layer"]
        HLF{{"Hyperledger Fabric"}} --> AU["Immutable Audit<br/>Multi-Party Verify"]
    end

    style RT fill:#eef6ff,stroke:#1f6feb
    style AUD fill:#f5eeff,stroke:#8957e5
```

---

## How the Tamper-Evidence Works

### PostgreSQL hash-chained audit log

Each row's `record_hash` is `SHA-256(row data ‖ prev_hash)`. Modifying any past row invalidates every hash after it — detectable by `verify_hash_chain()`.

```mermaid
flowchart LR
    R0["Event 0<br/>record_hash₀"] --> R1["Event 1<br/>prev = hash₀<br/>record_hash₁"]
    R1 --> R2["Event 2<br/>prev = hash₁<br/>record_hash₂"]
    R2 --> R3["Event 3<br/>prev = hash₂<br/>record_hash₃"]
    R3 --> RN["…"]
```

### Hyperledger Fabric transaction flow

Distributes trust across organizations: a transaction commits only after **both** orgs endorse and the Raft ordering service sequences it into a block.

```mermaid
sequenceDiagram
    participant C as Client
    participant P1 as Peer (Org1)
    participant P2 as Peer (Org2)
    participant O as Orderer (Raft ×3)
    participant L as Ledger

    C->>P1: 1. Submit proposal
    C->>P2: 1. Submit proposal
    P1-->>C: 2. Endorse + sign
    P2-->>C: 2. Endorse + sign
    C->>O: 3. Submit endorsed tx
    O->>O: 4. Order into block
    O-->>L: 5. Distribute + commit
    Note over O,L: AND(Org1, Org2) endorsement policy
```

---

## Repository Structure

```
z99_experiment/
├── run.py                  ← MAIN ENTRY POINT (PostgreSQL quick start)
├── blast.py                ← Async load tester (configurable TPS)
├── security_tests.py       ← Tamper / integrity / consensus test suite
├── docker-compose.yml      ← PostgreSQL / Solana services
├── requirements.txt        ← Python dependencies
│
├── data_parser/            ← Rust: raw CSV → normalized SecurityEvent
├── database/postgres/schema/
│   └── 001_init.sql        ← Hash-chained audit-log schema + procedures
├── blockchain/
│   ├── solana/             ← Anchor program (Rust)
│   └── hyperledger/        ← Fabric chaincode (Go)
├── src/                    ← Multi-system experiment orchestrator + clients
│   ├── run_experiment.py
│   └── clients/            ← postgres / fabric / solana clients
├── infrastructure/         ← Terraform + setup scripts (IaC)
└── final_paper_v1/         ← IEEE paper (LaTeX source)
```

---

## Quick Start

The PostgreSQL baseline runs out of the box; blockchain backends need extra setup (see Advanced sections).

```bash
# 1. Start PostgreSQL (schema auto-loads from database/postgres/schema/)
docker-compose up -d postgres

# 2. Install Python dependencies
pip install -r requirements.txt   # or: pip install psycopg2-binary

# 3. Run the experiment
python run.py                     # quick test (10 events)
python run.py --full              # latency + throughput tests
python run.py --full --tps 10 25 50 100 200   # custom TPS sweep
```

---

## Troubleshooting

**"Cannot connect to PostgreSQL"**
```bash
docker-compose up -d postgres
docker-compose ps          # check health
docker-compose logs postgres
```

**"psycopg2 not installed"** → `pip install psycopg2-binary`

**"Table does not exist"** — the schema auto-loads on first start. To reset:
```bash
docker-compose down -v && docker-compose up -d postgres
```

---

## Advanced: Solana

```bash
docker-compose up -d solana && sleep 30
curl http://localhost:8899 -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}'
# → {"jsonrpc":"2.0","result":"ok","id":1}
```
Then drive it via `src/clients/solana_client/client.py`.

## Advanced: Hyperledger Fabric

Fabric needs crypto material, channel creation, and chaincode deployment:
- `infrastructure/terraform/local/main.tf` — full Terraform setup
- `blockchain/hyperledger/` — Go chaincode + network configs

---

## Citation

> D. Garcia, *Performance Evaluation of Blockchain-Based Security Logging for Advanced Air Mobility Systems*, Department of Computer Engineering, Polytechnique Montreal.

Dataset: Hassler et al., *Cyber-Physical Dataset for UAVs Under Normal Operations and Cyberattacks* (IEEE DataPort, NSF Award 2220346). Paper source in [`final_paper_v1/`](final_paper_v1/).
