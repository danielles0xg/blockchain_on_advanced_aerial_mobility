# AAM Security Blockchain Experiment

### Step 1: Start PostgreSQL
```bash
cd z99_experiment
docker-compose up -d postgres
```

### Step 2: Install Python Dependencies
```bash
pip install psycopg2-binary
```

### Step 3: Run Experiment
```bash
# Quick test (10 events) - verify everything works
python run.py

# Full experiment with latency & throughput tests
python run.py --full

# Custom TPS levels
python run.py --full --tps 10 25 50 100 200
```

That's it! The experiment will run and print results.

---

## What This Does

Compares blockchain vs traditional database for AAM (Advanced Air Mobility) security logging:


| System | Type | Expected p95 Latency |
|--------|------|---------------------|
| **PostgreSQL** | Centralized DB (baseline) | 1-10 ms |
| **Hyperledger Fabric** | Permissioned Blockchain | 200-800 ms |
| **Solana** | Public Blockchain | 400-1200 ms |

---

## File Structure

```
z99_experiment/
├── run.py                 ← MAIN ENTRY POINT (run this!)
├── docker-compose.yml     ← Start PostgreSQL/Solana
├── requirements.txt       ← Python dependencies
│
├── database/postgres/schema/
│   └── 001_init.sql       ← Hash-chained audit log schema
│
├── blockchain/
│   ├── solana/            ← Solana program (Rust)
│   └── hyperledger/       ← Fabric chaincode (Go)
│
└── src/                   ← Advanced experiment code
    ├── run_experiment.py  ← Multi-system orchestrator
    └── clients/           ← System-specific clients
```

---

## Expected Output

```
============================================================
AAM SECURITY EXPERIMENT
Started: 2024-12-18 22:30:00
============================================================

============================================================
SETUP
============================================================

Connecting to PostgreSQL...
  Connected to PostgreSQL at localhost:5432

Setup complete!

============================================================
QUICK TEST
============================================================

Clearing existing data...

Logging 10 test events...
  Event 1: 2.34ms - OK
  Event 2: 1.89ms - OK
  Event 3: 2.12ms - OK
  ...

Total events in database: 10

============================================================
QUICK TEST PASSED!
============================================================
```

---

## Full Experiment Output

```bash
python run.py --full
```

```
============================================================
FULL EXPERIMENT
============================================================

------------------------------------------------------------
LATENCY TEST (500 events)
------------------------------------------------------------

Latency Results (PostgreSQL):
  Count: 500
  Min:   0.89 ms
  Avg:   2.34 ms
  P50:   2.12 ms
  P90:   3.45 ms
  P95:   4.12 ms
  P99:   6.78 ms
  Max:   12.34 ms

------------------------------------------------------------
THROUGHPUT TESTS
------------------------------------------------------------

Results at 10 TPS:
  Actual TPS:    10.0
  Success Rate:  300/300
  Avg Latency:   2.15 ms
  P95 Latency:   3.89 ms

Results at 50 TPS:
  Actual TPS:    49.8
  Success Rate:  1494/1500
  Avg Latency:   2.45 ms
  P95 Latency:   4.23 ms

Results at 100 TPS:
  Actual TPS:    98.7
  Success Rate:  2961/3000
  Avg Latency:   2.89 ms
  P95 Latency:   5.12 ms

============================================================
EXPERIMENT SUMMARY
============================================================

## PostgreSQL Baseline Results

### Latency (milliseconds)
| Metric | Value |
|--------|-------|
| P50    | 2.12 |
| P95    | 4.12 |
| P99    | 6.78 |

### Requirements Check
| Requirement | Target | Actual | Status |
|-------------|--------|--------|--------|
| Real-time   | <100ms | 4.1ms  | PASS   |
| Audit       | <5000ms | 4.1ms | PASS   |
```

---

## Troubleshooting

### "Cannot connect to PostgreSQL"
```bash
# Make sure PostgreSQL is running
docker-compose up -d postgres

# Check if it's healthy
docker-compose ps

# View logs if issues
docker-compose logs postgres
```

### "psycopg2 not installed"
```bash
pip install psycopg2-binary
```

### "Table does not exist"
The schema auto-loads from `database/postgres/schema/001_init.sql` when PostgreSQL starts. If it didn't:
```bash
# Restart with fresh volume
docker-compose down -v
docker-compose up -d postgres
```

---

## Advanced: Adding Solana

```bash
# Start Solana local validator
docker-compose up -d solana

# Wait for it to be ready (30 seconds)
sleep 30

# Check health
curl http://localhost:8899 -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}'
# Should return: {"jsonrpc":"2.0","result":"ok","id":1}
```

Then use `src/clients/solana_client/client.py` to interact with it.

---

## Advanced: Adding Hyperledger Fabric

Hyperledger Fabric requires more setup (crypto material, channel creation, chaincode deployment). Use:
- `infrastructure/terraform/local/main.tf` - Full Terraform setup
- `blockchain/hyperledger/` - Chaincode and network configs

This is more complex and optional for the baseline experiment.

---

## References

- [Experiment Design](z99_repo/experiment_validation_v4.md)
- [Terraform Guide](terraform_101.md)
- [Hyperledger Guide](hyperledger_101.md)
