#!/usr/bin/env python3
"""
AAM SECURITY LOAD BLASTER

Real performance testing - blasts PostgreSQL, Solana, and Hyperledger endpoints.
No bullshit, just raw throughput and latency metrics.

Usage:
    # Blast PostgreSQL only
    python blast.py --target postgres --tps 1000 --duration 60

    # Blast Solana private node
    python blast.py --target solana --rpc https://your-node.com --tps 500 --duration 60

    # Blast Hyperledger
    python blast.py --target hyperledger --peer localhost:7051 --tps 200 --duration 60

    # Blast all systems
    python blast.py --target all --duration 60

    # Use real data file
    python blast.py --target postgres --data events.csv --duration 60
"""

import argparse
import asyncio
import csv
import hashlib
import json
import os
import random
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
import threading
import queue

# =============================================================================
# METRICS
# =============================================================================

@dataclass
class Metric:
    timestamp: float
    system: str
    latency_ms: float
    success: bool
    error: Optional[str] = None
    tx_id: Optional[str] = None
    batch_size: int = 1


class MetricsCollector:
    """Thread-safe metrics collector"""

    def __init__(self, output_file: str = "results/blast_results.csv"):
        self.metrics: List[Metric] = []
        self.lock = threading.Lock()
        self.output_file = Path(output_file)
        self.output_file.parent.mkdir(parents=True, exist_ok=True)

        # Real-time counters
        self.total_sent = 0
        self.total_success = 0
        self.total_failed = 0
        self.latencies: List[float] = []

    def record(self, metric: Metric):
        with self.lock:
            self.metrics.append(metric)
            self.total_sent += metric.batch_size
            if metric.success:
                self.total_success += metric.batch_size
                self.latencies.append(metric.latency_ms)
            else:
                self.total_failed += metric.batch_size

    def get_stats(self) -> Dict[str, Any]:
        with self.lock:
            if not self.latencies:
                return {"error": "No successful metrics"}

            sorted_lat = sorted(self.latencies)
            n = len(sorted_lat)

            return {
                "total_sent": self.total_sent,
                "total_success": self.total_success,
                "total_failed": self.total_failed,
                "success_rate": self.total_success / max(self.total_sent, 1) * 100,
                "latency_min": min(sorted_lat),
                "latency_max": max(sorted_lat),
                "latency_avg": sum(sorted_lat) / n,
                "latency_p50": sorted_lat[int(n * 0.50)],
                "latency_p90": sorted_lat[int(n * 0.90)],
                "latency_p95": sorted_lat[int(n * 0.95)],
                "latency_p99": sorted_lat[min(int(n * 0.99), n - 1)],
            }

    def save(self):
        with self.lock:
            with open(self.output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'system', 'latency_ms', 'success', 'error', 'tx_id', 'batch_size'])
                for m in self.metrics:
                    writer.writerow([m.timestamp, m.system, m.latency_ms, m.success, m.error or '', m.tx_id or '', m.batch_size])
        print(f"\nResults saved to: {self.output_file}")


# =============================================================================
# EVENT DATA
# =============================================================================

@dataclass
class SecurityEvent:
    timestamp: int
    event_type: int
    confidence: int
    vehicle_id: bytes
    data_hash: bytes

    @classmethod
    def generate(cls) -> 'SecurityEvent':
        return cls(
            timestamp=int(time.time() * 1000),
            event_type=random.randint(1, 6),
            confidence=random.randint(50, 100),
            vehicle_id=os.urandom(32),
            data_hash=os.urandom(32),
        )

    @classmethod
    def from_csv_row(cls, row: dict) -> 'SecurityEvent':
        """Parse from CSV row"""
        # Get timestamp - use current time since dataset timestamps are from 1970
        ts_ms = int(row.get('timestamp_ms', 0))
        if ts_ms < 1000000000000:  # Before year 2001 in ms
            ts_ms = int(time.time() * 1000)

        return cls(
            timestamp=ts_ms,
            event_type=int(row.get('event_type', row.get('attack_type', 1))),
            confidence=int(row.get('confidence', 85)),
            vehicle_id=hashlib.sha256(str(row.get('vehicle_id', 'v1')).encode()).digest(),
            data_hash=bytes.fromhex(row.get('data_hash', 'a' * 32)),
        )


def load_events_from_file(filepath: str, count: int = 10000) -> List[SecurityEvent]:
    """Load events from CSV file"""
    events = []
    try:
        with open(filepath, 'r') as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if i >= count:
                    break
                events.append(SecurityEvent.from_csv_row(row))
        print(f"Loaded {len(events)} events from {filepath}")
    except Exception as e:
        print(f"Error loading file: {e}")
    return events


# =============================================================================
# POSTGRESQL BLASTER
# =============================================================================

class PostgresBlaster:
    """High-performance PostgreSQL blaster using connection pool"""

    def __init__(self, config: dict):
        self.config = config
        self.pool = None

    async def connect(self, pool_size: int = 20):
        import asyncpg
        self.pool = await asyncpg.create_pool(
            host=self.config.get('host', 'localhost'),
            port=self.config.get('port', 5432),
            database=self.config.get('database', 'aam_security'),
            user=self.config.get('user', 'aam_user'),
            password=self.config.get('password', 'aam_password'),
            min_size=pool_size,
            max_size=pool_size,
        )
        print(f"  PostgreSQL pool created: {pool_size} connections")

    async def disconnect(self):
        if self.pool:
            await self.pool.close()

    async def blast_event(self, event: SecurityEvent) -> Tuple[float, bool, Optional[str]]:
        """Send single event, return (latency_ms, success, error)"""
        start = time.perf_counter()
        try:
            async with self.pool.acquire() as conn:
                await conn.fetchrow("""
                    SELECT * FROM insert_security_event($1, $2, $3, $4, $5, $6)
                """,
                    datetime.fromtimestamp(event.timestamp / 1000),
                    event.event_type,
                    event.confidence,
                    event.vehicle_id,
                    event.data_hash,
                    datetime.now()
                )
            latency = (time.perf_counter() - start) * 1000
            return latency, True, None
        except Exception as e:
            latency = (time.perf_counter() - start) * 1000
            return latency, False, str(e)

    async def blast_batch(self, events: List[SecurityEvent]) -> Tuple[float, bool, Optional[str]]:
        """Send batch of events in single transaction"""
        start = time.perf_counter()
        try:
            async with self.pool.acquire() as conn:
                async with conn.transaction():
                    for event in events:
                        await conn.fetchrow("""
                            SELECT * FROM insert_security_event($1, $2, $3, $4, $5, $6)
                        """,
                            datetime.fromtimestamp(event.timestamp / 1000),
                            event.event_type,
                            event.confidence,
                            event.vehicle_id,
                            event.data_hash,
                            datetime.now()
                        )
            latency = (time.perf_counter() - start) * 1000
            return latency, True, None
        except Exception as e:
            latency = (time.perf_counter() - start) * 1000
            return latency, False, str(e)


# =============================================================================
# SOLANA BLASTER
# =============================================================================

class SolanaBlaster:
    """High-performance Solana blaster"""

    def __init__(self, rpc_url: str, program_id: str = None):
        self.rpc_url = rpc_url
        self.program_id = program_id
        self.client = None
        self.payer = None

    async def connect(self):
        try:
            from solana.rpc.async_api import AsyncClient
            from solders.keypair import Keypair

            self.client = AsyncClient(self.rpc_url)

            # Check if keypair exists
            keypair_path = Path.home() / ".config/solana/id.json"
            if keypair_path.exists():
                with open(keypair_path) as f:
                    self.payer = Keypair.from_bytes(bytes(json.load(f)))
            else:
                self.payer = Keypair()
                print(f"  Generated new keypair: {self.payer.pubkey()}")

            # Test connection
            version = await self.client.get_version()
            print(f"  Solana connected: {version.value.solana_core}")

            # Check balance
            balance = await self.client.get_balance(self.payer.pubkey())
            sol = balance.value / 1_000_000_000
            print(f"  Balance: {sol:.4f} SOL")

            if sol < 0.1:
                print("  WARNING: Low balance - transactions may fail")

        except ImportError:
            print("  ERROR: solana/solders not installed. Run: pip install solana solders")
            raise
        except Exception as e:
            print(f"  ERROR: {e}")
            raise

    async def disconnect(self):
        if self.client:
            await self.client.close()

    async def blast_event(self, event: SecurityEvent) -> Tuple[float, bool, Optional[str], Optional[str]]:
        """Send event to Solana, return (latency_ms, success, error, signature)"""
        start = time.perf_counter()
        try:
            from solders.keypair import Keypair
            from solders.pubkey import Pubkey
            from solders.system_program import ID as SYSTEM_PROGRAM_ID
            from solders.instruction import Instruction, AccountMeta
            from solders.message import Message
            from solders.transaction import Transaction
            from solana.rpc.types import TxOpts

            # Create new account for event
            event_account = Keypair()
            program_id = Pubkey.from_string(self.program_id) if self.program_id else SYSTEM_PROGRAM_ID

            # Build instruction (simplified - just transfer for now if no program)
            if not self.program_id:
                # Simple transfer as baseline
                from solders.system_program import transfer, TransferParams
                ix = transfer(TransferParams(
                    from_pubkey=self.payer.pubkey(),
                    to_pubkey=event_account.pubkey(),
                    lamports=1000
                ))
            else:
                # Actual program call
                discriminator = bytes([245, 247, 108, 165, 208, 92, 0, 54])
                data = discriminator
                data += struct.pack('<q', event.timestamp)
                data += struct.pack('<B', event.event_type)
                data += struct.pack('<B', event.confidence)
                data += event.vehicle_id
                data += event.data_hash

                ix = Instruction(
                    program_id,
                    data,
                    [
                        AccountMeta(event_account.pubkey(), True, True),
                        AccountMeta(self.payer.pubkey(), True, True),
                        AccountMeta(SYSTEM_PROGRAM_ID, False, False),
                    ]
                )

            blockhash = (await self.client.get_latest_blockhash()).value.blockhash

            if self.program_id:
                tx = Transaction.new_signed_with_payer(
                    [ix], self.payer.pubkey(), [self.payer, event_account], blockhash
                )
            else:
                tx = Transaction.new_signed_with_payer(
                    [ix], self.payer.pubkey(), [self.payer], blockhash
                )

            result = await self.client.send_transaction(tx, opts=TxOpts(skip_preflight=True))
            signature = str(result.value)

            # Wait for confirmation
            await self.client.confirm_transaction(result.value)

            latency = (time.perf_counter() - start) * 1000
            return latency, True, None, signature

        except Exception as e:
            latency = (time.perf_counter() - start) * 1000
            return latency, False, str(e), None


# =============================================================================
# HYPERLEDGER FABRIC BLASTER
# =============================================================================

class HyperledgerBlaster:
    """Hyperledger Fabric blaster using peer CLI with test-network setup"""

    def __init__(self, peer_endpoint: str, channel: str = "aamchannel", chaincode: str = "aam_security"):
        self.peer_endpoint = peer_endpoint
        self.channel = channel
        self.chaincode = chaincode
        self.executor = ThreadPoolExecutor(max_workers=1)  # Serial execution for CLI

        # Fabric test-network paths
        home = os.path.expanduser("~")
        self.test_network_path = f"{home}/fabric-samples/test-network"
        self.fabric_cfg_path = f"{home}/fabric-samples/config"
        self.bin_path = f"{home}/fabric-samples/bin"

        # TLS certificates
        self.orderer_ca = f"{self.test_network_path}/organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem"
        self.org1_tls = f"{self.test_network_path}/organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem"
        self.org2_tls = f"{self.test_network_path}/organizations/peerOrganizations/org2.example.com/tlsca/tlsca.org2.example.com-cert.pem"
        self.msp_path = f"{self.test_network_path}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"

    async def connect(self):
        print(f"  Hyperledger test-network: {self.test_network_path}")
        print(f"  Channel: {self.channel}")
        print(f"  Chaincode: {self.chaincode}")
        # Verify paths exist
        if not os.path.exists(self.orderer_ca):
            raise Exception(f"Orderer CA not found: {self.orderer_ca}")

    async def disconnect(self):
        self.executor.shutdown(wait=False)

    def _invoke_sync(self, event: SecurityEvent) -> Tuple[float, bool, Optional[str], Optional[str]]:
        """Synchronous invoke via peer CLI"""
        import subprocess

        start = time.perf_counter()
        try:
            args = json.dumps({
                "function": "LogSecurityEvent",
                "Args": [
                    str(event.timestamp),
                    str(event.event_type),
                    str(event.confidence),
                    event.vehicle_id.hex(),
                    event.data_hash.hex(),
                    str(int(time.time() * 1000))
                ]
            })

            env = os.environ.copy()
            env["PATH"] = f"{self.bin_path}:{env.get('PATH', '')}"
            env["FABRIC_CFG_PATH"] = self.fabric_cfg_path
            env["CORE_PEER_TLS_ENABLED"] = "true"
            env["CORE_PEER_LOCALMSPID"] = "Org1MSP"
            env["CORE_PEER_TLS_ROOTCERT_FILE"] = self.org1_tls
            env["CORE_PEER_MSPCONFIGPATH"] = self.msp_path
            env["CORE_PEER_ADDRESS"] = "localhost:7051"

            result = subprocess.run(
                [
                    f"{self.bin_path}/peer", "chaincode", "invoke",
                    "-o", "localhost:7050",
                    "--ordererTLSHostnameOverride", "orderer.example.com",
                    "--tls",
                    "--cafile", self.orderer_ca,
                    "-C", self.channel,
                    "-n", self.chaincode,
                    "--peerAddresses", "localhost:7051",
                    "--tlsRootCertFiles", self.org1_tls,
                    "--peerAddresses", "localhost:9051",
                    "--tlsRootCertFiles", self.org2_tls,
                    "-c", args,
                    "--waitForEvent"
                ],
                capture_output=True,
                text=True,
                timeout=30,
                env=env
            )

            latency = (time.perf_counter() - start) * 1000

            if result.returncode == 0:
                # Extract tx_id from output
                tx_id = None
                for line in result.stderr.split('\n'):  # Fabric outputs to stderr
                    if 'txid' in line.lower():
                        parts = line.split('[')
                        if len(parts) > 1:
                            tx_id = parts[1].split(']')[0]
                        break
                return latency, True, None, tx_id
            else:
                return latency, False, result.stderr[:200], None

        except subprocess.TimeoutExpired:
            latency = (time.perf_counter() - start) * 1000
            return latency, False, "Timeout", None
        except Exception as e:
            latency = (time.perf_counter() - start) * 1000
            return latency, False, str(e), None

    async def blast_event(self, event: SecurityEvent) -> Tuple[float, bool, Optional[str], Optional[str]]:
        """Send event to Hyperledger"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, self._invoke_sync, event)


# =============================================================================
# MAIN BLASTER
# =============================================================================

class LoadBlaster:
    """Orchestrates load testing across all systems"""

    def __init__(self, metrics: MetricsCollector):
        self.metrics = metrics
        self.postgres: Optional[PostgresBlaster] = None
        self.solana: Optional[SolanaBlaster] = None
        self.hyperledger: Optional[HyperledgerBlaster] = None
        self.running = False

    async def setup_postgres(self, config: dict, pool_size: int = 20):
        self.postgres = PostgresBlaster(config)
        await self.postgres.connect(pool_size)

    async def setup_solana(self, rpc_url: str, program_id: str = None):
        self.solana = SolanaBlaster(rpc_url, program_id)
        await self.solana.connect()

    async def setup_hyperledger(self, peer_endpoint: str, channel: str, chaincode: str):
        self.hyperledger = HyperledgerBlaster(peer_endpoint, channel, chaincode)
        await self.hyperledger.connect()

    async def teardown(self):
        if self.postgres:
            await self.postgres.disconnect()
        if self.solana:
            await self.solana.disconnect()
        if self.hyperledger:
            await self.hyperledger.disconnect()

    async def blast_postgres(self, events: List[SecurityEvent], tps: int, duration: int):
        """Blast PostgreSQL at specified TPS"""
        print(f"\n[PostgreSQL] Blasting at {tps} TPS for {duration}s...")

        interval = 1.0 / tps
        start_time = time.time()
        event_idx = 0
        tasks = []

        semaphore = asyncio.Semaphore(100)  # Max concurrent

        async def send_one(event: SecurityEvent):
            async with semaphore:
                latency, success, error = await self.postgres.blast_event(event)
                self.metrics.record(Metric(
                    timestamp=time.time(),
                    system='postgresql',
                    latency_ms=latency,
                    success=success,
                    error=error
                ))

        while (time.time() - start_time) < duration and self.running:
            event = events[event_idx % len(events)]
            event_idx += 1

            tasks.append(asyncio.create_task(send_one(event)))

            # Rate limiting
            elapsed = time.time() - start_time
            expected = event_idx * interval
            if elapsed < expected:
                await asyncio.sleep(expected - elapsed)

            # Progress
            if event_idx % 500 == 0:
                stats = self.metrics.get_stats()
                actual_tps = event_idx / elapsed
                print(f"  [{int(elapsed)}s] Sent: {event_idx}, TPS: {actual_tps:.0f}, "
                      f"p95: {stats.get('latency_p95', 0):.1f}ms")

        # Wait for remaining
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def blast_solana(self, events: List[SecurityEvent], tps: int, duration: int):
        """Blast Solana at specified TPS"""
        print(f"\n[Solana] Blasting at {tps} TPS for {duration}s...")

        interval = 1.0 / tps
        start_time = time.time()
        event_idx = 0
        tasks = []

        semaphore = asyncio.Semaphore(50)  # Lower for Solana

        async def send_one(event: SecurityEvent):
            async with semaphore:
                latency, success, error, sig = await self.solana.blast_event(event)
                self.metrics.record(Metric(
                    timestamp=time.time(),
                    system='solana',
                    latency_ms=latency,
                    success=success,
                    error=error,
                    tx_id=sig
                ))

        while (time.time() - start_time) < duration and self.running:
            event = events[event_idx % len(events)]
            event_idx += 1

            tasks.append(asyncio.create_task(send_one(event)))

            elapsed = time.time() - start_time
            expected = event_idx * interval
            if elapsed < expected:
                await asyncio.sleep(expected - elapsed)

            if event_idx % 100 == 0:
                stats = self.metrics.get_stats()
                success_count = stats.get('total_success', 0)
                actual_tps = success_count / elapsed if elapsed > 0 else 0
                print(f"  [{int(elapsed)}s] Sent: {event_idx}, Success: {success_count}, "
                      f"TPS: {actual_tps:.0f}")

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def blast_hyperledger(self, events: List[SecurityEvent], tps: int, duration: int):
        """Blast Hyperledger at specified TPS"""
        print(f"\n[Hyperledger] Blasting at {tps} TPS for {duration}s...")

        interval = 1.0 / tps
        start_time = time.time()
        event_idx = 0
        tasks = []

        semaphore = asyncio.Semaphore(20)  # Lower for Fabric

        async def send_one(event: SecurityEvent):
            async with semaphore:
                latency, success, error, tx_id = await self.hyperledger.blast_event(event)
                self.metrics.record(Metric(
                    timestamp=time.time(),
                    system='hyperledger',
                    latency_ms=latency,
                    success=success,
                    error=error,
                    tx_id=tx_id
                ))

        while (time.time() - start_time) < duration and self.running:
            event = events[event_idx % len(events)]
            event_idx += 1

            tasks.append(asyncio.create_task(send_one(event)))

            elapsed = time.time() - start_time
            expected = event_idx * interval
            if elapsed < expected:
                await asyncio.sleep(expected - elapsed)

            if event_idx % 50 == 0:
                stats = self.metrics.get_stats()
                print(f"  [{int(elapsed)}s] Sent: {event_idx}, Success: {stats.get('total_success', 0)}")

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


# =============================================================================
# MAIN
# =============================================================================

async def main():
    parser = argparse.ArgumentParser(description="AAM Security Load Blaster")
    parser.add_argument('--target', choices=['postgres', 'solana', 'hyperledger', 'all'],
                        default='postgres', help='Target system(s)')
    parser.add_argument('--tps', type=int, default=100, help='Target transactions per second')
    parser.add_argument('--duration', type=int, default=60, help='Test duration in seconds')
    parser.add_argument('--data', type=str, help='CSV file with event data')
    parser.add_argument('--events', type=int, default=10000, help='Number of events to generate if no data file')

    # PostgreSQL
    parser.add_argument('--pg-host', default='localhost')
    parser.add_argument('--pg-port', type=int, default=5433)
    parser.add_argument('--pg-db', default='aam_security')
    parser.add_argument('--pg-user', default='aam_user')
    parser.add_argument('--pg-password', default='aam_password')
    parser.add_argument('--pg-pool', type=int, default=20, help='PostgreSQL connection pool size')

    # Solana
    parser.add_argument('--rpc', default='http://localhost:8899', help='Solana RPC URL')
    parser.add_argument('--program', help='Solana program ID')

    # Hyperledger
    parser.add_argument('--peer', default='localhost:7051', help='Fabric peer endpoint')
    parser.add_argument('--channel', default='aamchannel', help='Fabric channel')
    parser.add_argument('--chaincode', default='aam_security', help='Fabric chaincode')

    # Output
    parser.add_argument('--output', default='results/blast_results.csv', help='Output CSV file')

    args = parser.parse_args()

    print("=" * 70)
    print("AAM SECURITY LOAD BLASTER")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    print(f"Target: {args.target}")
    print(f"TPS: {args.tps}")
    print(f"Duration: {args.duration}s")
    print("=" * 70)

    # Load or generate events
    if args.data:
        events = load_events_from_file(args.data, args.events)
        if not events:
            print("No events loaded, generating random events")
            events = [SecurityEvent.generate() for _ in range(args.events)]
    else:
        print(f"Generating {args.events} random events...")
        events = [SecurityEvent.generate() for _ in range(args.events)]

    print(f"Events ready: {len(events)}")

    # Setup
    metrics = MetricsCollector(args.output)
    blaster = LoadBlaster(metrics)
    blaster.running = True

    try:
        print("\n" + "=" * 70)
        print("SETUP")
        print("=" * 70)

        if args.target in ['postgres', 'all']:
            pg_config = {
                'host': args.pg_host,
                'port': args.pg_port,
                'database': args.pg_db,
                'user': args.pg_user,
                'password': args.pg_password,
            }
            await blaster.setup_postgres(pg_config, args.pg_pool)

        if args.target in ['solana', 'all']:
            await blaster.setup_solana(args.rpc, args.program)

        if args.target in ['hyperledger', 'all']:
            await blaster.setup_hyperledger(args.peer, args.channel, args.chaincode)

        # Blast
        print("\n" + "=" * 70)
        print("BLASTING")
        print("=" * 70)

        if args.target == 'postgres' or args.target == 'all':
            await blaster.blast_postgres(events, args.tps, args.duration)

        if args.target == 'solana' or args.target == 'all':
            await blaster.blast_solana(events, min(args.tps, 500), args.duration)

        if args.target == 'hyperledger' or args.target == 'all':
            await blaster.blast_hyperledger(events, min(args.tps, 200), args.duration)

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        blaster.running = False
    finally:
        await blaster.teardown()

    # Results
    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)

    stats = metrics.get_stats()
    if 'error' not in stats:
        print(f"\nTotal Sent:     {stats['total_sent']}")
        print(f"Total Success:  {stats['total_success']}")
        print(f"Total Failed:   {stats['total_failed']}")
        print(f"Success Rate:   {stats['success_rate']:.1f}%")
        print(f"\nLatency (ms):")
        print(f"  Min:  {stats['latency_min']:.2f}")
        print(f"  Avg:  {stats['latency_avg']:.2f}")
        print(f"  P50:  {stats['latency_p50']:.2f}")
        print(f"  P90:  {stats['latency_p90']:.2f}")
        print(f"  P95:  {stats['latency_p95']:.2f}")
        print(f"  P99:  {stats['latency_p99']:.2f}")
        print(f"  Max:  {stats['latency_max']:.2f}")
    else:
        print(f"Error: {stats['error']}")

    metrics.save()

    print("\n" + "=" * 70)
    print(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)


if __name__ == '__main__':
    asyncio.run(main())
