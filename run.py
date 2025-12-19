#!/usr/bin/env python3
"""
AAM Security Experiment - MAIN ENTRY POINT

Run this file to execute the experiment!

Usage:
    # Step 1: Start PostgreSQL
    docker-compose up -d postgres

    # Step 2: Install dependencies
    pip install psycopg2-binary pandas numpy

    # Step 3: Run experiment
    python run.py                    # Quick test (PostgreSQL only)
    python run.py --full             # Full experiment
    python run.py --tps 10 25 50     # Custom TPS levels
"""

import argparse
import hashlib
import random
import statistics
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from pathlib import Path
from typing import List, Optional, Dict, Any

# =============================================================================
# CONFIGURATION
# =============================================================================

POSTGRES_CONFIG = {
    "host": "localhost",
    "port": 5433,  # Using 5433 to avoid conflict with local PostgreSQL
    "database": "aam_security",
    "user": "aam_user",
    "password": "aam_password",
}

# =============================================================================
# DATA MODELS
# =============================================================================

class AttackType(IntEnum):
    GPS_SPOOF = 1
    DOS = 2
    MITM = 3
    REPLAY = 4
    GPS_JAM = 5
    EVIL_TWIN = 6


@dataclass
class SecurityEvent:
    timestamp: int          # ms since epoch
    event_type: AttackType
    confidence: int         # 0-100
    vehicle_id: bytes       # 32 bytes
    data_hash: bytes        # 32 bytes

    @classmethod
    def generate_random(cls, seed: Optional[int] = None) -> 'SecurityEvent':
        if seed:
            random.seed(seed)
        return cls(
            timestamp=int(time.time() * 1000),
            event_type=random.choice(list(AttackType)),
            confidence=random.randint(50, 100),
            vehicle_id=hashlib.sha256(f"vehicle_{random.randint(1,100)}".encode()).digest(),
            data_hash=hashlib.sha256(f"data_{random.random()}".encode()).digest()
        )


@dataclass
class MetricResult:
    event_id: int
    latency_ms: float
    success: bool
    error: Optional[str] = None


# =============================================================================
# POSTGRES CLIENT
# =============================================================================

class PostgresClient:
    def __init__(self):
        self.conn = None

    def connect(self):
        try:
            import psycopg2
            self.conn = psycopg2.connect(**POSTGRES_CONFIG)
            self.conn.autocommit = False
            print(f"  Connected to PostgreSQL at {POSTGRES_CONFIG['host']}:{POSTGRES_CONFIG['port']}")
            return True
        except ImportError:
            print("  ERROR: psycopg2 not installed. Run: pip install psycopg2-binary")
            return False
        except Exception as e:
            print(f"  ERROR: Cannot connect to PostgreSQL: {e}")
            print("  Make sure PostgreSQL is running: docker-compose up -d postgres")
            return False

    def disconnect(self):
        if self.conn:
            self.conn.close()

    def log_event(self, event: SecurityEvent) -> MetricResult:
        start = time.perf_counter()
        try:
            with self.conn.cursor() as cur:
                cur.execute("""
                    SELECT * FROM insert_security_event(
                        %s, %s, %s, %s, %s, %s
                    )
                """, (
                    datetime.fromtimestamp(event.timestamp / 1000),
                    int(event.event_type),
                    event.confidence,
                    event.vehicle_id,
                    event.data_hash,
                    datetime.now()
                ))
                result = cur.fetchone()
                self.conn.commit()

            latency = (time.perf_counter() - start) * 1000
            return MetricResult(
                event_id=result[0],
                latency_ms=result[1] if result[1] else latency,
                success=True
            )
        except Exception as e:
            self.conn.rollback()
            latency = (time.perf_counter() - start) * 1000
            return MetricResult(event_id=-1, latency_ms=latency, success=False, error=str(e))

    def get_count(self) -> int:
        with self.conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM security_events")
            return cur.fetchone()[0]

    def clear(self):
        with self.conn.cursor() as cur:
            cur.execute("TRUNCATE TABLE security_events RESTART IDENTITY")
            self.conn.commit()


# =============================================================================
# EXPERIMENT RUNNER
# =============================================================================

class ExperimentRunner:
    def __init__(self):
        self.postgres = PostgresClient()
        self.results: Dict[str, List[MetricResult]] = {}

    def setup(self) -> bool:
        print("\n" + "=" * 60)
        print("SETUP")
        print("=" * 60)

        print("\nConnecting to PostgreSQL...")
        if not self.postgres.connect():
            return False

        print("\nSetup complete!")
        return True

    def teardown(self):
        self.postgres.disconnect()
        print("\nDisconnected from PostgreSQL")

    def run_latency_test(self, count: int = 100) -> Dict[str, float]:
        """Run latency test and return percentiles"""
        print(f"\nRunning latency test ({count} events)...")

        results = []
        for i in range(count):
            event = SecurityEvent.generate_random()
            result = self.postgres.log_event(event)
            results.append(result)

            if (i + 1) % 20 == 0:
                print(f"  Progress: {i+1}/{count}")

        # Calculate percentiles
        latencies = sorted([r.latency_ms for r in results if r.success])
        n = len(latencies)

        if n == 0:
            return {"error": "No successful events"}

        percentiles = {
            "count": n,
            "min": min(latencies),
            "max": max(latencies),
            "avg": statistics.mean(latencies),
            "p50": latencies[int(n * 0.50)],
            "p90": latencies[int(n * 0.90)],
            "p95": latencies[int(n * 0.95)],
            "p99": latencies[min(int(n * 0.99), n - 1)],
        }

        return percentiles

    def run_throughput_test(self, tps: int, duration: int = 30) -> Dict[str, float]:
        """Run throughput test at specified TPS"""
        print(f"\nRunning throughput test at {tps} TPS for {duration}s...")

        interval = 1.0 / tps
        results = []
        start_time = time.time()
        event_count = 0

        while (time.time() - start_time) < duration:
            event_start = time.time()

            event = SecurityEvent.generate_random()
            result = self.postgres.log_event(event)
            results.append(result)
            event_count += 1

            # Rate limiting
            elapsed = time.time() - event_start
            if elapsed < interval:
                time.sleep(interval - elapsed)

            # Progress every 5 seconds
            total_elapsed = time.time() - start_time
            if event_count % (tps * 5) == 0:
                actual_tps = event_count / total_elapsed
                print(f"  {int(total_elapsed)}s: {event_count} events, actual TPS: {actual_tps:.1f}")

        # Calculate stats
        total_time = time.time() - start_time
        successful = sum(1 for r in results if r.success)
        latencies = [r.latency_ms for r in results if r.success]

        return {
            "target_tps": tps,
            "actual_tps": successful / total_time,
            "total_events": len(results),
            "successful": successful,
            "failed": len(results) - successful,
            "avg_latency_ms": statistics.mean(latencies) if latencies else 0,
            "p95_latency_ms": sorted(latencies)[int(len(latencies) * 0.95)] if latencies else 0,
        }

    def run_quick_test(self):
        """Quick test - just verify everything works"""
        print("\n" + "=" * 60)
        print("QUICK TEST")
        print("=" * 60)

        # Clear existing data
        print("\nClearing existing data...")
        self.postgres.clear()

        # Log 10 events
        print("\nLogging 10 test events...")
        for i in range(10):
            event = SecurityEvent.generate_random()
            result = self.postgres.log_event(event)
            status = "OK" if result.success else f"FAIL: {result.error}"
            print(f"  Event {i+1}: {result.latency_ms:.2f}ms - {status}")

        # Verify count
        count = self.postgres.get_count()
        print(f"\nTotal events in database: {count}")

        print("\n" + "=" * 60)
        print("QUICK TEST PASSED!")
        print("=" * 60)

    def run_full_experiment(self, tps_levels: List[int] = None):
        """Run the full experiment"""
        if tps_levels is None:
            tps_levels = [10, 25, 50, 100]

        print("\n" + "=" * 60)
        print("FULL EXPERIMENT")
        print("=" * 60)

        # Clear existing data
        print("\nClearing existing data...")
        self.postgres.clear()

        # Warmup
        print("\nWarmup (50 events)...")
        for _ in range(50):
            event = SecurityEvent.generate_random()
            self.postgres.log_event(event)
        print("  Warmup complete")

        # Latency test
        print("\n" + "-" * 60)
        print("LATENCY TEST (500 events)")
        print("-" * 60)
        latency_results = self.run_latency_test(500)

        print("\nLatency Results (PostgreSQL):")
        print(f"  Count: {latency_results['count']}")
        print(f"  Min:   {latency_results['min']:.2f} ms")
        print(f"  Avg:   {latency_results['avg']:.2f} ms")
        print(f"  P50:   {latency_results['p50']:.2f} ms")
        print(f"  P90:   {latency_results['p90']:.2f} ms")
        print(f"  P95:   {latency_results['p95']:.2f} ms")
        print(f"  P99:   {latency_results['p99']:.2f} ms")
        print(f"  Max:   {latency_results['max']:.2f} ms")

        # Throughput tests
        print("\n" + "-" * 60)
        print("THROUGHPUT TESTS")
        print("-" * 60)

        throughput_results = []
        for tps in tps_levels:
            self.postgres.clear()  # Fresh start for each TPS level
            result = self.run_throughput_test(tps, duration=30)
            throughput_results.append(result)

            print(f"\nResults at {tps} TPS:")
            print(f"  Actual TPS:    {result['actual_tps']:.1f}")
            print(f"  Success Rate:  {result['successful']}/{result['total_events']}")
            print(f"  Avg Latency:   {result['avg_latency_ms']:.2f} ms")
            print(f"  P95 Latency:   {result['p95_latency_ms']:.2f} ms")

        # Summary
        print("\n" + "=" * 60)
        print("EXPERIMENT SUMMARY")
        print("=" * 60)

        print("\n## PostgreSQL Baseline Results\n")
        print("### Latency (milliseconds)")
        print(f"| Metric | Value |")
        print(f"|--------|-------|")
        print(f"| P50    | {latency_results['p50']:.2f} |")
        print(f"| P95    | {latency_results['p95']:.2f} |")
        print(f"| P99    | {latency_results['p99']:.2f} |")

        print("\n### Throughput")
        print(f"| Target TPS | Actual TPS | P95 Latency |")
        print(f"|------------|------------|-------------|")
        for r in throughput_results:
            print(f"| {r['target_tps']:>10} | {r['actual_tps']:>10.1f} | {r['p95_latency_ms']:>11.2f} |")

        print("\n### Requirements Check")
        rt_pass = latency_results['p95'] < 100
        audit_pass = latency_results['p95'] < 5000
        print(f"| Requirement | Target | Actual | Status |")
        print(f"|-------------|--------|--------|--------|")
        print(f"| Real-time   | <100ms | {latency_results['p95']:.1f}ms | {'PASS' if rt_pass else 'FAIL'} |")
        print(f"| Audit       | <5000ms | {latency_results['p95']:.1f}ms | {'PASS' if audit_pass else 'FAIL'} |")

        print("\n" + "=" * 60)
        print("EXPERIMENT COMPLETE")
        print("=" * 60)


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="AAM Security Blockchain Experiment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py              # Quick test (10 events)
  python run.py --full       # Full experiment
  python run.py --tps 10 50  # Custom TPS levels

Prerequisites:
  1. Start PostgreSQL: docker-compose up -d postgres
  2. Install deps: pip install psycopg2-binary pandas numpy
        """
    )
    parser.add_argument('--full', action='store_true', help='Run full experiment')
    parser.add_argument('--tps', type=int, nargs='+', default=[10, 25, 50, 100],
                        help='TPS levels for throughput test')

    args = parser.parse_args()

    print("=" * 60)
    print("AAM SECURITY EXPERIMENT")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    runner = ExperimentRunner()

    if not runner.setup():
        print("\nSetup failed. Exiting.")
        sys.exit(1)

    try:
        if args.full:
            runner.run_full_experiment(args.tps)
        else:
            runner.run_quick_test()
    finally:
        runner.teardown()

    print(f"\nFinished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == '__main__':
    main()
