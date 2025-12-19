#!/usr/bin/env python3
"""
AAM Security Experiment Runner

Main entry point for running blockchain performance experiments.
Compares Solana, Hyperledger Fabric, and PostgreSQL for AAM security logging.
"""
import argparse
import asyncio
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from config.settings import (
    ExperimentConfig,
    RealTimeScenarioConfig,
    AuditScenarioConfig,
    DEFAULT_CONFIG
)
from event_generator.generator import EventGenerator, SecurityEvent
from clients.postgres_client.client import PostgresClient, AsyncPostgresClient
from clients.solana_client.client import SolanaClient
from clients.fabric_client.client import FabricCLIClient
from metrics.collector import MetricsCollector, MetricsAnalyzer


class ExperimentRunner:
    """Orchestrates experiment execution across all platforms"""

    def __init__(self, config: Optional[ExperimentConfig] = None):
        self.config = config or DEFAULT_CONFIG
        self.generator = EventGenerator(seed=self.config.random_seed)
        self.metrics = MetricsCollector()
        self.analyzer = MetricsAnalyzer()

        # Clients (initialized lazily)
        self.postgres_client: Optional[PostgresClient] = None
        self.postgres_async: Optional[AsyncPostgresClient] = None
        self.solana_client: Optional[SolanaClient] = None
        self.fabric_client: Optional[FabricCLIClient] = None

    async def setup_clients(self, systems: List[str]):
        """Initialize clients for specified systems"""
        print("\n=== Setting up clients ===")

        if 'postgresql' in systems:
            print("Connecting to PostgreSQL...")
            self.postgres_client = PostgresClient(self.config.postgres)
            self.postgres_client.connect()
            self.postgres_async = AsyncPostgresClient(self.config.postgres)
            await self.postgres_async.connect()
            print(f"  Connected: {self.config.postgres.host}:{self.config.postgres.port}")

        if 'solana' in systems:
            print("Connecting to Solana...")
            self.solana_client = SolanaClient(self.config.solana)
            await self.solana_client.connect()
            balance = await self.solana_client.get_balance()
            print(f"  Connected: {self.config.solana.rpc_url}")
            print(f"  Balance: {balance} SOL")

            if balance < 0.5:
                print("  Requesting airdrop...")
                await self.solana_client.request_airdrop(2.0)

        if 'hyperledger' in systems:
            print("Setting up Hyperledger Fabric client...")
            self.fabric_client = FabricCLIClient(self.config.hyperledger)
            print(f"  Peer: {self.config.hyperledger.peer_endpoint}")
            print(f"  Channel: {self.config.hyperledger.channel_name}")

    async def teardown_clients(self):
        """Close all client connections"""
        print("\n=== Tearing down clients ===")

        if self.postgres_client:
            self.postgres_client.disconnect()
        if self.postgres_async:
            await self.postgres_async.disconnect()
        if self.solana_client:
            await self.solana_client.disconnect()

        print("All clients disconnected")

    async def warmup(self, systems: List[str], count: int = 100):
        """Warmup all systems before experiment"""
        print(f"\n=== Warmup ({count} events per system) ===")
        events = self.generator.generate_random_events(count)

        for system in systems:
            print(f"Warming up {system}...")
            start = time.time()

            if system == 'postgresql' and self.postgres_client:
                for event in events[:count]:
                    self.postgres_client.log_event(event)

            elif system == 'solana' and self.solana_client:
                for event in events[:min(10, count)]:  # Fewer for Solana due to cost
                    await self.solana_client.log_security_event(event)

            elif system == 'hyperledger' and self.fabric_client:
                for event in events[:min(10, count)]:
                    self.fabric_client.log_security_event(event)

            elapsed = time.time() - start
            print(f"  Completed in {elapsed:.2f}s")

    async def run_real_time_scenario(
        self,
        systems: List[str],
        config: Optional[RealTimeScenarioConfig] = None
    ):
        """
        Run Scenario A: Real-Time Security Alerts

        Tests burst patterns with target p95 < 100ms
        """
        config = config or self.config.real_time

        print("\n" + "=" * 70)
        print("SCENARIO A: REAL-TIME SECURITY ALERTS")
        print(f"  Target: p95 < {config.target_latency_p95_ms}ms")
        print(f"  Burst Size: {config.burst_size}")
        print(f"  Duration: {config.test_duration_sec}s")
        print("=" * 70)

        run_id = self.metrics.start_run(
            scenario='real_time',
            target_tps=config.burst_size,
            duration_seconds=config.test_duration_sec,
            config={
                'burst_size': config.burst_size,
                'burst_interval': config.burst_interval_sec,
                'target_p95_ms': config.target_latency_p95_ms
            }
        )

        start_time = time.time()

        # Generate bursts
        burst_count = 0
        while (time.time() - start_time) < config.test_duration_sec:
            burst_count += 1
            burst = self.generator.generate_burst(config.burst_size)

            print(f"\nBurst {burst_count}: {len(burst)} events")

            for system in systems:
                await self._log_events_to_system(system, burst, 'real_time')

            # Wait for next burst
            await asyncio.sleep(config.burst_interval_sec)

        self.metrics.end_run()

        # Generate report
        print("\n" + "-" * 70)
        print("SCENARIO A RESULTS")
        print("-" * 70)
        report = self.analyzer.generate_report(
            run_id,
            output_path=Path(f"results/reports/real_time_{run_id[:8]}.txt")
        )
        print(report)

        return run_id

    async def run_audit_scenario(
        self,
        systems: List[str],
        config: Optional[AuditScenarioConfig] = None
    ):
        """
        Run Scenario B: Audit Trail Logging

        Tests steady-state TPS with target p95 < 5000ms
        """
        config = config or self.config.audit

        print("\n" + "=" * 70)
        print("SCENARIO B: AUDIT TRAIL LOGGING")
        print(f"  Target: p95 < {config.target_latency_p95_ms}ms")
        print(f"  TPS Levels: {config.tps_levels}")
        print(f"  Duration per TPS: {config.test_duration_per_tps_sec}s")
        print("=" * 70)

        results = {}

        for tps in config.tps_levels:
            print(f"\n--- Testing at {tps} TPS ---")

            run_id = self.metrics.start_run(
                scenario='audit_trail',
                target_tps=tps,
                duration_seconds=config.test_duration_per_tps_sec,
                config={
                    'target_tps': tps,
                    'target_p95_ms': config.target_latency_p95_ms
                }
            )

            interval = 1.0 / tps
            start_time = time.time()
            event_count = 0

            while (time.time() - start_time) < config.test_duration_per_tps_sec:
                event = self.generator.generate_random_events(1)[0]

                for system in systems:
                    await self._log_event_to_system(system, event, 'audit_trail')

                event_count += 1

                # Rate limiting
                elapsed = time.time() - start_time
                expected_time = event_count * interval
                if elapsed < expected_time:
                    await asyncio.sleep(expected_time - elapsed)

                # Progress
                if event_count % 100 == 0:
                    actual_tps = event_count / elapsed
                    print(f"  Events: {event_count}, Actual TPS: {actual_tps:.1f}")

            self.metrics.end_run()

            # Analyze this TPS level
            latencies = self.analyzer.get_latency_percentiles(run_id=run_id)
            results[tps] = {
                'run_id': run_id,
                'latencies': latencies
            }

            # Cool down
            print(f"  Cooling down ({self.config.cooldown_seconds}s)...")
            await asyncio.sleep(self.config.cooldown_seconds)

        # Summary report
        print("\n" + "=" * 70)
        print("SCENARIO B SUMMARY")
        print("=" * 70)

        print(f"\n{'TPS':>6} | {'System':<12} | {'P50':>8} | {'P95':>8} | {'Status':<8}")
        print("-" * 55)

        for tps, data in results.items():
            for system, stats in data['latencies'].items():
                status = "PASS" if stats['p95'] < config.target_latency_p95_ms else "FAIL"
                print(f"{tps:>6} | {system:<12} | {stats['p50']:>8.1f} | {stats['p95']:>8.1f} | {status:<8}")

        return results

    async def _log_event_to_system(
        self,
        system: str,
        event: SecurityEvent,
        scenario: str
    ):
        """Log a single event to a specific system"""
        submit_time = time.time()

        if system == 'postgresql' and self.postgres_client:
            result = self.postgres_client.log_event(event)
            self.metrics.record_metric(
                system_name='postgresql',
                scenario=scenario,
                latency_ms=result.latency_ms,
                success=result.success,
                event_id=result.event_id,
                submit_time=submit_time,
                error_message=result.error_message
            )

        elif system == 'solana' and self.solana_client:
            result = await self.solana_client.log_security_event(event)
            self.metrics.record_metric(
                system_name='solana',
                scenario=scenario,
                latency_ms=result.latency_ms,
                success=result.success,
                submit_time=submit_time,
                block_number=result.slot,
                tx_hash=result.signature,
                error_message=result.error_message
            )

        elif system == 'hyperledger' and self.fabric_client:
            result = self.fabric_client.log_security_event(event)
            self.metrics.record_metric(
                system_name='hyperledger',
                scenario=scenario,
                latency_ms=result.latency_ms,
                success=result.success,
                submit_time=submit_time,
                block_number=result.block_number,
                tx_hash=result.tx_id,
                error_message=result.error_message
            )

    async def _log_events_to_system(
        self,
        system: str,
        events: List[SecurityEvent],
        scenario: str
    ):
        """Log multiple events to a system"""
        for event in events:
            await self._log_event_to_system(system, event, scenario)


async def main():
    parser = argparse.ArgumentParser(
        description='AAM Security Blockchain Experiment Runner'
    )
    parser.add_argument(
        '--systems',
        nargs='+',
        choices=['postgresql', 'solana', 'hyperledger'],
        default=['postgresql'],
        help='Systems to test'
    )
    parser.add_argument(
        '--scenario',
        choices=['real_time', 'audit', 'both'],
        default='both',
        help='Scenario to run'
    )
    parser.add_argument(
        '--warmup',
        type=int,
        default=100,
        help='Warmup event count'
    )
    parser.add_argument(
        '--duration',
        type=int,
        default=60,
        help='Test duration in seconds'
    )
    parser.add_argument(
        '--tps',
        type=int,
        nargs='+',
        default=[10, 25, 50],
        help='TPS levels for audit scenario'
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path('results'),
        help='Output directory for results'
    )

    args = parser.parse_args()

    print("=" * 70)
    print("AAM SECURITY BLOCKCHAIN EXPERIMENT")
    print(f"Started: {datetime.now().isoformat()}")
    print("=" * 70)
    print(f"Systems: {', '.join(args.systems)}")
    print(f"Scenario: {args.scenario}")
    print(f"Duration: {args.duration}s")

    # Create output directories
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / 'metrics').mkdir(exist_ok=True)
    (args.output_dir / 'reports').mkdir(exist_ok=True)

    # Run experiment
    runner = ExperimentRunner()

    try:
        await runner.setup_clients(args.systems)

        if args.warmup > 0:
            await runner.warmup(args.systems, args.warmup)

        if args.scenario in ['real_time', 'both']:
            real_time_config = RealTimeScenarioConfig(
                test_duration_sec=args.duration
            )
            await runner.run_real_time_scenario(args.systems, real_time_config)

        if args.scenario in ['audit', 'both']:
            audit_config = AuditScenarioConfig(
                tps_levels=args.tps,
                test_duration_per_tps_sec=args.duration
            )
            await runner.run_audit_scenario(args.systems, audit_config)

    finally:
        await runner.teardown_clients()

    print("\n" + "=" * 70)
    print("EXPERIMENT COMPLETE")
    print(f"Ended: {datetime.now().isoformat()}")
    print("=" * 70)


if __name__ == '__main__':
    asyncio.run(main())
