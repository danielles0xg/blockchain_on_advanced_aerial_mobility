"""
Unified Metrics Collection for AAM Security Experiment

Collects, stores, and analyzes experiment metrics across all platforms.
"""
import json
import sqlite3
import time
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
import statistics

import sys
sys.path.append(str(__file__).rsplit('/', 2)[0])
from config.settings import MetricsConfig, DEFAULT_CONFIG


@dataclass
class ExperimentMetric:
    """Single metric data point"""
    experiment_run_id: str
    system_name: str          # 'solana', 'hyperledger', 'postgresql'
    scenario: str             # 'real_time', 'audit_trail'
    event_id: Optional[int]
    submit_time: float        # Unix timestamp
    confirm_time: Optional[float]
    latency_ms: float
    tps_at_submission: Optional[float]
    batch_size: int
    success: bool
    error_message: Optional[str]
    block_number: Optional[int]
    tx_hash: Optional[str]


@dataclass
class ExperimentRun:
    """Experiment run metadata"""
    run_id: str
    scenario: str
    target_tps: Optional[int]
    duration_seconds: int
    start_time: float
    end_time: Optional[float]
    config: Dict[str, Any]
    notes: str


class MetricsCollector:
    """Collects and stores experiment metrics"""

    def __init__(self, config: Optional[MetricsConfig] = None):
        self.config = config or DEFAULT_CONFIG.metrics
        self.db_path = Path(self.config.db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

        self.current_run_id: Optional[str] = None
        self.run_metrics: List[ExperimentMetric] = []

    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS experiment_runs (
                run_id TEXT PRIMARY KEY,
                scenario TEXT NOT NULL,
                target_tps INTEGER,
                duration_seconds INTEGER,
                start_time REAL,
                end_time REAL,
                config TEXT,
                notes TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                experiment_run_id TEXT NOT NULL,
                system_name TEXT NOT NULL,
                scenario TEXT NOT NULL,
                event_id INTEGER,
                submit_time REAL NOT NULL,
                confirm_time REAL,
                latency_ms REAL NOT NULL,
                tps_at_submission REAL,
                batch_size INTEGER,
                success INTEGER,
                error_message TEXT,
                block_number INTEGER,
                tx_hash TEXT,
                FOREIGN KEY (experiment_run_id) REFERENCES experiment_runs(run_id)
            )
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_metrics_run ON metrics(experiment_run_id)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_metrics_system ON metrics(system_name)
        ''')

        conn.commit()
        conn.close()

    def start_run(
        self,
        scenario: str,
        target_tps: Optional[int] = None,
        duration_seconds: int = 60,
        config: Optional[Dict[str, Any]] = None,
        notes: str = ""
    ) -> str:
        """Start a new experiment run"""
        self.current_run_id = str(uuid.uuid4())
        self.run_metrics = []

        run = ExperimentRun(
            run_id=self.current_run_id,
            scenario=scenario,
            target_tps=target_tps,
            duration_seconds=duration_seconds,
            start_time=time.time(),
            end_time=None,
            config=config or {},
            notes=notes
        )

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO experiment_runs
            (run_id, scenario, target_tps, duration_seconds, start_time, config, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            run.run_id,
            run.scenario,
            run.target_tps,
            run.duration_seconds,
            run.start_time,
            json.dumps(run.config),
            run.notes
        ))
        conn.commit()
        conn.close()

        print(f"Started experiment run: {self.current_run_id}")
        return self.current_run_id

    def end_run(self):
        """End the current experiment run"""
        if not self.current_run_id:
            return

        # Flush any remaining metrics
        self._flush_metrics()

        # Update end time
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE experiment_runs SET end_time = ? WHERE run_id = ?
        ''', (time.time(), self.current_run_id))
        conn.commit()
        conn.close()

        print(f"Ended experiment run: {self.current_run_id}")
        self.current_run_id = None

    def record_metric(
        self,
        system_name: str,
        scenario: str,
        latency_ms: float,
        success: bool,
        event_id: Optional[int] = None,
        submit_time: Optional[float] = None,
        confirm_time: Optional[float] = None,
        tps_at_submission: Optional[float] = None,
        batch_size: int = 1,
        error_message: Optional[str] = None,
        block_number: Optional[int] = None,
        tx_hash: Optional[str] = None
    ):
        """Record a single metric"""
        if not self.current_run_id:
            raise ValueError("No active experiment run. Call start_run() first.")

        metric = ExperimentMetric(
            experiment_run_id=self.current_run_id,
            system_name=system_name,
            scenario=scenario,
            event_id=event_id,
            submit_time=submit_time or time.time(),
            confirm_time=confirm_time,
            latency_ms=latency_ms,
            tps_at_submission=tps_at_submission,
            batch_size=batch_size,
            success=success,
            error_message=error_message,
            block_number=block_number,
            tx_hash=tx_hash
        )

        self.run_metrics.append(metric)

        # Flush periodically
        if len(self.run_metrics) >= 100:
            self._flush_metrics()

    def _flush_metrics(self):
        """Write buffered metrics to database"""
        if not self.run_metrics:
            return

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for metric in self.run_metrics:
            cursor.execute('''
                INSERT INTO metrics
                (experiment_run_id, system_name, scenario, event_id, submit_time,
                 confirm_time, latency_ms, tps_at_submission, batch_size, success,
                 error_message, block_number, tx_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                metric.experiment_run_id,
                metric.system_name,
                metric.scenario,
                metric.event_id,
                metric.submit_time,
                metric.confirm_time,
                metric.latency_ms,
                metric.tps_at_submission,
                metric.batch_size,
                1 if metric.success else 0,
                metric.error_message,
                metric.block_number,
                metric.tx_hash
            ))

        conn.commit()
        conn.close()

        self.run_metrics = []


class MetricsAnalyzer:
    """Analyze collected experiment metrics"""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or Path(DEFAULT_CONFIG.metrics.db_path)

    def get_latency_percentiles(
        self,
        run_id: Optional[str] = None,
        system_name: Optional[str] = None,
        scenario: Optional[str] = None
    ) -> Dict[str, Dict[str, float]]:
        """Calculate latency percentiles"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = '''
            SELECT system_name, latency_ms
            FROM metrics
            WHERE success = 1
        '''
        params = []

        if run_id:
            query += ' AND experiment_run_id = ?'
            params.append(run_id)
        if system_name:
            query += ' AND system_name = ?'
            params.append(system_name)
        if scenario:
            query += ' AND scenario = ?'
            params.append(scenario)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        # Group by system
        systems = {}
        for system, latency in rows:
            if system not in systems:
                systems[system] = []
            systems[system].append(latency)

        # Calculate percentiles
        results = {}
        for system, latencies in systems.items():
            if latencies:
                sorted_latencies = sorted(latencies)
                n = len(sorted_latencies)

                results[system] = {
                    'count': n,
                    'min': min(sorted_latencies),
                    'max': max(sorted_latencies),
                    'avg': statistics.mean(sorted_latencies),
                    'stddev': statistics.stdev(sorted_latencies) if n > 1 else 0,
                    'p50': sorted_latencies[int(n * 0.50)],
                    'p90': sorted_latencies[int(n * 0.90)],
                    'p95': sorted_latencies[int(n * 0.95)],
                    'p99': sorted_latencies[int(n * 0.99)] if n > 100 else sorted_latencies[-1],
                }

        return results

    def get_throughput_stats(
        self,
        run_id: str
    ) -> Dict[str, Dict[str, float]]:
        """Calculate throughput statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT system_name,
                   COUNT(*) as total,
                   SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                   MIN(submit_time) as start_time,
                   MAX(submit_time) as end_time
            FROM metrics
            WHERE experiment_run_id = ?
            GROUP BY system_name
        ''', (run_id,))

        rows = cursor.fetchall()
        conn.close()

        results = {}
        for system, total, successful, start_time, end_time in rows:
            duration = end_time - start_time if end_time and start_time else 1
            results[system] = {
                'total_events': total,
                'successful_events': successful,
                'failed_events': total - successful,
                'success_rate': successful / total if total > 0 else 0,
                'duration_seconds': duration,
                'actual_tps': successful / duration if duration > 0 else 0,
            }

        return results

    def compare_systems(
        self,
        run_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Compare all systems"""
        latencies = self.get_latency_percentiles(run_id=run_id)

        comparison = {
            'latency': {},
            'meets_real_time': {},  # p95 < 100ms
            'meets_audit': {},      # p95 < 5000ms
        }

        for system, stats in latencies.items():
            comparison['latency'][system] = {
                'p50_ms': stats['p50'],
                'p95_ms': stats['p95'],
                'p99_ms': stats['p99'],
            }
            comparison['meets_real_time'][system] = stats['p95'] < 100
            comparison['meets_audit'][system] = stats['p95'] < 5000

        return comparison

    def generate_report(
        self,
        run_id: str,
        output_path: Optional[Path] = None
    ) -> str:
        """Generate a detailed experiment report"""
        latencies = self.get_latency_percentiles(run_id=run_id)
        throughput = self.get_throughput_stats(run_id=run_id)
        comparison = self.compare_systems(run_id=run_id)

        report = []
        report.append("=" * 70)
        report.append("AAM SECURITY EXPERIMENT REPORT")
        report.append(f"Run ID: {run_id}")
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append("=" * 70)

        report.append("\n## LATENCY ANALYSIS (milliseconds)\n")
        report.append(f"{'System':<15} {'Count':>8} {'P50':>10} {'P95':>10} {'P99':>10} {'Max':>10}")
        report.append("-" * 65)

        for system in ['postgresql', 'hyperledger', 'solana']:
            if system in latencies:
                stats = latencies[system]
                report.append(
                    f"{system:<15} {stats['count']:>8} {stats['p50']:>10.2f} "
                    f"{stats['p95']:>10.2f} {stats['p99']:>10.2f} {stats['max']:>10.2f}"
                )

        report.append("\n## THROUGHPUT ANALYSIS\n")
        report.append(f"{'System':<15} {'Total':>8} {'Success':>8} {'Failed':>8} {'TPS':>10}")
        report.append("-" * 55)

        for system in ['postgresql', 'hyperledger', 'solana']:
            if system in throughput:
                stats = throughput[system]
                report.append(
                    f"{system:<15} {stats['total_events']:>8} {stats['successful_events']:>8} "
                    f"{stats['failed_events']:>8} {stats['actual_tps']:>10.2f}"
                )

        report.append("\n## REQUIREMENTS COMPLIANCE\n")
        report.append(f"{'System':<15} {'Real-Time (<100ms)':>20} {'Audit (<5000ms)':>20}")
        report.append("-" * 55)

        for system in ['postgresql', 'hyperledger', 'solana']:
            if system in comparison['meets_real_time']:
                rt = "PASS" if comparison['meets_real_time'][system] else "FAIL"
                audit = "PASS" if comparison['meets_audit'][system] else "FAIL"
                report.append(f"{system:<15} {rt:>20} {audit:>20}")

        report.append("\n" + "=" * 70)

        report_text = "\n".join(report)

        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(report_text)
            print(f"Report saved to: {output_path}")

        return report_text


if __name__ == '__main__':
    print("=== Testing Metrics Collector ===\n")

    collector = MetricsCollector()

    # Start a test run
    run_id = collector.start_run(
        scenario='test',
        target_tps=100,
        duration_seconds=10,
        notes='Test run for metrics collector'
    )

    # Simulate some metrics
    import random

    for i in range(100):
        system = random.choice(['postgresql', 'hyperledger', 'solana'])

        # Simulate realistic latencies
        if system == 'postgresql':
            latency = random.uniform(1, 10)
        elif system == 'hyperledger':
            latency = random.uniform(200, 800)
        else:  # solana
            latency = random.uniform(400, 1200)

        collector.record_metric(
            system_name=system,
            scenario='test',
            latency_ms=latency,
            success=random.random() > 0.05,  # 95% success rate
            event_id=i
        )

    collector.end_run()

    # Analyze results
    print("\n=== Analyzing Results ===\n")

    analyzer = MetricsAnalyzer()
    report = analyzer.generate_report(run_id)
    print(report)

    print("\n=== Metrics Collector Tests Complete ===")
