"""
AAM Security Event Generator

Generates security events from datasets for blockchain logging experiments.
Supports both real-time (burst) and audit (steady-state) patterns.
"""
import hashlib
import random
import time
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from pathlib import Path
from typing import Iterator, List, Optional, Generator
import pandas as pd
import numpy as np


class AttackType(IntEnum):
    """Attack types for security events"""
    GPS_SPOOF = 1
    DOS = 2
    MITM = 3
    REPLAY = 4
    GPS_JAM = 5
    EVIL_TWIN = 6


@dataclass
class SecurityEvent:
    """Normalized security event for cross-platform logging"""
    timestamp: int          # Detection time (ms since epoch)
    event_type: AttackType  # Attack classification
    confidence: int         # Detection confidence (0-100)
    vehicle_id: bytes       # 32-byte vehicle identifier (SHA-256)
    data_hash: bytes        # SHA-256 of original event data

    @classmethod
    def from_uav_attack_dataset(cls, row: dict) -> 'SecurityEvent':
        """Parse UAV Attack Dataset row"""
        # Map attack types
        attack_mapping = {
            'gps_spoofing': AttackType.GPS_SPOOF,
            'gps spoofing': AttackType.GPS_SPOOF,
            'ping_dos': AttackType.DOS,
            'dos': AttackType.DOS,
            'gps_jamming': AttackType.GPS_JAM,
            'jamming': AttackType.GPS_JAM,
        }

        attack_str = str(row.get('attack_type', row.get('attack', 'dos'))).lower()
        event_type = AttackType.DOS  # default

        for key, val in attack_mapping.items():
            if key in attack_str:
                event_type = val
                break

        return cls(
            timestamp=int(row.get('timestamp', time.time()) * 1000),
            event_type=event_type,
            confidence=int(row.get('confidence', 85)),
            vehicle_id=hashlib.sha256(str(row.get('vehicle_id', 'unknown')).encode()).digest(),
            data_hash=hashlib.sha256(str(row).encode()).digest()
        )

    @classmethod
    def from_cyber_physical_dataset(cls, row: dict) -> 'SecurityEvent':
        """Parse Cyber-Physical IoD Dataset row"""
        attack_mapping = {
            'dos': AttackType.DOS,
            'replay': AttackType.REPLAY,
            'false_data': AttackType.MITM,
            'evil_twin': AttackType.EVIL_TWIN,
        }

        attack_str = str(row.get('attack_type', 'dos')).lower()
        event_type = attack_mapping.get(attack_str, AttackType.DOS)

        return cls(
            timestamp=int(row.get('timestamp', time.time()) * 1000),
            event_type=event_type,
            confidence=int(row.get('label_confidence', 90)),
            vehicle_id=hashlib.sha256(str(row.get('drone_id', 'drone_1')).encode()).digest(),
            data_hash=hashlib.sha256(str(row).encode()).digest()
        )

    @classmethod
    def generate_random(cls, seed: Optional[int] = None) -> 'SecurityEvent':
        """Generate a random security event for testing"""
        if seed is not None:
            random.seed(seed)

        return cls(
            timestamp=int(time.time() * 1000),
            event_type=random.choice(list(AttackType)),
            confidence=random.randint(50, 100),
            vehicle_id=hashlib.sha256(f"vehicle_{random.randint(1, 100)}".encode()).digest(),
            data_hash=hashlib.sha256(f"data_{random.random()}".encode()).digest()
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'timestamp': self.timestamp,
            'event_type': int(self.event_type),
            'confidence': self.confidence,
            'vehicle_id': self.vehicle_id.hex(),
            'data_hash': self.data_hash.hex(),
        }


class EventGenerator:
    """Generates security events for experiment scenarios"""

    def __init__(
        self,
        seed: int = 42,
        dataset_path: Optional[Path] = None
    ):
        self.seed = seed
        self.rng = random.Random(seed)
        self.np_rng = np.random.default_rng(seed)
        self.dataset_path = dataset_path
        self._events_cache: List[SecurityEvent] = []

    def load_dataset(self, path: Path, dataset_type: str = 'uav_attack') -> List[SecurityEvent]:
        """Load and parse a dataset file"""
        df = pd.read_csv(path)
        events = []

        for _, row in df.iterrows():
            row_dict = row.to_dict()
            if dataset_type == 'uav_attack':
                events.append(SecurityEvent.from_uav_attack_dataset(row_dict))
            elif dataset_type == 'cyber_physical':
                events.append(SecurityEvent.from_cyber_physical_dataset(row_dict))
            else:
                events.append(SecurityEvent.from_uav_attack_dataset(row_dict))

        self._events_cache = events
        return events

    def generate_random_events(self, count: int) -> List[SecurityEvent]:
        """Generate random events for testing"""
        events = []
        for i in range(count):
            event = SecurityEvent(
                timestamp=int(time.time() * 1000) + i,
                event_type=self.rng.choice(list(AttackType)),
                confidence=self.rng.randint(50, 100),
                vehicle_id=hashlib.sha256(f"vehicle_{self.rng.randint(1, 100)}".encode()).digest(),
                data_hash=hashlib.sha256(f"data_{self.rng.random()}".encode()).digest()
            )
            events.append(event)
        return events

    def generate_burst(self, burst_size: int) -> List[SecurityEvent]:
        """Generate a burst of events (for real-time scenario)"""
        return self.generate_random_events(burst_size)

    def generate_steady_stream(
        self,
        tps: float,
        duration_seconds: float
    ) -> Generator[SecurityEvent, None, None]:
        """Generate a steady stream of events at specified TPS"""
        interval = 1.0 / tps if tps > 0 else 1.0
        total_events = int(tps * duration_seconds)

        for i in range(total_events):
            yield SecurityEvent(
                timestamp=int(time.time() * 1000),
                event_type=self.rng.choice(list(AttackType)),
                confidence=self.rng.randint(50, 100),
                vehicle_id=hashlib.sha256(f"vehicle_{self.rng.randint(1, 100)}".encode()).digest(),
                data_hash=hashlib.sha256(f"event_{i}_{self.rng.random()}".encode()).digest()
            )
            time.sleep(interval)

    def real_time_scenario(
        self,
        burst_size: int = 50,
        burst_interval: float = 1.0,
        duration_seconds: float = 60.0
    ) -> Generator[List[SecurityEvent], None, None]:
        """
        Generate events for real-time alert scenario (Scenario A)

        Produces bursts of events to simulate attack detection patterns.
        """
        start_time = time.time()

        while (time.time() - start_time) < duration_seconds:
            burst = self.generate_burst(burst_size)
            yield burst
            time.sleep(burst_interval)

    def audit_scenario(
        self,
        tps: float,
        duration_seconds: float = 300.0
    ) -> Generator[SecurityEvent, None, None]:
        """
        Generate events for audit trail scenario (Scenario B)

        Produces steady stream of events at specified TPS.
        """
        yield from self.generate_steady_stream(tps, duration_seconds)


class DatasetLoader:
    """Load and preprocess experiment datasets"""

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)

    def load_uav_attack_dataset(self, filename: str = 'uav_attacks.csv') -> pd.DataFrame:
        """Load UAV Attack Dataset"""
        path = self.data_dir / 'raw' / filename
        if path.exists():
            return pd.read_csv(path)
        return pd.DataFrame()

    def load_cyber_physical_dataset(self, filename: str = 'cyber_physical.csv') -> pd.DataFrame:
        """Load Cyber-Physical IoD Dataset"""
        path = self.data_dir / 'raw' / filename
        if path.exists():
            return pd.read_csv(path)
        return pd.DataFrame()

    def create_synthetic_dataset(
        self,
        num_events: int = 10000,
        output_file: str = 'synthetic_events.csv'
    ) -> pd.DataFrame:
        """Create synthetic dataset for testing"""
        generator = EventGenerator()
        events = generator.generate_random_events(num_events)

        data = []
        for event in events:
            data.append({
                'timestamp': event.timestamp / 1000,
                'event_type': event.event_type.name,
                'event_type_id': int(event.event_type),
                'confidence': event.confidence,
                'vehicle_id': event.vehicle_id.hex()[:16],
                'data_hash': event.data_hash.hex()
            })

        df = pd.DataFrame(data)

        output_path = self.data_dir / 'processed' / output_file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)

        return df


if __name__ == '__main__':
    # Test event generation
    generator = EventGenerator(seed=42)

    print("=== Testing Event Generation ===\n")

    # Generate random events
    events = generator.generate_random_events(5)
    print("Random Events:")
    for e in events:
        print(f"  Type: {e.event_type.name}, Confidence: {e.confidence}")

    # Test burst generation
    print("\n=== Testing Burst Generation ===")
    burst = generator.generate_burst(10)
    print(f"Generated burst of {len(burst)} events")

    # Test steady stream (short duration)
    print("\n=== Testing Steady Stream (2 seconds at 5 TPS) ===")
    count = 0
    for event in generator.generate_steady_stream(tps=5, duration_seconds=2):
        count += 1
    print(f"Generated {count} events")

    print("\n=== Event Generation Tests Complete ===")
