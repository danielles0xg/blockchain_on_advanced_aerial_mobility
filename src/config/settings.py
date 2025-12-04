"""
AAM Security Experiment Configuration Settings
"""
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional
import os


class AttackType(IntEnum):
    """Attack types matching smart contract definitions"""
    GPS_SPOOF = 1
    DOS = 2
    MITM = 3
    REPLAY = 4
    GPS_JAM = 5
    EVIL_TWIN = 6


@dataclass
class PostgresConfig:
    """PostgreSQL connection configuration"""
    host: str = "localhost"
    port: int = 5432
    database: str = "aam_security"
    user: str = "aam_user"
    password: str = "aam_password"

    @property
    def connection_string(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"


@dataclass
class SolanaConfig:
    """Solana connection configuration"""
    rpc_url: str = "http://localhost:8899"
    ws_url: str = "ws://localhost:8900"
    program_id: str = "AAMSec111111111111111111111111111111111111"
    keypair_path: str = "~/.config/solana/id.json"
    commitment: str = "confirmed"  # processed, confirmed, finalized


@dataclass
class HyperledgerConfig:
    """Hyperledger Fabric connection configuration"""
    peer_endpoint: str = "localhost:7051"
    orderer_endpoint: str = "localhost:7050"
    channel_name: str = "aamchannel"
    chaincode_name: str = "aam_security"
    msp_id: str = "Org1MSP"
    cert_path: str = ""
    key_path: str = ""
    tls_ca_cert_path: str = ""


@dataclass
class MetricsConfig:
    """Metrics collection configuration"""
    db_path: str = "results/metrics/experiment_metrics.db"
    prometheus_port: int = 9090
    grafana_port: int = 3000


@dataclass
class RealTimeScenarioConfig:
    """Configuration for real-time alert scenario (Scenario A)"""
    target_latency_p95_ms: int = 100
    burst_size: int = 50
    burst_interval_sec: float = 1.0
    test_duration_sec: int = 60
    success_criteria: str = "p95 < 100ms"


@dataclass
class AuditScenarioConfig:
    """Configuration for audit trail scenario (Scenario B)"""
    target_latency_p95_ms: int = 5000
    tps_levels: list = field(default_factory=lambda: [10, 25, 50, 100, 200, 500])
    test_duration_per_tps_sec: int = 300
    success_criteria: str = "p95 < 5000ms"


@dataclass
class ExperimentConfig:
    """Main experiment configuration"""
    postgres: PostgresConfig = field(default_factory=PostgresConfig)
    solana: SolanaConfig = field(default_factory=SolanaConfig)
    hyperledger: HyperledgerConfig = field(default_factory=HyperledgerConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    real_time: RealTimeScenarioConfig = field(default_factory=RealTimeScenarioConfig)
    audit: AuditScenarioConfig = field(default_factory=AuditScenarioConfig)

    # General settings
    random_seed: int = 42
    warmup_events: int = 100
    cooldown_seconds: int = 30

    @classmethod
    def from_env(cls) -> 'ExperimentConfig':
        """Create configuration from environment variables"""
        config = cls()

        # PostgreSQL
        config.postgres.host = os.getenv("POSTGRES_HOST", config.postgres.host)
        config.postgres.port = int(os.getenv("POSTGRES_PORT", config.postgres.port))
        config.postgres.database = os.getenv("POSTGRES_DB", config.postgres.database)
        config.postgres.user = os.getenv("POSTGRES_USER", config.postgres.user)
        config.postgres.password = os.getenv("POSTGRES_PASSWORD", config.postgres.password)

        # Solana
        config.solana.rpc_url = os.getenv("SOLANA_RPC_URL", config.solana.rpc_url)
        config.solana.program_id = os.getenv("SOLANA_PROGRAM_ID", config.solana.program_id)

        # Hyperledger
        config.hyperledger.peer_endpoint = os.getenv("FABRIC_PEER_ENDPOINT", config.hyperledger.peer_endpoint)
        config.hyperledger.channel_name = os.getenv("FABRIC_CHANNEL", config.hyperledger.channel_name)

        return config


# Default configuration instance
DEFAULT_CONFIG = ExperimentConfig()
