"""
Hyperledger Fabric Client for AAM Security Experiment

Interacts with the AAM Security chaincode on Hyperledger Fabric.
"""
import asyncio
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Any
import subprocess
import os

import sys
sys.path.append(str(__file__).rsplit('/', 3)[0])
from event_generator.generator import SecurityEvent
from config.settings import HyperledgerConfig, DEFAULT_CONFIG


@dataclass
class TransactionResult:
    """Result of a Fabric transaction"""
    tx_id: str
    block_number: int
    latency_ms: float
    success: bool
    error_message: Optional[str] = None
    endorsement_time_ms: Optional[float] = None
    commit_time_ms: Optional[float] = None
    response: Optional[Dict[str, Any]] = None


class FabricCLIClient:
    """
    Fabric client using peer CLI commands.

    For production, use the Fabric SDK (fabric-gateway or fabric-sdk-py).
    This CLI-based approach is simpler for testing.
    """

    def __init__(self, config: Optional[HyperledgerConfig] = None):
        self.config = config or DEFAULT_CONFIG.hyperledger
        self.env = self._setup_environment()

    def _setup_environment(self) -> dict:
        """Setup environment variables for peer CLI"""
        env = os.environ.copy()

        # Core peer settings
        env['CORE_PEER_ADDRESS'] = self.config.peer_endpoint
        env['CORE_PEER_LOCALMSPID'] = self.config.msp_id
        env['CORE_PEER_TLS_ENABLED'] = 'true'

        if self.config.cert_path:
            env['CORE_PEER_MSPCONFIGPATH'] = self.config.cert_path
        if self.config.tls_ca_cert_path:
            env['CORE_PEER_TLS_ROOTCERT_FILE'] = self.config.tls_ca_cert_path

        return env

    def _run_peer_command(self, args: List[str], timeout: int = 30) -> tuple:
        """Execute a peer CLI command"""
        cmd = ['peer'] + args
        try:
            result = subprocess.run(
                cmd,
                env=self.env,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, '', 'Command timed out'
        except Exception as e:
            return False, '', str(e)

    def invoke_chaincode(
        self,
        function: str,
        args: List[str],
        wait_for_event: bool = True
    ) -> TransactionResult:
        """Invoke chaincode function"""
        start_time = time.perf_counter()

        # Build invoke command
        cmd_args = [
            'chaincode', 'invoke',
            '-o', self.config.orderer_endpoint,
            '-C', self.config.channel_name,
            '-n', self.config.chaincode_name,
            '-c', json.dumps({'function': function, 'Args': args}),
            '--tls',
            '--cafile', self.config.tls_ca_cert_path,
        ]

        if wait_for_event:
            cmd_args.extend(['--waitForEvent'])

        success, stdout, stderr = self._run_peer_command(cmd_args)

        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000

        if success:
            # Parse transaction ID from output
            tx_id = ''
            for line in stdout.split('\n'):
                if 'txid' in line.lower():
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if 'txid' in part.lower() and i + 1 < len(parts):
                            tx_id = parts[i + 1].strip('[]')
                            break

            return TransactionResult(
                tx_id=tx_id or 'unknown',
                block_number=0,
                latency_ms=latency_ms,
                success=True,
                response={'stdout': stdout}
            )
        else:
            return TransactionResult(
                tx_id='',
                block_number=0,
                latency_ms=latency_ms,
                success=False,
                error_message=stderr or stdout
            )

    def query_chaincode(self, function: str, args: List[str]) -> TransactionResult:
        """Query chaincode (read-only)"""
        start_time = time.perf_counter()

        cmd_args = [
            'chaincode', 'query',
            '-C', self.config.channel_name,
            '-n', self.config.chaincode_name,
            '-c', json.dumps({'function': function, 'Args': args}),
        ]

        success, stdout, stderr = self._run_peer_command(cmd_args)

        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000

        if success:
            try:
                response = json.loads(stdout)
            except json.JSONDecodeError:
                response = {'raw': stdout}

            return TransactionResult(
                tx_id='query',
                block_number=0,
                latency_ms=latency_ms,
                success=True,
                response=response
            )
        else:
            return TransactionResult(
                tx_id='',
                block_number=0,
                latency_ms=latency_ms,
                success=False,
                error_message=stderr or stdout
            )

    def log_security_event(self, event: SecurityEvent) -> TransactionResult:
        """Log a security event to the chaincode"""
        submit_time = int(time.time() * 1000)

        args = [
            str(event.timestamp),
            str(int(event.event_type)),
            str(event.confidence),
            event.vehicle_id.hex(),
            event.data_hash.hex(),
            str(submit_time)
        ]

        return self.invoke_chaincode('LogSecurityEvent', args)

    def log_batch_events(self, events: List[SecurityEvent]) -> TransactionResult:
        """Log multiple events in a single transaction"""
        submit_time = int(time.time() * 1000)

        events_json = json.dumps([
            {
                'eventTimestamp': event.timestamp,
                'eventType': int(event.event_type),
                'confidence': event.confidence,
                'vehicleId': event.vehicle_id.hex(),
                'dataHash': event.data_hash.hex(),
                'submitTime': submit_time
            }
            for event in events
        ])

        return self.invoke_chaincode('LogBatchEvents', [events_json])

    def get_event(self, event_id: int) -> TransactionResult:
        """Get a specific event by ID"""
        return self.query_chaincode('GetEvent', [str(event_id)])

    def get_event_count(self) -> int:
        """Get total number of events"""
        result = self.query_chaincode('GetEventCount', [])
        if result.success and result.response:
            try:
                return int(result.response.get('raw', result.response))
            except (ValueError, TypeError):
                return 0
        return 0

    def init_ledger(self) -> TransactionResult:
        """Initialize the ledger"""
        return self.invoke_chaincode('InitLedger', [])


class FabricSDKClient:
    """
    Fabric client using the fabric-gateway SDK.

    This is the recommended approach for production applications.
    Requires: pip install fabric-gateway
    """

    def __init__(self, config: Optional[HyperledgerConfig] = None):
        self.config = config or DEFAULT_CONFIG.hyperledger
        self.gateway = None
        self.network = None
        self.contract = None

    async def connect(self):
        """Connect to Fabric network using gateway"""
        try:
            from grpc import aio as grpc_aio
            from fabric_gateway import Gateway, identity

            # Load credentials
            cert_path = Path(self.config.cert_path)
            key_path = Path(self.config.key_path)
            tls_cert_path = Path(self.config.tls_ca_cert_path)

            with open(cert_path, 'rb') as f:
                certificate = f.read()
            with open(key_path, 'rb') as f:
                private_key = f.read()
            with open(tls_cert_path, 'rb') as f:
                tls_root_cert = f.read()

            # Create identity and sign
            id = identity.X509Identity(self.config.msp_id, certificate)
            signer = identity.Signer(private_key)

            # Create gRPC channel
            channel = grpc_aio.secure_channel(
                self.config.peer_endpoint,
                grpc_aio.ssl_channel_credentials(tls_root_cert)
            )

            # Connect gateway
            self.gateway = Gateway(channel, id, signer)
            self.network = await self.gateway.get_network(self.config.channel_name)
            self.contract = self.network.get_contract(self.config.chaincode_name)

            print(f"Connected to Fabric network: {self.config.channel_name}")

        except ImportError:
            print("fabric-gateway not installed. Using CLI client instead.")
            raise

    async def disconnect(self):
        """Disconnect from network"""
        if self.gateway:
            self.gateway.close()
            self.gateway = None
            self.network = None
            self.contract = None

    async def log_security_event(self, event: SecurityEvent) -> TransactionResult:
        """Log a security event using the SDK"""
        start_time = time.perf_counter()
        submit_time = int(time.time() * 1000)

        try:
            result = await self.contract.submit_transaction(
                'LogSecurityEvent',
                str(event.timestamp),
                str(int(event.event_type)),
                str(event.confidence),
                event.vehicle_id.hex(),
                event.data_hash.hex(),
                str(submit_time)
            )

            end_time = time.perf_counter()

            response = json.loads(result.decode()) if result else {}

            return TransactionResult(
                tx_id=response.get('txId', 'unknown'),
                block_number=0,
                latency_ms=(end_time - start_time) * 1000,
                success=True,
                response=response
            )

        except Exception as e:
            end_time = time.perf_counter()
            return TransactionResult(
                tx_id='',
                block_number=0,
                latency_ms=(end_time - start_time) * 1000,
                success=False,
                error_message=str(e)
            )

    async def log_events_concurrent(
        self,
        events: List[SecurityEvent],
        max_concurrent: int = 10
    ) -> List[TransactionResult]:
        """Log multiple events concurrently"""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def log_with_semaphore(event: SecurityEvent) -> TransactionResult:
            async with semaphore:
                return await self.log_security_event(event)

        tasks = [log_with_semaphore(event) for event in events]
        return await asyncio.gather(*tasks)

    async def get_event_count(self) -> int:
        """Get total number of events"""
        try:
            result = await self.contract.evaluate_transaction('GetEventCount')
            return int(result.decode())
        except Exception:
            return 0


def get_fabric_client(use_sdk: bool = False) -> FabricCLIClient:
    """Factory function to get appropriate Fabric client"""
    if use_sdk:
        try:
            return FabricSDKClient()
        except ImportError:
            print("SDK not available, falling back to CLI client")

    return FabricCLIClient()


if __name__ == '__main__':
    print("=== Testing Hyperledger Fabric Client ===\n")

    # Test CLI client (simulated - requires running Fabric network)
    print("Testing CLI client...")
    client = FabricCLIClient()

    # Note: These will fail without a running Fabric network
    # This is just to demonstrate the API

    from event_generator.generator import EventGenerator
    generator = EventGenerator()

    print("\nGenerating test event...")
    event = generator.generate_random_events(1)[0]
    print(f"  Type: {event.event_type.name}")
    print(f"  Confidence: {event.confidence}")
    print(f"  Vehicle ID: {event.vehicle_id.hex()[:16]}...")

    print("\nTo test with real network:")
    print("  1. Start the Fabric network using Terraform")
    print("  2. Deploy the AAM Security chaincode")
    print("  3. Run: result = client.log_security_event(event)")

    print("\n=== Hyperledger Fabric Client Tests Complete ===")
