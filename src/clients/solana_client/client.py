"""
Solana Client for AAM Security Experiment

Interacts with the AAM Security Log Solana program.
"""
import asyncio
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple
import struct

# Solana Python SDK
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.system_program import ID as SYSTEM_PROGRAM_ID
from solana.rpc.async_api import AsyncClient
from solana.rpc.commitment import Confirmed, Finalized, Processed
from solana.transaction import Transaction

import sys
sys.path.append(str(__file__).rsplit('/', 3)[0])
from event_generator.generator import SecurityEvent
from config.settings import SolanaConfig, DEFAULT_CONFIG


@dataclass
class TransactionResult:
    """Result of a Solana transaction"""
    signature: str
    slot: int
    latency_ms: float
    success: bool
    error_message: Optional[str] = None
    confirmation_time_ms: Optional[float] = None


class SolanaClient:
    """Solana client for AAM security event logging"""

    def __init__(self, config: Optional[SolanaConfig] = None):
        self.config = config or DEFAULT_CONFIG.solana
        self.client: Optional[AsyncClient] = None
        self.payer: Optional[Keypair] = None
        self.program_id: Optional[Pubkey] = None
        self.counter_pda: Optional[Pubkey] = None
        self.counter_bump: Optional[int] = None

    async def connect(self):
        """Connect to Solana cluster"""
        self.client = AsyncClient(self.config.rpc_url)
        self.program_id = Pubkey.from_string(self.config.program_id)

        # Load payer keypair
        keypair_path = Path(self.config.keypair_path).expanduser()
        if keypair_path.exists():
            with open(keypair_path, 'r') as f:
                keypair_data = json.load(f)
                self.payer = Keypair.from_bytes(bytes(keypair_data))
        else:
            # Generate new keypair for testing
            self.payer = Keypair()
            print(f"Generated new keypair: {self.payer.pubkey()}")

        # Derive counter PDA
        self.counter_pda, self.counter_bump = Pubkey.find_program_address(
            [b"counter"],
            self.program_id
        )

        # Check connection
        version = await self.client.get_version()
        print(f"Connected to Solana: {version.value.solana_core}")

    async def disconnect(self):
        """Close connection"""
        if self.client:
            await self.client.close()
            self.client = None

    async def request_airdrop(self, amount_sol: float = 2.0) -> str:
        """Request airdrop for testing on localnet/devnet"""
        lamports = int(amount_sol * 1_000_000_000)
        response = await self.client.request_airdrop(
            self.payer.pubkey(),
            lamports
        )
        signature = response.value

        # Wait for confirmation
        await self.client.confirm_transaction(signature)
        return str(signature)

    async def get_balance(self) -> float:
        """Get SOL balance"""
        response = await self.client.get_balance(self.payer.pubkey())
        return response.value / 1_000_000_000

    async def initialize_program(self) -> TransactionResult:
        """Initialize the program counter (call once after deployment)"""
        start_time = time.perf_counter()

        try:
            # Build initialize instruction
            # Discriminator for 'initialize' in Anchor
            discriminator = bytes([175, 175, 109, 31, 13, 152, 155, 237])

            instruction_data = discriminator

            # Create instruction
            from solders.instruction import Instruction, AccountMeta

            accounts = [
                AccountMeta(self.counter_pda, is_signer=False, is_writable=True),
                AccountMeta(self.payer.pubkey(), is_signer=True, is_writable=True),
                AccountMeta(SYSTEM_PROGRAM_ID, is_signer=False, is_writable=False),
            ]

            instruction = Instruction(
                self.program_id,
                instruction_data,
                accounts
            )

            # Build and send transaction
            from solana.rpc.types import TxOpts
            from solders.message import Message
            from solders.transaction import Transaction as SoldersTransaction

            blockhash_resp = await self.client.get_latest_blockhash()
            recent_blockhash = blockhash_resp.value.blockhash

            msg = Message.new_with_blockhash(
                [instruction],
                self.payer.pubkey(),
                recent_blockhash
            )
            tx = SoldersTransaction.new([self.payer], msg, recent_blockhash)

            response = await self.client.send_transaction(
                tx,
                opts=TxOpts(skip_preflight=False)
            )

            signature = response.value
            confirm_start = time.perf_counter()

            # Wait for confirmation
            await self.client.confirm_transaction(signature)

            end_time = time.perf_counter()

            return TransactionResult(
                signature=str(signature),
                slot=0,
                latency_ms=(end_time - start_time) * 1000,
                success=True,
                confirmation_time_ms=(end_time - confirm_start) * 1000
            )

        except Exception as e:
            end_time = time.perf_counter()
            return TransactionResult(
                signature="",
                slot=0,
                latency_ms=(end_time - start_time) * 1000,
                success=False,
                error_message=str(e)
            )

    async def log_security_event(self, event: SecurityEvent) -> TransactionResult:
        """Log a security event to the Solana blockchain"""
        start_time = time.perf_counter()

        try:
            from solders.instruction import Instruction, AccountMeta
            from solders.message import Message
            from solders.transaction import Transaction as SoldersTransaction
            from solana.rpc.types import TxOpts

            # Generate new account for the event
            event_account = Keypair()

            # Anchor discriminator for 'log_security_event'
            discriminator = bytes([245, 247, 108, 165, 208, 92, 0, 54])

            # Serialize instruction data
            instruction_data = discriminator
            instruction_data += struct.pack('<q', event.timestamp)  # i64
            instruction_data += struct.pack('<B', int(event.event_type))  # u8
            instruction_data += struct.pack('<B', event.confidence)  # u8
            instruction_data += event.vehicle_id  # [u8; 32]
            instruction_data += event.data_hash  # [u8; 32]

            accounts = [
                AccountMeta(event_account.pubkey(), is_signer=True, is_writable=True),
                AccountMeta(self.counter_pda, is_signer=False, is_writable=True),
                AccountMeta(self.payer.pubkey(), is_signer=True, is_writable=True),
                AccountMeta(SYSTEM_PROGRAM_ID, is_signer=False, is_writable=False),
            ]

            instruction = Instruction(
                self.program_id,
                instruction_data,
                accounts
            )

            blockhash_resp = await self.client.get_latest_blockhash()
            recent_blockhash = blockhash_resp.value.blockhash

            msg = Message.new_with_blockhash(
                [instruction],
                self.payer.pubkey(),
                recent_blockhash
            )
            tx = SoldersTransaction.new(
                [self.payer, event_account],
                msg,
                recent_blockhash
            )

            response = await self.client.send_transaction(
                tx,
                opts=TxOpts(skip_preflight=False)
            )

            signature = response.value
            confirm_start = time.perf_counter()

            # Wait for confirmation based on commitment
            if self.config.commitment == 'finalized':
                await self.client.confirm_transaction(signature, commitment=Finalized)
            else:
                await self.client.confirm_transaction(signature)

            end_time = time.perf_counter()

            # Get slot
            tx_info = await self.client.get_transaction(signature)
            slot = tx_info.value.slot if tx_info.value else 0

            return TransactionResult(
                signature=str(signature),
                slot=slot,
                latency_ms=(end_time - start_time) * 1000,
                success=True,
                confirmation_time_ms=(end_time - confirm_start) * 1000
            )

        except Exception as e:
            end_time = time.perf_counter()
            return TransactionResult(
                signature="",
                slot=0,
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
        """Get total number of logged events"""
        try:
            account_info = await self.client.get_account_info(self.counter_pda)
            if account_info.value and account_info.value.data:
                # Skip 8-byte discriminator
                data = bytes(account_info.value.data)[8:]
                count = struct.unpack('<Q', data[:8])[0]
                return count
            return 0
        except Exception:
            return 0

    async def get_slot(self) -> int:
        """Get current slot"""
        response = await self.client.get_slot()
        return response.value


class SolanaMetrics:
    """Collect Solana-specific metrics"""

    def __init__(self, client: SolanaClient):
        self.client = client

    async def get_block_time(self, slot: int) -> Optional[int]:
        """Get block time for a slot"""
        response = await self.client.client.get_block_time(slot)
        return response.value

    async def get_recent_performance(self) -> dict:
        """Get recent performance samples"""
        response = await self.client.client.get_recent_performance_samples(10)
        samples = response.value

        if not samples:
            return {}

        avg_tps = sum(s.num_transactions / s.sample_period_secs for s in samples) / len(samples)
        avg_slot_time = sum(s.sample_period_secs / s.num_slots for s in samples) / len(samples)

        return {
            'avg_tps': avg_tps,
            'avg_slot_time_ms': avg_slot_time * 1000,
            'samples': len(samples)
        }


if __name__ == '__main__':
    import asyncio

    print("=== Testing Solana Client ===\n")

    async def test_client():
        client = SolanaClient()

        try:
            await client.connect()
            print(f"Payer: {client.payer.pubkey()}")
            print(f"Program ID: {client.program_id}")
            print(f"Counter PDA: {client.counter_pda}")

            # Get balance
            balance = await client.get_balance()
            print(f"Balance: {balance} SOL")

            if balance < 0.1:
                print("\nRequesting airdrop...")
                sig = await client.request_airdrop(2.0)
                print(f"Airdrop signature: {sig}")
                balance = await client.get_balance()
                print(f"New balance: {balance} SOL")

            # Initialize program (if not already)
            print("\nInitializing program...")
            result = await client.initialize_program()
            print(f"  Success: {result.success}")
            if result.error_message:
                print(f"  (Expected if already initialized: {result.error_message[:50]}...)")

            # Log test event
            print("\nLogging test event...")
            from event_generator.generator import EventGenerator
            generator = EventGenerator()
            event = generator.generate_random_events(1)[0]

            result = await client.log_security_event(event)
            print(f"  Signature: {result.signature[:20]}...")
            print(f"  Slot: {result.slot}")
            print(f"  Latency: {result.latency_ms:.2f}ms")
            print(f"  Confirmation: {result.confirmation_time_ms:.2f}ms")
            print(f"  Success: {result.success}")

            # Get event count
            count = await client.get_event_count()
            print(f"\nTotal events: {count}")

        except Exception as e:
            print(f"Error: {e}")
        finally:
            await client.disconnect()

    asyncio.run(test_client())

    print("\n=== Solana Client Tests Complete ===")
