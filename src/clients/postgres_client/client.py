"""
PostgreSQL Client for AAM Security Experiment

Provides hash-chained audit logging as the baseline comparison.
"""
import asyncio
import time
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple
import asyncpg
import psycopg2
from psycopg2.extras import execute_values

import sys
sys.path.append(str(__file__).rsplit('/', 3)[0])
from event_generator.generator import SecurityEvent
from config.settings import PostgresConfig, DEFAULT_CONFIG


@dataclass
class InsertResult:
    """Result of an insert operation"""
    event_id: int
    latency_ms: float
    success: bool
    error_message: Optional[str] = None


class PostgresClient:
    """Synchronous PostgreSQL client for security event logging"""

    def __init__(self, config: Optional[PostgresConfig] = None):
        self.config = config or DEFAULT_CONFIG.postgres
        self.conn = None

    def connect(self):
        """Establish database connection"""
        self.conn = psycopg2.connect(
            host=self.config.host,
            port=self.config.port,
            database=self.config.database,
            user=self.config.user,
            password=self.config.password
        )
        self.conn.autocommit = False

    def disconnect(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            self.conn = None

    def log_event(self, event: SecurityEvent) -> InsertResult:
        """Log a single security event with hash chain"""
        start_time = time.perf_counter()
        submit_time = datetime.now()

        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT * FROM insert_security_event(
                        %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        datetime.fromtimestamp(event.timestamp / 1000),
                        event.event_type,
                        event.confidence,
                        event.vehicle_id,
                        event.data_hash,
                        submit_time
                    )
                )
                result = cur.fetchone()
                self.conn.commit()

            end_time = time.perf_counter()
            latency_ms = (end_time - start_time) * 1000

            return InsertResult(
                event_id=result[0],
                latency_ms=result[1] if result[1] else latency_ms,
                success=True
            )

        except Exception as e:
            self.conn.rollback()
            end_time = time.perf_counter()
            return InsertResult(
                event_id=-1,
                latency_ms=(end_time - start_time) * 1000,
                success=False,
                error_message=str(e)
            )

    def log_events_batch(self, events: List[SecurityEvent]) -> List[InsertResult]:
        """Log multiple events in a single transaction"""
        results = []
        start_time = time.perf_counter()
        submit_time = datetime.now()

        try:
            with self.conn.cursor() as cur:
                for event in events:
                    event_start = time.perf_counter()
                    cur.execute(
                        """
                        SELECT * FROM insert_security_event(
                            %s, %s, %s, %s, %s, %s
                        )
                        """,
                        (
                            datetime.fromtimestamp(event.timestamp / 1000),
                            event.event_type,
                            event.confidence,
                            event.vehicle_id,
                            event.data_hash,
                            submit_time
                        )
                    )
                    result = cur.fetchone()
                    event_end = time.perf_counter()

                    results.append(InsertResult(
                        event_id=result[0],
                        latency_ms=(event_end - event_start) * 1000,
                        success=True
                    ))

                self.conn.commit()

        except Exception as e:
            self.conn.rollback()
            # Mark remaining as failed
            for _ in range(len(events) - len(results)):
                results.append(InsertResult(
                    event_id=-1,
                    latency_ms=0,
                    success=False,
                    error_message=str(e)
                ))

        return results

    def verify_hash_chain(
        self,
        start_id: int = 1,
        end_id: Optional[int] = None
    ) -> List[Tuple[int, bool, Optional[str]]]:
        """Verify the hash chain integrity"""
        with self.conn.cursor() as cur:
            if end_id:
                cur.execute(
                    "SELECT * FROM verify_hash_chain(%s, %s)",
                    (start_id, end_id)
                )
            else:
                cur.execute(
                    "SELECT * FROM verify_hash_chain(%s)",
                    (start_id,)
                )
            return cur.fetchall()

    def get_event_count(self) -> int:
        """Get total number of events"""
        with self.conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM security_events")
            return cur.fetchone()[0]

    def get_event(self, event_id: int) -> Optional[dict]:
        """Retrieve a specific event"""
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT event_id, event_timestamp, event_type, confidence,
                       vehicle_id, data_hash, record_hash, created_at
                FROM security_events WHERE event_id = %s
                """,
                (event_id,)
            )
            row = cur.fetchone()
            if row:
                return {
                    'event_id': row[0],
                    'event_timestamp': row[1],
                    'event_type': row[2],
                    'confidence': row[3],
                    'vehicle_id': row[4].hex() if row[4] else None,
                    'data_hash': row[5].hex() if row[5] else None,
                    'record_hash': row[6].hex() if row[6] else None,
                    'created_at': row[7]
                }
            return None

    def clear_events(self):
        """Clear all events (for testing)"""
        with self.conn.cursor() as cur:
            cur.execute("TRUNCATE TABLE security_events RESTART IDENTITY")
            self.conn.commit()


class AsyncPostgresClient:
    """Asynchronous PostgreSQL client for high-throughput testing"""

    def __init__(self, config: Optional[PostgresConfig] = None):
        self.config = config or DEFAULT_CONFIG.postgres
        self.pool: Optional[asyncpg.Pool] = None

    async def connect(self, min_size: int = 5, max_size: int = 20):
        """Create connection pool"""
        self.pool = await asyncpg.create_pool(
            host=self.config.host,
            port=self.config.port,
            database=self.config.database,
            user=self.config.user,
            password=self.config.password,
            min_size=min_size,
            max_size=max_size
        )

    async def disconnect(self):
        """Close connection pool"""
        if self.pool:
            await self.pool.close()
            self.pool = None

    async def log_event(self, event: SecurityEvent) -> InsertResult:
        """Log a single security event"""
        start_time = time.perf_counter()
        submit_time = datetime.now()

        try:
            async with self.pool.acquire() as conn:
                result = await conn.fetchrow(
                    """
                    SELECT * FROM insert_security_event(
                        $1, $2, $3, $4, $5, $6
                    )
                    """,
                    datetime.fromtimestamp(event.timestamp / 1000),
                    event.event_type,
                    event.confidence,
                    event.vehicle_id,
                    event.data_hash,
                    submit_time
                )

            end_time = time.perf_counter()

            return InsertResult(
                event_id=result['event_id'],
                latency_ms=result['latency_ms'] or (end_time - start_time) * 1000,
                success=True
            )

        except Exception as e:
            end_time = time.perf_counter()
            return InsertResult(
                event_id=-1,
                latency_ms=(end_time - start_time) * 1000,
                success=False,
                error_message=str(e)
            )

    async def log_events_concurrent(
        self,
        events: List[SecurityEvent],
        max_concurrent: int = 10
    ) -> List[InsertResult]:
        """Log multiple events concurrently"""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def log_with_semaphore(event: SecurityEvent) -> InsertResult:
            async with semaphore:
                return await self.log_event(event)

        tasks = [log_with_semaphore(event) for event in events]
        return await asyncio.gather(*tasks)

    async def get_event_count(self) -> int:
        """Get total number of events"""
        async with self.pool.acquire() as conn:
            result = await conn.fetchval("SELECT COUNT(*) FROM security_events")
            return result


if __name__ == '__main__':
    import asyncio

    print("=== Testing PostgreSQL Client ===\n")

    # Test synchronous client
    print("Testing synchronous client...")
    client = PostgresClient()

    try:
        client.connect()
        print("Connected to PostgreSQL")

        # Generate test event
        from event_generator.generator import EventGenerator
        generator = EventGenerator()
        events = generator.generate_random_events(5)

        # Log events
        for event in events:
            result = client.log_event(event)
            print(f"  Event {result.event_id}: latency={result.latency_ms:.2f}ms, success={result.success}")

        # Get count
        count = client.get_event_count()
        print(f"\nTotal events: {count}")

        # Verify hash chain
        print("\nVerifying hash chain...")
        verification = client.verify_hash_chain()
        valid_count = sum(1 for _, valid, _ in verification if valid)
        print(f"  Valid: {valid_count}/{len(verification)}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.disconnect()

    # Test async client
    print("\n\nTesting async client...")

    async def test_async():
        async_client = AsyncPostgresClient()
        try:
            await async_client.connect()
            print("Connected (async)")

            events = generator.generate_random_events(10)
            results = await async_client.log_events_concurrent(events)

            success_count = sum(1 for r in results if r.success)
            avg_latency = sum(r.latency_ms for r in results) / len(results)
            print(f"  Logged {success_count}/{len(results)} events")
            print(f"  Average latency: {avg_latency:.2f}ms")

        finally:
            await async_client.disconnect()

    asyncio.run(test_async())

    print("\n=== PostgreSQL Client Tests Complete ===")
