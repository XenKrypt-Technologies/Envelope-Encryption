"""
Pytest configuration and fixtures for envelope encryption tests.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import AsyncGenerator

import pytest
import asyncpg
from dotenv import load_dotenv

from envelope_encryption import (
    InMemoryStorage,
    PostgresStorage,
)


@pytest.fixture
def memory_storage() -> InMemoryStorage:
    """Create an in-memory storage instance for testing."""
    return InMemoryStorage()


@pytest.fixture
async def pg_pool() -> AsyncGenerator[asyncpg.Pool, None]:
    """Create a PostgreSQL connection pool for testing."""
    # Load environment from project root
    env_path = Path(__file__).parent.parent.parent / ".env"
    load_dotenv(env_path)

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        pytest.skip("DATABASE_URL not set, skipping PostgreSQL tests")

    pool = await asyncpg.create_pool(database_url)
    if pool is None:
        pytest.skip("Failed to create PostgreSQL connection pool")

    # Truncate tables before tests
    try:
        await pool.execute("TRUNCATE TABLE user_keks CASCADE")
    except Exception:
        pass  # Table may not exist

    yield pool

    await pool.close()


@pytest.fixture
async def postgres_storage(pg_pool: asyncpg.Pool) -> PostgresStorage:
    """Create a PostgreSQL storage instance for testing."""
    return PostgresStorage(pg_pool)
