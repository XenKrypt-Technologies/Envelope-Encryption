"""
PostgreSQL storage backend for KEK management.

This module provides:
- PostgresStorage: PostgreSQL-backed storage for KEKs
- StoredKek: KEK stored in database (plaintext, encrypted at rest by database)
- StoredDek: DEK metadata (EDEK stored with application data)
- KekStatus: KEK lifecycle status enum

Architecture:
- Database: Stores user KEKs as plaintext (database encryption handles at rest encryption)
- Memory: DEKs generated on-demand, never persisted

Key hierarchy:
- Database Encryption → KEK (stored as plaintext in DB, encrypted at rest by database)
- KEK → DEK (in-memory only)
- DEK → Application Data
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Tuple
from uuid import UUID

import asyncpg

from .errors import StorageError


class KekStatus(Enum):
    """KEK lifecycle status (matches database ENUM)."""

    ACTIVE = "ACTIVE"  # Current KEK for user (encrypt + decrypt)
    RETIRED = "RETIRED"  # Old KEK version (decrypt only, pending rotation)
    DISABLED = "DISABLED"  # Marked for deletion (no active EDEKs)

    def __str__(self) -> str:
        return self.value

    @classmethod
    def from_str(cls, s: str) -> KekStatus:
        """Parse from string."""
        try:
            return cls(s.upper())
        except ValueError:
            raise StorageError(f"Invalid KEK status: {s}")


@dataclass
class StoredKek:
    """
    Stored KEK (database encrypted at rest).

    KEK stored as plaintext (32 bytes), encrypted at rest by database encryption.
    """

    user_id: UUID
    version: int
    kek_plaintext: bytes  # KEK as plaintext (32 bytes), database encrypts at rest
    status: KekStatus
    created_at: datetime
    last_accessed_at: Optional[datetime] = None
    last_rotated_at: Optional[datetime] = None


@dataclass
class StoredDek:
    """
    Stored DEK metadata (EDEK = Encrypted DEK by KEK).

    Production AEAD format: edek_blob = nonce || ciphertext || tag (60 bytes total)
    """

    dek_id: UUID
    user_id: UUID
    kek_version: int
    edek_blob: bytes  # AEAD format: nonce(12) || ciphertext(32) || tag(16) = 60 bytes
    created_at: datetime
    last_used_at: Optional[datetime] = None


class PostgresStorage:
    """
    PostgreSQL storage backend for KEKs.

    Stores KEKs as plaintext (encrypted at rest by database encryption).
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        """
        Initialize PostgreSQL storage.

        Args:
            pool: asyncpg connection pool
        """
        self._pool = pool

    @property
    def pool(self) -> asyncpg.Pool:
        """Get the connection pool."""
        return self._pool

    async def get_active_kek(self, user_id: UUID) -> Optional[StoredKek]:
        """
        Get active KEK for a user (calls SQL function).

        Args:
            user_id: User UUID

        Returns:
            StoredKek if found, None otherwise
        """
        query = """
            SELECT user_id, kek_version, kek_plaintext, status::TEXT as status,
                   created_at, last_accessed_at, last_rotated_at
            FROM get_active_kek($1)
        """
        try:
            row = await self._pool.fetchrow(query, user_id)
            if row is None:
                return None
            return self._row_to_stored_kek(row)
        except Exception as e:
            raise StorageError(f"Failed to get active KEK: {e}")

    async def get_kek_by_version(
        self, user_id: UUID, version: int
    ) -> Optional[StoredKek]:
        """
        Get KEK by version (calls SQL function).

        Args:
            user_id: User UUID
            version: KEK version number

        Returns:
            StoredKek if found, None otherwise
        """
        query = """
            SELECT user_id, kek_version, kek_plaintext, status::TEXT as status,
                   created_at, last_accessed_at, last_rotated_at
            FROM get_kek_by_version($1, $2)
        """
        try:
            row = await self._pool.fetchrow(query, user_id, version)
            if row is None:
                return None
            return self._row_to_stored_kek(row)
        except Exception as e:
            raise StorageError(f"Failed to get KEK by version: {e}")

    async def store_kek(self, kek: StoredKek) -> None:
        """
        Store a new KEK (plaintext, will be encrypted at rest by database).

        Args:
            kek: StoredKek to store
        """
        query = """
            INSERT INTO user_keks (user_id, kek_version, kek_plaintext, status, created_at)
            VALUES ($1, $2, $3, $4::key_status, $5)
        """
        try:
            await self._pool.execute(
                query,
                kek.user_id,
                kek.version,
                kek.kek_plaintext,
                kek.status.value,
                kek.created_at,
            )
        except Exception as e:
            raise StorageError(f"Failed to store KEK: {e}")

    async def disable_kek(self, user_id: UUID, version: int) -> bool:
        """
        Disable KEK (calls SQL function).

        Changes status to DISABLED. Only RETIRED KEKs can be disabled.

        Args:
            user_id: User UUID
            version: KEK version number

        Returns:
            True if status changed, False if already disabled
        """
        query = "SELECT disable_kek($1, $2) as result"
        try:
            row = await self._pool.fetchrow(query, user_id, version)
            return row["result"] if row else False
        except Exception as e:
            raise StorageError(f"Failed to disable KEK: {e}")

    async def delete_kek(self, user_id: UUID, version: int) -> bool:
        """
        Delete KEK (calls SQL function).

        Only deletes if status is DISABLED, otherwise raises exception.

        Args:
            user_id: User UUID
            version: KEK version number

        Returns:
            True if deleted, False if not found
        """
        query = "SELECT delete_kek($1, $2) as result"
        try:
            row = await self._pool.fetchrow(query, user_id, version)
            return row["result"] if row else False
        except Exception as e:
            raise StorageError(f"Failed to delete KEK: {e}")

    async def mark_all_active_keks_as_retired(self) -> int:
        """
        Mark all ACTIVE KEKs as RETIRED (first step of bulk rotation).

        Returns:
            Count of KEKs marked as RETIRED
        """
        query = "SELECT mark_all_active_keks_as_retired() as count"
        try:
            row = await self._pool.fetchrow(query)
            return row["count"] if row else 0
        except Exception as e:
            raise StorageError(f"Failed to mark KEKs as retired: {e}")

    async def get_retired_keks_batch(self, batch_size: int = 50) -> List[StoredKek]:
        """
        Get batch of RETIRED KEKs for rotation (calls SQL function).

        Uses SKIP LOCKED for concurrent rotation workers.

        Args:
            batch_size: Maximum number of KEKs to return (default: 50)

        Returns:
            List of StoredKek for rotation
        """
        query = """
            SELECT user_id, kek_version, kek_plaintext, status::TEXT as status,
                   created_at, last_accessed_at, last_rotated_at
            FROM get_retired_keks_batch($1)
        """
        try:
            rows = await self._pool.fetch(query, batch_size)
            return [self._row_to_stored_kek(row) for row in rows]
        except Exception as e:
            raise StorageError(f"Failed to get retired KEKs batch: {e}")

    async def rotate_kek(
        self, user_id: UUID, old_version: int, new_kek: bytes
    ) -> int:
        """
        Rotate single KEK (calls SQL function).

        Marks old KEK as RETIRED, creates new ACTIVE KEK.

        Args:
            user_id: User UUID
            old_version: Current KEK version to rotate from
            new_kek: New KEK bytes (32 bytes)

        Returns:
            New version number
        """
        query = "SELECT rotate_kek($1, $2, $3) as new_version"
        try:
            row = await self._pool.fetchrow(query, user_id, old_version, new_kek)
            return row["new_version"] if row else 0
        except Exception as e:
            raise StorageError(f"Failed to rotate KEK: {e}")

    async def get_kek_stats(self) -> List[Tuple[str, int]]:
        """
        Get KEK statistics (calls SQL function).

        Returns:
            List of (status, count) tuples
        """
        query = "SELECT status::TEXT, count FROM get_kek_stats()"
        try:
            rows = await self._pool.fetch(query)
            return [(row["status"], row["count"]) for row in rows]
        except Exception as e:
            raise StorageError(f"Failed to get KEK stats: {e}")

    @staticmethod
    def _row_to_stored_kek(row: asyncpg.Record) -> StoredKek:
        """Convert database row to StoredKek."""
        return StoredKek(
            user_id=row["user_id"],
            version=row["kek_version"],
            kek_plaintext=bytes(row["kek_plaintext"]),
            status=KekStatus.from_str(row["status"]),
            created_at=row["created_at"],
            last_accessed_at=row["last_accessed_at"],
            last_rotated_at=row["last_rotated_at"],
        )
