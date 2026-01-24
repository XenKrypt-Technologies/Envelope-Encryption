"""
PostgreSQL-based envelope encryption service.

This module provides:
- PostgresEnvelopeService: Main API for envelope encryption with PostgreSQL backend
- GeneratedDek: Result of DEK generation
- BulkRotationResult: Result of bulk KEK rotation
- UserKekRotationResult: Result of single user KEK rotation

Architecture:
- **Database**: Stores KEKs as plaintext (32 bytes, encrypted at rest by database encryption)
- **Memory**: DEKs generated on-demand, never persisted to database

Key hierarchy:
- Database Encryption → KEK (plaintext in DB, encrypted at rest by database)
- KEK → DEK (ephemeral, managed by application)
- DEK → Application Data

HSM-style design:
- Library manages KEK lifecycle (create, rotate, disable, delete)
- Application manages DEK caching/storage (as EDEK blobs)
- Crypto primitives provided for DEK encryption/decryption

Rotation strategy:
1. Mark all ACTIVE KEKs as RETIRED
2. Rotate in batches of 50 using SQL LIMIT
3. Lazy rotation: if RETIRED KEK accessed, rotate immediately
4. Only ACTIVE KEK used for encryption, old KEKs for decryption only
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from uuid import UUID, uuid4

from .crypto import AesGcmCipher, EncryptedData, SecureKey, generate_random_bytes
from .errors import KeyNotFoundError
from .postgres_storage import KekStatus, PostgresStorage, StoredKek


@dataclass
class GeneratedDek:
    """Result of generate_dek operation."""

    dek_id: UUID
    dek: SecureKey
    edek_blob: bytes  # AEAD format: nonce(12) || ciphertext(32) || tag(16) = 60 bytes
    kek_version: int


@dataclass
class BulkRotationResult:
    """Result of bulk KEK rotation."""

    keks_marked_retired: int
    keks_rotated: int


@dataclass
class UserKekRotationResult:
    """Result of single user KEK rotation."""

    user_id: UUID
    old_version: int
    new_version: int


@dataclass
class _KekInfo:
    """Internal KEK info (in-memory only)."""

    version: int
    kek: SecureKey
    status: KekStatus


class PostgresEnvelopeService:
    """
    PostgreSQL-based envelope encryption service.

    Provides the main API for envelope encryption with PostgreSQL backend.
    """

    def __init__(self, storage: PostgresStorage) -> None:
        """
        Initialize service with storage backend.

        Args:
            storage: PostgresStorage instance
        """
        self._storage = storage

    @classmethod
    async def new(cls, storage: PostgresStorage) -> PostgresEnvelopeService:
        """
        Initialize service (async factory method).

        Args:
            storage: PostgresStorage instance

        Returns:
            PostgresEnvelopeService instance
        """
        return cls(storage)

    async def generate_dek(self, user_id: UUID) -> GeneratedDek:
        """
        Generate a new DEK for a user.

        Crypto flow:
        1. Get or create ACTIVE KEK for user (plaintext from DB, encrypted at rest by database)
        2. Generate fresh DEK (random 32 bytes, ephemeral)
        3. Encrypt DEK using KEK with AES-GCM (AAD = dek_id) → EDEK
        4. Return (dek_id, dek, edek_blob, kek_version)

        Note: Application is responsible for caching DEK or storing EDEK blob

        Args:
            user_id: User UUID

        Returns:
            GeneratedDek with dek_id, dek, edek_blob, and kek_version
        """
        # Get or create user's ACTIVE KEK from database
        kek_info = await self._get_or_create_user_kek(user_id)

        # If KEK is RETIRED, perform lazy rotation
        if kek_info.status == KekStatus.RETIRED:
            rotated_kek = await self._rotate_single_kek(user_id, kek_info.version)
            return await self._generate_dek_with_kek(user_id, rotated_kek)

        return await self._generate_dek_with_kek(user_id, kek_info)

    async def _generate_dek_with_kek(
        self, user_id: UUID, kek_info: _KekInfo
    ) -> GeneratedDek:
        """Internal: Generate DEK with a specific KEK."""
        # Generate fresh DEK (random 32 bytes, ephemeral)
        dek = SecureKey.generate()
        dek_id = uuid4()

        # Encrypt DEK with user's KEK (AAD = dek_id for binding)
        edek = AesGcmCipher.encrypt(kek_info.kek, dek.as_bytes(), dek_id.bytes)

        # Convert to AEAD blob format (nonce || ciphertext || tag)
        edek_blob = edek.to_aead_blob()

        return GeneratedDek(
            dek_id=dek_id,
            dek=dek,
            edek_blob=edek_blob,
            kek_version=kek_info.version,
        )

    async def decrypt_edek(
        self,
        dek_id: UUID,
        edek_blob: bytes,
        user_id: UUID,
        kek_version: int,
    ) -> SecureKey:
        """
        Decrypt an EDEK to recover the DEK.

        Crypto flow:
        1. Fetch KEK from database by (user_id, kek_version)
        2. Decrypt EDEK using the ORIGINAL KEK (AAD = dek_id) → DEK
        3. Return DEK

        IMPORTANT: Must use the SAME KEK version that was used for encryption.

        Args:
            dek_id: DEK UUID (used as AAD for binding)
            edek_blob: Encrypted DEK blob (AEAD format)
            user_id: User UUID
            kek_version: KEK version that encrypted this DEK

        Returns:
            Decrypted DEK as SecureKey
        """
        # Get user's KEK for this version
        kek_info = await self._get_kek_by_version(user_id, kek_version)

        # Decrypt EDEK using the ORIGINAL KEK (CRITICAL: must use same KEK that encrypted it)
        edek = EncryptedData.from_aead_blob(edek_blob)
        dek_bytes = AesGcmCipher.decrypt(kek_info.kek, edek, dek_id.bytes)

        return SecureKey(dek_bytes)

    async def bulk_rotate_all_keks(self) -> BulkRotationResult:
        """
        Rotate all KEKs in bulk.

        Rotation strategy:
        1. Mark all ACTIVE KEKs as RETIRED
        2. Rotate in batches of 50 using SQL LIMIT
        3. For each KEK: generate new 32-byte key, call rotate_kek()

        Returns:
            BulkRotationResult with counts of marked and rotated KEKs
        """
        # Mark all ACTIVE KEKs as RETIRED
        marked_count = await self._storage.mark_all_active_keks_as_retired()

        if marked_count == 0:
            return BulkRotationResult(keks_marked_retired=0, keks_rotated=0)

        # Rotate in batches of 50
        total_rotated = 0
        batch_size = 50
        iteration = 0
        # Calculate max iterations based on marked count (with buffer)
        max_iterations = (marked_count // batch_size) + 10

        while True:
            iteration += 1

            batch = await self._storage.get_retired_keks_batch(batch_size)
            if not batch:
                break

            for stored_kek in batch:
                # Generate new KEK (32 bytes)
                new_kek_bytes = generate_random_bytes(32)

                # Rotate KEK
                await self._storage.rotate_kek(
                    stored_kek.user_id,
                    stored_kek.version,
                    new_kek_bytes,
                )

                total_rotated += 1

            # Safety check: prevent infinite loop (should never hit with fixed SQL)
            if iteration > max_iterations:
                print(f"[ERROR] Bulk rotation safety limit reached ({max_iterations} iterations)")
                break

        return BulkRotationResult(
            keks_marked_retired=marked_count,
            keks_rotated=total_rotated,
        )

    async def rotate_user_kek(self, user_id: UUID) -> UserKekRotationResult:
        """
        Rotate a specific user's ACTIVE KEK on demand.

        This function allows you to rotate a specific user's KEK without doing bulk rotation.
        It will:
        1. Get the user's current ACTIVE KEK
        2. Mark it as RETIRED
        3. Generate a new ACTIVE KEK for the user

        Args:
            user_id: User UUID

        Returns:
            UserKekRotationResult with old and new version numbers

        Raises:
            KeyNotFoundError: If no ACTIVE KEK exists for user
        """
        # Get the current ACTIVE KEK
        active_kek = await self._storage.get_active_kek(user_id)

        if active_kek is None:
            raise KeyNotFoundError(
                f"No ACTIVE KEK found for user: {user_id}. "
                "Generate a KEK first by calling generate_dek()."
            )

        old_version = active_kek.version

        # Rotate the KEK
        rotated_kek = await self._rotate_single_kek(user_id, old_version)

        return UserKekRotationResult(
            user_id=user_id,
            old_version=old_version,
            new_version=rotated_kek.version,
        )

    async def disable_kek(self, user_id: UUID, version: int) -> bool:
        """
        Disable a KEK.

        Changes KEK status to DISABLED. Only RETIRED KEKs can be disabled.

        Args:
            user_id: User UUID
            version: KEK version number

        Returns:
            True if status changed, False if already disabled
        """
        return await self._storage.disable_kek(user_id, version)

    async def delete_kek(self, user_id: UUID, version: int) -> bool:
        """
        Delete a KEK.

        Only deletes if status is DISABLED. Otherwise raises exception.

        Args:
            user_id: User UUID
            version: KEK version number

        Returns:
            True if deleted, False if not found
        """
        return await self._storage.delete_kek(user_id, version)

    async def get_kek_stats(self) -> List[Tuple[str, int]]:
        """
        Get KEK statistics by status.

        Returns:
            List of (status, count) tuples
        """
        return await self._storage.get_kek_stats()

    async def get_active_kek_raw(
        self, user_id: UUID
    ) -> Optional[Tuple[bytes, int]]:
        """
        Get user's active KEK as raw bytes for caching purposes.

        Args:
            user_id: User UUID

        Returns:
            Tuple of (kek_bytes, version) if exists, None otherwise
        """
        stored_kek = await self._storage.get_active_kek(user_id)
        if stored_kek:
            return (stored_kek.kek_plaintext, stored_kek.version)
        return None

    async def create_kek_for_user(self, user_id: UUID, kek_bytes: bytes) -> int:
        """
        Create a new active KEK for user with provided bytes.

        Used when application wants to provide its own KEK material.

        Args:
            user_id: User UUID
            kek_bytes: KEK bytes (must be exactly 32 bytes)

        Returns:
            Version number (always 1 for new KEKs)

        Raises:
            ValueError: If kek_bytes is not 32 bytes
        """
        if len(kek_bytes) != 32:
            raise ValueError("KEK must be exactly 32 bytes")

        stored_kek = StoredKek(
            user_id=user_id,
            version=1,
            kek_plaintext=kek_bytes,
            status=KekStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
        )

        await self._storage.store_kek(stored_kek)
        return 1

    async def _get_or_create_user_kek(self, user_id: UUID) -> _KekInfo:
        """Internal: Get or create user's ACTIVE KEK."""
        # Try to get existing active KEK
        stored_kek = await self._storage.get_active_kek(user_id)
        if stored_kek:
            kek = SecureKey(stored_kek.kek_plaintext)
            return _KekInfo(
                version=stored_kek.version,
                kek=kek,
                status=stored_kek.status,
            )

        # Create new KEK for user
        kek = SecureKey.generate()
        version = 1

        # Store KEK in database (plaintext, database encrypts at rest)
        new_kek = StoredKek(
            user_id=user_id,
            version=version,
            kek_plaintext=kek.as_bytes(),
            status=KekStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
        )

        await self._storage.store_kek(new_kek)

        return _KekInfo(version=version, kek=kek, status=KekStatus.ACTIVE)

    async def _get_kek_by_version(self, user_id: UUID, version: int) -> _KekInfo:
        """Internal: Get KEK by version."""
        stored_kek = await self._storage.get_kek_by_version(user_id, version)

        if stored_kek is None:
            raise KeyNotFoundError(f"KEK for user {user_id} version {version}")

        kek = SecureKey(stored_kek.kek_plaintext)

        return _KekInfo(
            version=version,
            kek=kek,
            status=stored_kek.status,
        )

    async def _rotate_single_kek(self, user_id: UUID, old_version: int) -> _KekInfo:
        """Internal: Rotate single KEK (lazy rotation)."""
        # Generate new KEK
        new_kek_bytes = generate_random_bytes(32)
        new_kek = SecureKey(new_kek_bytes)

        # Call SQL function to rotate
        new_version = await self._storage.rotate_kek(
            user_id, old_version, new_kek_bytes
        )

        return _KekInfo(version=new_version, kek=new_kek, status=KekStatus.ACTIVE)
