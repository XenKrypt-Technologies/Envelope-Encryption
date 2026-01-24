"""
Legacy key manager with server key hierarchy.

This module provides:
- KeyManager: Legacy key management with server key → KEK → DEK hierarchy
- UserKekInfo: User's KEK information
- DekInfo: Generated DEK information
- RotationResult: Key rotation result
- KeyStats: Key statistics

Architecture:
- ServerKey: Each server has its own key for DB and system security
- KEK: Per-user Key Encryption Key (one per user_id)
- DEK: One-time Data Encryption Key (generated per encryption operation)

Hierarchy: ServerKey -> EKEK (encrypted KEK) -> EDEK (encrypted DEK) -> Encrypted Data

Note: This is the legacy in-memory implementation. For production use,
see PostgresEnvelopeService which uses PostgreSQL for KEK storage.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from .crypto import AesGcmCipher, EncryptedData, SecureKey
from .errors import InvalidKeyStateError, KeyNotFoundError
from .storage import EncryptedRecord, KeyMetadata, KeyStorage, KeyType, StoredKey


@dataclass
class UserKekInfo:
    """User's KEK information."""

    kek_id: UUID
    kek_version: int
    user_id: UUID
    kek: SecureKey


@dataclass
class DekInfo:
    """Generated DEK information."""

    dek_id: UUID
    kek_id: UUID
    user_id: UUID
    cid: Optional[UUID]
    dek: SecureKey
    edek_nonce: bytes
    edek_ciphertext: bytes


@dataclass
class RotationResult:
    """Key rotation result."""

    old_key_id: UUID
    new_key_id: UUID
    old_version: int
    new_version: int
    keys_rewrapped: int

    def __str__(self) -> str:
        return f"v{self.old_version} -> v{self.new_version}, {self.keys_rewrapped} keys re-wrapped"


@dataclass
class KeyStats:
    """Key statistics."""

    total_server_keys: int
    active_server_keys: int
    total_keks: int
    active_keks: int
    total_deks: int
    active_deks: int
    server_key_version: int


class KeyManager:
    """
    Legacy key manager with server key hierarchy.

    Manages a three-tier key hierarchy:
    - ServerKey: System-level key for encrypting KEKs
    - KEK: Per-user key for encrypting DEKs
    - DEK: One-time key for encrypting data
    """

    def __init__(
        self,
        storage: KeyStorage,
        server_key: SecureKey,
        server_key_id: UUID,
        server_key_version: int,
    ) -> None:
        """
        Initialize KeyManager with existing server key.

        Args:
            storage: KeyStorage backend
            server_key: Server key for encrypting KEKs
            server_key_id: Server key UUID
            server_key_version: Server key version
        """
        self._storage = storage
        self._server_key = server_key
        self._server_key_id = server_key_id
        self._server_key_version = server_key_version

    @classmethod
    async def new(cls, storage: KeyStorage) -> KeyManager:
        """
        Create new KeyManager with a fresh server key.

        Args:
            storage: KeyStorage backend

        Returns:
            New KeyManager instance
        """
        server_key = SecureKey.generate()
        server_key_id = uuid4()

        metadata = KeyMetadata(
            key_id=server_key_id,
            key_type=KeyType.SERVER_KEY,
            version=1,
            created_at=datetime.now(timezone.utc),
            is_active=True,
        )

        stored_server_key = StoredKey(
            metadata=metadata,
            encrypted_key=b"",  # ServerKey stored securely (HSM/KMS in production)
            nonce=b"",
        )
        await storage.store_key(stored_server_key)

        return cls(
            storage=storage,
            server_key=server_key,
            server_key_id=server_key_id,
            server_key_version=1,
        )

    @classmethod
    def with_server_key(
        cls,
        storage: KeyStorage,
        server_key: SecureKey,
        server_key_id: UUID,
        version: int,
    ) -> KeyManager:
        """
        Initialize with existing server key.

        Args:
            storage: KeyStorage backend
            server_key: Existing server key
            server_key_id: Server key UUID
            version: Server key version

        Returns:
            KeyManager instance
        """
        return cls(
            storage=storage,
            server_key=server_key,
            server_key_id=server_key_id,
            server_key_version=version,
        )

    @property
    def server_key_id(self) -> UUID:
        """Get server key ID."""
        return self._server_key_id

    @property
    def server_key_version(self) -> int:
        """Get server key version."""
        return self._server_key_version

    async def get_or_create_user_kek(self, user_id: UUID) -> UserKekInfo:
        """
        Generate or get KEK for a user.

        Each user has their own KEK, encrypted by the server key.

        Args:
            user_id: User UUID

        Returns:
            UserKekInfo with KEK details
        """
        # Try to get existing KEK for this user
        stored_kek = await self._storage.get_kek_by_user_id(user_id)
        if stored_kek:
            # Decrypt EKEK to get KEK
            ekek = EncryptedData(
                nonce=stored_kek.nonce,
                ciphertext=stored_kek.encrypted_key,
            )
            kek_bytes = AesGcmCipher.decrypt(
                self._server_key,
                ekek,
                user_id.bytes,
            )
            kek = SecureKey(kek_bytes)

            return UserKekInfo(
                kek_id=stored_kek.metadata.key_id,
                kek_version=stored_kek.metadata.version,
                user_id=user_id,
                kek=kek,
            )

        # Create new KEK for this user
        kek = SecureKey.generate()
        kek_id = uuid4()

        # Encrypt KEK with server key (using user_id as AAD)
        ekek = AesGcmCipher.encrypt(self._server_key, kek.as_bytes(), user_id.bytes)

        metadata = KeyMetadata(
            key_id=kek_id,
            key_type=KeyType.KEK,
            version=1,
            created_at=datetime.now(timezone.utc),
            is_active=True,
            parent_key_id=self._server_key_id,
            user_id=user_id,
        )

        await self._storage.store_key(
            StoredKey(
                metadata=metadata,
                encrypted_key=ekek.ciphertext,
                nonce=ekek.nonce,
            )
        )

        return UserKekInfo(
            kek_id=kek_id,
            kek_version=1,
            user_id=user_id,
            kek=kek,
        )

    async def generate_dek(
        self, user_id: UUID, cid: Optional[UUID] = None
    ) -> DekInfo:
        """
        Generate a one-time DEK for encrypting data.

        DEK is encrypted by the user's KEK and returned (not permanently stored beyond EDEK).

        Args:
            user_id: User UUID
            cid: Optional content ID to associate with DEK

        Returns:
            DekInfo with DEK and EDEK details
        """
        user_kek = await self.get_or_create_user_kek(user_id)

        # Generate one-time DEK
        dek = SecureKey.generate()
        dek_id = uuid4()

        # Encrypt DEK with user's KEK (using dek_id as AAD for binding)
        edek = AesGcmCipher.encrypt(user_kek.kek, dek.as_bytes(), dek_id.bytes)

        metadata = KeyMetadata(
            key_id=dek_id,
            key_type=KeyType.DEK,
            version=1,
            created_at=datetime.now(timezone.utc),
            is_active=True,
            parent_key_id=user_kek.kek_id,
            user_id=user_id,
            cid=cid,
        )

        # Store EDEK for later decryption
        await self._storage.store_key(
            StoredKey(
                metadata=metadata,
                encrypted_key=edek.ciphertext,
                nonce=edek.nonce,
            )
        )

        return DekInfo(
            dek_id=dek_id,
            kek_id=user_kek.kek_id,
            user_id=user_id,
            cid=cid,
            dek=dek,
            edek_nonce=edek.nonce,
            edek_ciphertext=edek.ciphertext,
        )

    async def unwrap_dek(self, dek_id: UUID) -> SecureKey:
        """
        Unwrap EDEK to get DEK.

        Args:
            dek_id: DEK UUID

        Returns:
            Decrypted DEK

        Raises:
            KeyNotFoundError: If DEK not found
            InvalidKeyStateError: If key is not a DEK
        """
        stored_dek = await self._storage.get_key(dek_id)
        if stored_dek is None:
            raise KeyNotFoundError(f"DEK {dek_id}")

        if stored_dek.metadata.key_type != KeyType.DEK:
            raise InvalidKeyStateError(f"{dek_id} is not a DEK")

        user_id = stored_dek.metadata.user_id
        if user_id is None:
            raise InvalidKeyStateError("DEK has no user_id")

        # Get user's KEK
        user_kek = await self.get_or_create_user_kek(user_id)

        # Decrypt EDEK to get DEK
        edek = EncryptedData(
            nonce=stored_dek.nonce,
            ciphertext=stored_dek.encrypted_key,
        )
        dek_bytes = AesGcmCipher.decrypt(user_kek.kek, edek, dek_id.bytes)

        return SecureKey(dek_bytes)

    async def rotate_server_key(self) -> RotationResult:
        """
        Rotate server key and re-wrap all KEKs.

        Returns:
            RotationResult with rotation details
        """
        old_version = self._server_key_version
        new_server_key = SecureKey.generate()
        new_server_key_id = uuid4()
        new_version = old_version + 1

        # Get all KEKs
        keks = await self._storage.get_keys_by_type(KeyType.KEK)
        rewrapped = 0

        for stored_kek in keks:
            if not stored_kek.metadata.is_active:
                continue

            user_id = stored_kek.metadata.user_id
            if user_id is None:
                raise InvalidKeyStateError("KEK has no user_id")

            # Decrypt EKEK with old server key
            ekek = EncryptedData(
                nonce=stored_kek.nonce,
                ciphertext=stored_kek.encrypted_key,
            )
            kek_bytes = AesGcmCipher.decrypt(self._server_key, ekek, user_id.bytes)

            # Re-encrypt with new server key
            new_ekek = AesGcmCipher.encrypt(new_server_key, kek_bytes, user_id.bytes)

            updated = StoredKey(
                metadata=stored_kek.metadata,
                encrypted_key=new_ekek.ciphertext,
                nonce=new_ekek.nonce,
            )

            await self._storage.delete_key(stored_kek.metadata.key_id)
            await self._storage.store_key(updated)
            rewrapped += 1

        # Deactivate old server key metadata
        old_sk = await self._storage.get_key(self._server_key_id)
        if old_sk:
            old_meta = KeyMetadata(
                key_id=old_sk.metadata.key_id,
                key_type=old_sk.metadata.key_type,
                version=old_sk.metadata.version,
                created_at=old_sk.metadata.created_at,
                is_active=False,
                parent_key_id=old_sk.metadata.parent_key_id,
                user_id=old_sk.metadata.user_id,
                cid=old_sk.metadata.cid,
            )
            await self._storage.update_key_metadata(self._server_key_id, old_meta)

        # Store new server key metadata
        new_meta = KeyMetadata(
            key_id=new_server_key_id,
            key_type=KeyType.SERVER_KEY,
            version=new_version,
            created_at=datetime.now(timezone.utc),
            is_active=True,
        )
        await self._storage.store_key(
            StoredKey(
                metadata=new_meta,
                encrypted_key=b"",
                nonce=b"",
            )
        )

        old_server_key_id = self._server_key_id
        self._server_key = new_server_key
        self._server_key_id = new_server_key_id
        self._server_key_version = new_version

        return RotationResult(
            old_key_id=old_server_key_id,
            new_key_id=new_server_key_id,
            old_version=old_version,
            new_version=new_version,
            keys_rewrapped=rewrapped,
        )

    async def rotate_user_kek(self, user_id: UUID) -> RotationResult:
        """
        Rotate a specific user's KEK and re-wrap all their DEKs.

        Args:
            user_id: User UUID

        Returns:
            RotationResult with rotation details

        Raises:
            KeyNotFoundError: If no KEK found for user
        """
        # Get old KEK
        old_kek_stored = await self._storage.get_kek_by_user_id(user_id)
        if old_kek_stored is None:
            raise KeyNotFoundError(f"KEK for user {user_id}")

        old_version = old_kek_stored.metadata.version
        old_kek_id = old_kek_stored.metadata.key_id

        # Decrypt old KEK
        old_ekek = EncryptedData(
            nonce=old_kek_stored.nonce,
            ciphertext=old_kek_stored.encrypted_key,
        )
        old_kek_bytes = AesGcmCipher.decrypt(self._server_key, old_ekek, user_id.bytes)
        old_kek = SecureKey(old_kek_bytes)

        # Generate new KEK
        new_kek = SecureKey.generate()
        new_kek_id = uuid4()
        new_version = old_version + 1

        # Get all DEKs for this user
        all_deks = await self._storage.get_keys_by_type(KeyType.DEK)
        user_deks = [
            d
            for d in all_deks
            if d.metadata.user_id == user_id and d.metadata.is_active
        ]

        rewrapped = 0

        for stored_dek in user_deks:
            # Decrypt EDEK with old KEK
            edek = EncryptedData(
                nonce=stored_dek.nonce,
                ciphertext=stored_dek.encrypted_key,
            )
            dek_bytes = AesGcmCipher.decrypt(
                old_kek, edek, stored_dek.metadata.key_id.bytes
            )

            # Re-encrypt with new KEK
            new_edek = AesGcmCipher.encrypt(
                new_kek, dek_bytes, stored_dek.metadata.key_id.bytes
            )

            updated_meta = KeyMetadata(
                key_id=stored_dek.metadata.key_id,
                key_type=stored_dek.metadata.key_type,
                version=stored_dek.metadata.version,
                created_at=stored_dek.metadata.created_at,
                is_active=stored_dek.metadata.is_active,
                parent_key_id=new_kek_id,
                user_id=stored_dek.metadata.user_id,
                cid=stored_dek.metadata.cid,
            )

            updated = StoredKey(
                metadata=updated_meta,
                encrypted_key=new_edek.ciphertext,
                nonce=new_edek.nonce,
            )

            await self._storage.delete_key(stored_dek.metadata.key_id)
            await self._storage.store_key(updated)
            rewrapped += 1

        # Deactivate old KEK
        old_meta = KeyMetadata(
            key_id=old_kek_stored.metadata.key_id,
            key_type=old_kek_stored.metadata.key_type,
            version=old_kek_stored.metadata.version,
            created_at=old_kek_stored.metadata.created_at,
            is_active=False,
            parent_key_id=old_kek_stored.metadata.parent_key_id,
            user_id=old_kek_stored.metadata.user_id,
            cid=old_kek_stored.metadata.cid,
        )
        await self._storage.update_key_metadata(old_kek_id, old_meta)

        # Encrypt new KEK with server key
        new_ekek = AesGcmCipher.encrypt(
            self._server_key, new_kek.as_bytes(), user_id.bytes
        )

        # Store new KEK
        new_meta = KeyMetadata(
            key_id=new_kek_id,
            key_type=KeyType.KEK,
            version=new_version,
            created_at=datetime.now(timezone.utc),
            is_active=True,
            parent_key_id=self._server_key_id,
            user_id=user_id,
        )
        await self._storage.store_key(
            StoredKey(
                metadata=new_meta,
                encrypted_key=new_ekek.ciphertext,
                nonce=new_ekek.nonce,
            )
        )

        return RotationResult(
            old_key_id=old_kek_id,
            new_key_id=new_kek_id,
            old_version=old_version,
            new_version=new_version,
            keys_rewrapped=rewrapped,
        )

    async def get_stats(self) -> KeyStats:
        """
        Get key statistics.

        Returns:
            KeyStats with key counts by type
        """
        key_ids = await self._storage.list_key_ids()
        stats = KeyStats(
            total_server_keys=0,
            active_server_keys=0,
            total_keks=0,
            active_keks=0,
            total_deks=0,
            active_deks=0,
            server_key_version=self._server_key_version,
        )

        for key_id in key_ids:
            key = await self._storage.get_key(key_id)
            if key is None:
                continue

            if key.metadata.key_type == KeyType.SERVER_KEY:
                stats.total_server_keys += 1
                if key.metadata.is_active:
                    stats.active_server_keys += 1
            elif key.metadata.key_type == KeyType.KEK:
                stats.total_keks += 1
                if key.metadata.is_active:
                    stats.active_keks += 1
            elif key.metadata.key_type == KeyType.DEK:
                stats.total_deks += 1
                if key.metadata.is_active:
                    stats.active_deks += 1

        return stats

    def export_server_key(self) -> bytes:
        """
        Export server key bytes.

        Note: To be stored securely in HSM/KMS in production.

        Returns:
            Server key bytes
        """
        return self._server_key.as_bytes()
