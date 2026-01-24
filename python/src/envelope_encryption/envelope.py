"""
Legacy envelope encryption service.

This module provides:
- EnvelopeEncryption: High-level envelope encryption service wrapping KeyManager
- EncryptedEnvelope: Encrypted data envelope with metadata

Architecture:
- Each server has its own ServerKey (for DB and system security)
- Each user has their own KEK (actual master key per user_id)
- DEKs are one-time use (no rotation needed)
- ServerKey and KEK support manual rotation with versioning

Note: This is the legacy in-memory implementation. For production use,
see PostgresEnvelopeService which uses PostgreSQL for KEK storage.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from .crypto import AesGcmCipher, EncryptedData, SecureKey
from .errors import KeyNotFoundError, SerializationError
from .key_manager import KeyManager, KeyStats, RotationResult
from .storage import EncryptedRecord, KeyStorage


@dataclass
class EncryptedEnvelope:
    """Encrypted data envelope with metadata."""

    cid: UUID
    user_id: UUID
    dek_id: UUID
    kek_id: UUID
    encrypted_data: EncryptedData

    def to_json(self) -> str:
        """Serialize envelope to JSON string."""
        try:
            return json.dumps(
                {
                    "cid": str(self.cid),
                    "user_id": str(self.user_id),
                    "dek_id": str(self.dek_id),
                    "kek_id": str(self.kek_id),
                    "encrypted_data": {
                        "nonce": self.encrypted_data.to_base64().split(",")[0]
                        if "," in self.encrypted_data.to_base64()
                        else self.encrypted_data.to_base64(),
                        "ciphertext_base64": self.encrypted_data.to_base64(),
                    },
                }
            )
        except Exception as e:
            raise SerializationError(f"Failed to serialize envelope: {e}")

    @classmethod
    def from_json(cls, json_str: str) -> EncryptedEnvelope:
        """Deserialize envelope from JSON string."""
        try:
            data = json.loads(json_str)
            encrypted_data = EncryptedData.from_base64(
                data["encrypted_data"]["ciphertext_base64"]
            )
            return cls(
                cid=UUID(data["cid"]),
                user_id=UUID(data["user_id"]),
                dek_id=UUID(data["dek_id"]),
                kek_id=UUID(data["kek_id"]),
                encrypted_data=encrypted_data,
            )
        except Exception as e:
            raise SerializationError(f"Failed to deserialize envelope: {e}")

    def ciphertext_base64(self) -> str:
        """Get ciphertext as base64 string."""
        return self.encrypted_data.to_base64()


class EnvelopeEncryption:
    """
    Legacy envelope encryption service.

    Provides high-level encryption/decryption with automatic key management.
    """

    def __init__(self, key_manager: KeyManager, storage: KeyStorage) -> None:
        """
        Initialize EnvelopeEncryption.

        Args:
            key_manager: KeyManager instance
            storage: KeyStorage backend
        """
        self._key_manager = key_manager
        self._storage = storage

    @classmethod
    async def new(cls, storage: KeyStorage) -> EnvelopeEncryption:
        """
        Create new EnvelopeEncryption with fresh server key.

        Args:
            storage: KeyStorage backend

        Returns:
            EnvelopeEncryption instance
        """
        key_manager = await KeyManager.new(storage)
        return cls(key_manager=key_manager, storage=storage)

    @classmethod
    def with_server_key(
        cls,
        storage: KeyStorage,
        server_key: SecureKey,
        server_key_id: UUID,
        version: int,
    ) -> EnvelopeEncryption:
        """
        Create EnvelopeEncryption with existing server key.

        Args:
            storage: KeyStorage backend
            server_key: Existing server key
            server_key_id: Server key UUID
            version: Server key version

        Returns:
            EnvelopeEncryption instance
        """
        key_manager = KeyManager.with_server_key(
            storage=storage,
            server_key=server_key,
            server_key_id=server_key_id,
            version=version,
        )
        return cls(key_manager=key_manager, storage=storage)

    @property
    def server_key_id(self) -> UUID:
        """Get server key ID."""
        return self._key_manager.server_key_id

    @property
    def server_key_version(self) -> int:
        """Get server key version."""
        return self._key_manager.server_key_version

    async def encrypt(
        self,
        plaintext: bytes,
        user_id: UUID,
        cid: Optional[UUID] = None,
    ) -> EncryptedEnvelope:
        """
        Encrypt data for a specific user.

        Args:
            plaintext: Data to encrypt
            user_id: User UUID (determines which KEK to use)
            cid: Optional content ID (auto-generated if not provided)

        Returns:
            EncryptedEnvelope with encrypted data and metadata
        """
        actual_cid = cid if cid is not None else uuid4()

        # Generate one-time DEK for this user
        dek_info = await self._key_manager.generate_dek(user_id, actual_cid)

        # Encrypt data with DEK (using cid as AAD)
        encrypted = AesGcmCipher.encrypt(dek_info.dek, plaintext, actual_cid.bytes)

        # Store encrypted record
        await self._storage.store_record(
            EncryptedRecord(
                cid=actual_cid,
                dek_id=dek_info.dek_id,
                encrypted_data=encrypted.ciphertext,
                nonce=encrypted.nonce,
                created_at=datetime.now(timezone.utc),
            )
        )

        return EncryptedEnvelope(
            cid=actual_cid,
            user_id=user_id,
            dek_id=dek_info.dek_id,
            kek_id=dek_info.kek_id,
            encrypted_data=encrypted,
        )

    async def decrypt(self, envelope: EncryptedEnvelope) -> bytes:
        """
        Decrypt using an envelope.

        Args:
            envelope: EncryptedEnvelope to decrypt

        Returns:
            Decrypted plaintext
        """
        dek = await self._key_manager.unwrap_dek(envelope.dek_id)
        return AesGcmCipher.decrypt(dek, envelope.encrypted_data, envelope.cid.bytes)

    async def decrypt_by_cid(self, cid: UUID) -> bytes:
        """
        Decrypt by content ID.

        Args:
            cid: Content ID

        Returns:
            Decrypted plaintext

        Raises:
            KeyNotFoundError: If record not found
        """
        record = await self._storage.get_record(cid)
        if record is None:
            raise KeyNotFoundError(f"Record {cid}")

        dek = await self._key_manager.unwrap_dek(record.dek_id)
        encrypted = EncryptedData(nonce=record.nonce, ciphertext=record.encrypted_data)
        return AesGcmCipher.decrypt(dek, encrypted, cid.bytes)

    async def rotate_server_key(self) -> RotationResult:
        """
        Rotate server key and re-wrap all user KEKs.

        Returns:
            RotationResult with rotation details
        """
        return await self._key_manager.rotate_server_key()

    async def rotate_user_kek(self, user_id: UUID) -> RotationResult:
        """
        Rotate a specific user's KEK and re-wrap all their DEKs.

        Args:
            user_id: User UUID

        Returns:
            RotationResult with rotation details
        """
        return await self._key_manager.rotate_user_kek(user_id)

    async def get_stats(self) -> KeyStats:
        """
        Get key statistics.

        Returns:
            KeyStats with key counts
        """
        return await self._key_manager.get_stats()

    def export_server_key(self) -> bytes:
        """
        Export server key bytes.

        Note: To be stored securely in HSM/KMS in production.

        Returns:
            Server key bytes
        """
        return self._key_manager.export_server_key()
