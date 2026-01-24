"""
Storage abstractions for key management.

This module provides:
- KeyStorage: Abstract protocol for key storage backends
- InMemoryStorage: Thread-safe in-memory implementation for testing
- Supporting data structures: KeyMetadata, KeyType, StoredKey, EncryptedRecord
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional
from uuid import UUID, uuid4

from .errors import KeyNotFoundError


class KeyType(Enum):
    """Type of encryption key."""

    SERVER_KEY = "ServerKey"  # System-level key (renamed from MasterKey)
    KEK = "KEK"  # Per-user Key Encryption Key
    DEK = "DEK"  # One-time Data Encryption Key

    def __str__(self) -> str:
        return self.value


@dataclass
class KeyMetadata:
    """Metadata for stored keys."""

    key_id: UUID
    key_type: KeyType
    version: int
    created_at: datetime
    is_active: bool
    parent_key_id: Optional[UUID] = None
    user_id: Optional[UUID] = None  # User ID for per-user KEKs
    cid: Optional[UUID] = None

    @classmethod
    def new(cls, key_type: KeyType) -> KeyMetadata:
        """Create new KeyMetadata with default values."""
        return cls(
            key_id=uuid4(),
            key_type=key_type,
            version=1,
            created_at=datetime.now(timezone.utc),
            is_active=True,
        )


@dataclass
class StoredKey:
    """Stored key with metadata and encrypted key material."""

    metadata: KeyMetadata
    encrypted_key: bytes  # EKEK or EDEK
    nonce: bytes


@dataclass
class EncryptedRecord:
    """Encrypted data record."""

    cid: UUID
    dek_id: UUID
    encrypted_data: bytes
    nonce: bytes
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class KeyStorage(ABC):
    """
    Abstract storage interface for key management.

    All methods are async to support both in-memory and database backends.
    """

    @abstractmethod
    async def store_key(self, key: StoredKey) -> None:
        """Store a key."""
        ...

    @abstractmethod
    async def get_key(self, key_id: UUID) -> Optional[StoredKey]:
        """Get a key by ID."""
        ...

    @abstractmethod
    async def get_keys_by_type(self, key_type: KeyType) -> List[StoredKey]:
        """Get all keys of a specific type."""
        ...

    @abstractmethod
    async def get_key_by_cid(self, cid: UUID) -> Optional[StoredKey]:
        """Get an active key by content ID."""
        ...

    @abstractmethod
    async def get_kek_by_user_id(self, user_id: UUID) -> Optional[StoredKey]:
        """Get active KEK for a user."""
        ...

    @abstractmethod
    async def get_active_server_key(self) -> Optional[StoredKey]:
        """Get the active server key."""
        ...

    @abstractmethod
    async def update_key_metadata(self, key_id: UUID, metadata: KeyMetadata) -> None:
        """Update key metadata."""
        ...

    @abstractmethod
    async def delete_key(self, key_id: UUID) -> None:
        """Delete a key."""
        ...

    @abstractmethod
    async def list_key_ids(self) -> List[UUID]:
        """List all key IDs."""
        ...

    @abstractmethod
    async def store_record(self, record: EncryptedRecord) -> None:
        """Store an encrypted record."""
        ...

    @abstractmethod
    async def get_record(self, cid: UUID) -> Optional[EncryptedRecord]:
        """Get an encrypted record by content ID."""
        ...

    @abstractmethod
    async def delete_record(self, cid: UUID) -> None:
        """Delete an encrypted record."""
        ...


class InMemoryStorage(KeyStorage):
    """
    Thread-safe in-memory storage implementation for testing.

    Uses asyncio.Lock for safe concurrent access.
    """

    def __init__(self) -> None:
        self._keys: Dict[UUID, StoredKey] = {}
        self._records: Dict[UUID, EncryptedRecord] = {}
        self._lock = asyncio.Lock()

    async def store_key(self, key: StoredKey) -> None:
        """Store a key."""
        async with self._lock:
            self._keys[key.metadata.key_id] = key

    async def get_key(self, key_id: UUID) -> Optional[StoredKey]:
        """Get a key by ID."""
        async with self._lock:
            return self._keys.get(key_id)

    async def get_keys_by_type(self, key_type: KeyType) -> List[StoredKey]:
        """Get all keys of a specific type."""
        async with self._lock:
            return [k for k in self._keys.values() if k.metadata.key_type == key_type]

    async def get_key_by_cid(self, cid: UUID) -> Optional[StoredKey]:
        """Get an active key by content ID."""
        async with self._lock:
            for key in self._keys.values():
                if key.metadata.cid == cid and key.metadata.is_active:
                    return key
            return None

    async def get_kek_by_user_id(self, user_id: UUID) -> Optional[StoredKey]:
        """Get active KEK for a user."""
        async with self._lock:
            for key in self._keys.values():
                if (
                    key.metadata.key_type == KeyType.KEK
                    and key.metadata.user_id == user_id
                    and key.metadata.is_active
                ):
                    return key
            return None

    async def get_active_server_key(self) -> Optional[StoredKey]:
        """Get the active server key."""
        async with self._lock:
            for key in self._keys.values():
                if key.metadata.key_type == KeyType.SERVER_KEY and key.metadata.is_active:
                    return key
            return None

    async def update_key_metadata(self, key_id: UUID, metadata: KeyMetadata) -> None:
        """Update key metadata."""
        async with self._lock:
            if key_id not in self._keys:
                raise KeyNotFoundError(str(key_id))
            # Create new StoredKey with updated metadata
            old_key = self._keys[key_id]
            self._keys[key_id] = StoredKey(
                metadata=metadata,
                encrypted_key=old_key.encrypted_key,
                nonce=old_key.nonce,
            )

    async def delete_key(self, key_id: UUID) -> None:
        """Delete a key."""
        async with self._lock:
            self._keys.pop(key_id, None)

    async def list_key_ids(self) -> List[UUID]:
        """List all key IDs."""
        async with self._lock:
            return list(self._keys.keys())

    async def store_record(self, record: EncryptedRecord) -> None:
        """Store an encrypted record."""
        async with self._lock:
            self._records[record.cid] = record

    async def get_record(self, cid: UUID) -> Optional[EncryptedRecord]:
        """Get an encrypted record by content ID."""
        async with self._lock:
            return self._records.get(cid)

    async def delete_record(self, cid: UUID) -> None:
        """Delete an encrypted record."""
        async with self._lock:
            self._records.pop(cid, None)
