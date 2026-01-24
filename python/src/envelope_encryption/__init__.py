"""
Envelope Encryption Library

A Python implementation of envelope encryption with per-user key encryption keys
and PostgreSQL-backed storage.

Overview
--------
This library provides a complete envelope encryption solution where:

- **Data Encryption Keys (DEKs)** are one-time keys that encrypt actual data
- **Key Encryption Keys (KEKs)** are per-user master keys that wrap/encrypt DEKs
- **Database Encryption** protects KEKs at rest in PostgreSQL

Quick Start
-----------
```python
import asyncio
import asyncpg
from uuid import uuid4
from envelope_encryption import (
    PostgresStorage,
    PostgresEnvelopeService,
    AesGcmCipher,
)

async def main():
    # Initialize service
    pool = await asyncpg.create_pool("postgresql://localhost/envelope_encryption")
    storage = PostgresStorage(pool)
    service = await PostgresEnvelopeService.new(storage)

    # Generate DEK for a user
    user_id = uuid4()
    dek = await service.generate_dek(user_id)

    # Encrypt data
    plaintext = b"Sensitive data"
    encrypted = AesGcmCipher.encrypt(dek.dek, plaintext)

    # Decrypt data
    recovered_dek = await service.decrypt_edek(
        dek.dek_id,
        dek.edek_blob,
        user_id,
        dek.kek_version
    )
    decrypted = AesGcmCipher.decrypt(recovered_dek, encrypted)

asyncio.run(main())
```

Key Features
------------
- **AES-256-GCM**: Industry-standard authenticated encryption
- **Per-User KEKs**: Each user has their own isolated KEK
- **KEK Rotation**: Rotate individual KEKs or all KEKs in bulk
- **Version Tracking**: Maintain backward compatibility with old KEKs
- **PostgreSQL Storage**: Production-ready persistent storage
- **Memory Security**: Best-effort key zeroization on deletion

Modules
-------
- `crypto`: AES-256-GCM encryption primitives
- `postgres_storage`: PostgreSQL storage backend for KEKs
- `postgres_envelope`: High-level envelope encryption service
- `errors`: Error types and exception classes
- `storage`: In-memory storage for testing
- `key_manager`: Legacy key manager (in-memory)
- `envelope`: Legacy envelope encryption (in-memory)
"""

__version__ = "0.1.0"

# ============================================================================
# Crypto Exports
# ============================================================================

from .crypto import (
    AES_256_KEY_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    AesGcmCipher,
    EncryptedData,
    SecureKey,
    generate_random_bytes,
)

# ============================================================================
# Error Exports
# ============================================================================

from .errors import (
    ConfigError,
    CryptoError,
    EnvelopeError,
    InvalidKeyStateError,
    KeyNotFoundError,
    KeyRotationError,
    SerializationError,
    StorageError,
)

# ============================================================================
# Legacy Storage Exports (In-Memory)
# ============================================================================

from .storage import (
    EncryptedRecord,
    InMemoryStorage,
    KeyMetadata,
    KeyStorage,
    KeyType,
    StoredKey,
)

# ============================================================================
# Legacy Key Manager Exports
# ============================================================================

from .key_manager import (
    DekInfo,
    KeyManager,
    KeyStats,
    RotationResult,
    UserKekInfo,
)

# ============================================================================
# Legacy Envelope Exports
# ============================================================================

from .envelope import (
    EncryptedEnvelope,
    EnvelopeEncryption,
)

# ============================================================================
# PostgreSQL Exports (Primary API)
# ============================================================================

from .postgres_storage import (
    KekStatus,
    PostgresStorage,
    StoredDek,
    StoredKek,
)

from .postgres_envelope import (
    BulkRotationResult,
    GeneratedDek,
    PostgresEnvelopeService,
    UserKekRotationResult,
)

# ============================================================================
# Public API
# ============================================================================

__all__ = [
    # Version
    "__version__",
    # Crypto
    "AES_256_KEY_SIZE",
    "NONCE_SIZE",
    "TAG_SIZE",
    "AesGcmCipher",
    "EncryptedData",
    "SecureKey",
    "generate_random_bytes",
    # Errors
    "EnvelopeError",
    "CryptoError",
    "KeyNotFoundError",
    "InvalidKeyStateError",
    "StorageError",
    "SerializationError",
    "KeyRotationError",
    "ConfigError",
    # Legacy storage
    "KeyStorage",
    "InMemoryStorage",
    "KeyMetadata",
    "KeyType",
    "StoredKey",
    "EncryptedRecord",
    # Legacy key manager
    "KeyManager",
    "UserKekInfo",
    "DekInfo",
    "RotationResult",
    "KeyStats",
    # Legacy envelope
    "EnvelopeEncryption",
    "EncryptedEnvelope",
    # PostgreSQL (Primary API)
    "PostgresStorage",
    "StoredKek",
    "StoredDek",
    "KekStatus",
    "PostgresEnvelopeService",
    "GeneratedDek",
    "BulkRotationResult",
    "UserKekRotationResult",
]
