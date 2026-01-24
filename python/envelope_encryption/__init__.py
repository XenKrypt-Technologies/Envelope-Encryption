"""
Envelope Encryption Library

A Python implementation of envelope encryption with per-user key encryption keys
and PostgreSQL-backed storage.

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
"""

__version__ = "0.1.0"

# =============================================================================
# Crypto Exports
# =============================================================================

from .crypto import (
    AES_256_KEY_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    AesGcmCipher,
    EncryptedData,
    SecureKey,
    generate_random_bytes,
)

# =============================================================================
# Error Exports
# =============================================================================

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

# =============================================================================
# PostgreSQL Exports (Primary API)
# =============================================================================

from .postgres import (
    BulkRotationResult,
    GeneratedDek,
    KekStatus,
    PostgresEnvelopeService,
    PostgresStorage,
    StoredDek,
    StoredKek,
    UserKekRotationResult,
)

# =============================================================================
# Public API
# =============================================================================

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
