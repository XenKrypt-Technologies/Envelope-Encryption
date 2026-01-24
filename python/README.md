# Envelope Encryption (Python)

A Python implementation of envelope encryption with per-user key encryption keys and PostgreSQL-backed storage.

## Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# For development
pip install -r requirements-dev.txt
```

## Quick Start

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

    assert decrypted == plaintext
    print("Success!")

asyncio.run(main())
```

## Database Setup

Run the schema file from the project root:

```bash
psql -U postgres -f ../schema.sql
```

Create a `.env` file in the project root:

```
DATABASE_URL=postgresql://postgres:password@localhost:5432/envelope_encryption
```

## Running the Benchmark

```bash
python demo/benchmark.py
```

## Running Tests

```bash
pytest tests/
```

## Architecture

### Key Hierarchy

```
Database Encryption (at rest)
    ↓
KEK (Key Encryption Key) - Per-user, 32-byte keys stored in PostgreSQL
    ↓
DEK (Data Encryption Key) - One-time ephemeral keys
    ↓
Application Data - Encrypted with DEK
```

### KEK Lifecycle

1. **ACTIVE**: Current KEK for encryption and decryption
2. **RETIRED**: Old version (decryption only), triggers lazy rotation on access
3. **DISABLED**: Marked for deletion, no active EDEKs using it
4. **Deleted**: Permanently removed from database

## API Reference

### Core Types

- `PostgresEnvelopeService`: Main service for envelope encryption operations
- `PostgresStorage`: PostgreSQL storage backend for KEKs
- `AesGcmCipher`: AES-256-GCM encryption/decryption
- `SecureKey`: Secure key wrapper with automatic zeroization
- `GeneratedDek`: Result of DEK generation with EDEK blob

### Main Methods

- `service.generate_dek(user_id)`: Generate a new DEK for a user
- `service.decrypt_edek(dek_id, edek_blob, user_id, kek_version)`: Decrypt EDEK
- `service.rotate_user_kek(user_id)`: Rotate a user's KEK
- `service.bulk_rotate_all_keks()`: Rotate all KEKs in bulk

## License

MIT
