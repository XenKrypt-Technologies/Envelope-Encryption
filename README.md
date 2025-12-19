# Envelope Encryption

A Rust implementation of envelope encryption with per-user key encryption keys and PostgreSQL-backed storage.

## Overview

Envelope encryption is a data protection strategy where:
1. **Data Encryption Key (DEK)** - One-time key that encrypts the actual data
2. **Key Encryption Key (KEK)** - Per-user master key that wraps/encrypts DEKs
3. **Database Encryption** - Database-level encryption protects KEKs at rest

This creates layers of protection and enables **key rotation without re-encrypting all data**.

## Key Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│              Database Encryption (at rest)                  │
└─────────────────────────┬───────────────────────────────────┘
                          │
              ┌───────────┴───────────┐
              │                       │
              ▼                       ▼
┌─────────────────────┐   ┌─────────────────────┐
│   KEK-1 (User 1)    │   │   KEK-2 (User 2)    │
│  32-byte plaintext  │   │  32-byte plaintext  │
│  Stored in DB       │   │  Stored in DB       │
└──────────┬──────────┘   └──────────┬──────────┘
           │                         │
    ┌──────┴──────┐          ┌───────┴───────┐
    │             │          │               │
    ▼             ▼          ▼               ▼
┌───────┐    ┌───────┐  ┌───────┐      ┌───────┐
│ DEK-1 │    │ DEK-2 │  │ DEK-3 │      │ DEK-4 │
│(EDEK) │    │(EDEK) │  │(EDEK) │      │(EDEK) │
└───┬───┘    └───┬───┘  └───┬───┘      └───┬───┘
    │            │          │              │
    ▼            ▼          ▼              ▼
┌───────┐    ┌───────┐  ┌───────┐      ┌───────┐
│ Data  │    │ Data  │  │ Data  │      │ Data  │
│  A    │    │  B    │  │  C    │      │  D    │
└───────┘    └───────┘  └───────┘      └───────┘
```

## Features

- **AES-256-GCM**: Industry-standard authenticated encryption with AEAD
- **Per-User KEKs**: Each user has their own Key Encryption Key
- **KEK Rotation**: Rotate KEKs individually or in bulk
- **Version Tracking**: KEKs maintain version numbers for backward compatibility
- **One-Time DEKs**: DEKs are generated per encryption operation (no rotation needed)
- **PostgreSQL Storage**: Production-ready persistent storage
- **Zero-copy Security**: Keys are zeroized from memory when dropped
- **User Isolation**: Each user's data is protected by their unique KEK

## Setup

### 1. PostgreSQL Setup

```bash
# Run schema (this will drop and recreate the database)
psql -U postgres -f schema.sql
```

### 2. Configure Environment

Create a `.env` file:
```bash
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/envelope_encryption
```

### 3. Run Demo

```bash
cargo run
```

## API Usage

### Initialize Service

```rust
use envelope_encryption::{PostgresStorage, PostgresEnvelopeService};
use sqlx::PgPool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment
    dotenvy::dotenv().ok();
    let database_url = std::env::var("DATABASE_URL")?;

    // Connect to PostgreSQL
    let pool = PgPool::connect(&database_url).await?;

    // Initialize service
    let storage = PostgresStorage::new(pool);
    let service = PostgresEnvelopeService::new(storage).await?;

    Ok(())
}
```

### Generate DEK for User

```rust
use uuid::Uuid;

// Generate a DEK for a user (automatically creates KEK if needed)
let user_id = Uuid::new_v4();
let dek = service.generate_dek(&user_id).await?;

println!("DEK ID: {}", dek.dek_id);
println!("KEK Version: {}", dek.kek_version);
println!("EDEK blob size: {} bytes", dek.edek_blob.len());
```

### Encrypt Data

```rust
use envelope_encryption::AesGcmCipher;

let plaintext = b"Sensitive user data";
let content_id = Uuid::new_v4();

// Encrypt using the DEK
let encrypted = AesGcmCipher::encrypt(
    &dek.dek,
    plaintext,
    Some(content_id.as_bytes())
)?;

println!("Ciphertext: {} bytes", encrypted.ciphertext.len());
```

### Decrypt Data

```rust
// Decrypt the EDEK to recover the DEK
let recovered_dek = service.decrypt_edek(
    &dek.dek_id,
    &dek.edek_blob,
    &user_id,
    dek.kek_version
).await?;

// Decrypt the data
let decrypted = AesGcmCipher::decrypt(
    &recovered_dek,
    &encrypted,
    Some(content_id.as_bytes())
)?;

assert_eq!(plaintext, &decrypted[..]);
```

## KEK Rotation

### Rotate Single User's KEK

Rotate a specific user's KEK on demand:

```rust
use envelope_encryption::UserKekRotationResult;

let user_id = Uuid::new_v4();

// First ensure the user has a KEK
let dek = service.generate_dek(&user_id).await?;

// Rotate this user's KEK
let result = service.rotate_user_kek(&user_id).await?;

println!("User: {}", result.user_id);
println!("Old version: {}", result.old_version);
println!("New version: {}", result.new_version);
```

### Bulk Rotate All KEKs

Rotate all users' KEKs in batches of 50:

```rust
use envelope_encryption::BulkRotationResult;

let result = service.bulk_rotate_all_keks().await?;

println!("KEKs marked as RETIRED: {}", result.keks_marked_retired);
println!("KEKs rotated: {}", result.keks_rotated);
```

### Lazy Rotation (Automatic)

KEKs are automatically rotated when a RETIRED KEK is accessed:

```rust
// If a RETIRED KEK is accessed during generate_dek or decrypt_edek,
// it will be automatically rotated to a new ACTIVE version
let dek = service.generate_dek(&user_id).await?;
// ↑ If user's KEK is RETIRED, it's automatically rotated here
```

## KEK Lifecycle Management

### Disable KEK

Mark a RETIRED KEK as DISABLED (safe to delete):

```rust
let disabled = service.disable_kek(&user_id, old_version).await?;

if disabled {
    println!("KEK disabled successfully");
}
```

### Delete KEK

Delete a DISABLED KEK from the database:

```rust
let deleted = service.delete_kek(&user_id, old_version).await?;

if deleted {
    println!("KEK deleted successfully");
}
```

### Get KEK Statistics

Monitor KEK lifecycle across all users:

```rust
let stats = service.get_kek_stats().await?;

for (status, count) in stats {
    println!("{}: {}", status, count);
}
// Output example:
// ACTIVE: 125
// RETIRED: 50
// DISABLED: 10
```

## KEK Status Lifecycle

```
┌─────────┐   generate_dek()    ┌────────────┐
│  NEW    │ ─────────────────> │   ACTIVE   │
│ (user)  │                     │  (current) │
└─────────┘                     └──────┬─────┘
                                       │
                         rotate_user_kek() or
                         bulk_rotate_all_keks()
                                       │
                                       ▼
                                ┌─────────────┐
                                │   RETIRED   │
                                │ (decrypt-   │
                                │   only)     │
                                └──────┬──────┘
                                       │
                                 disable_kek()
                                       │
                                       ▼
                                ┌─────────────┐
                                │  DISABLED   │
                                │ (safe to    │
                                │   delete)   │
                                └──────┬──────┘
                                       │
                                 delete_kek()
                                       │
                                       ▼
                                   [DELETED]
```

## Architecture

### Core Modules

| Module | Description |
|--------|-------------|
| `crypto` | AES-256-GCM encryption primitives |
| `postgres_storage` | PostgreSQL storage backend for KEKs |
| `postgres_envelope` | High-level envelope encryption service |
| `error` | Error types and Result aliases |

### Storage Strategy

- **KEKs**: Stored as plaintext (32 bytes) in PostgreSQL, encrypted at rest by database encryption
- **DEKs**: In-memory only, never persisted to database
- **EDEKs**: Application-managed, can be stored with encrypted data

### Key Types

| Key Type | Size | Lifetime | Rotation | Storage |
|----------|------|----------|----------|---------|
| **KEK** | 32 bytes | Per-user, versioned | Manual via API | PostgreSQL `user_keks` table |
| **DEK** | 32 bytes | One-time use | Not needed | In-memory only |
| **EDEK** | 60 bytes | Tied to data | Via KEK rotation | Application-managed |

### EDEK Format (AEAD)

```
┌─────────────┬──────────────┬─────────────┐
│   Nonce     │  Ciphertext  │     Tag     │
│  12 bytes   │   32 bytes   │  16 bytes   │
└─────────────┴──────────────┴─────────────┘
       Total: 60 bytes
```

## Security Considerations

1. **Database Encryption at Rest**: Enable PostgreSQL encryption at rest for production
2. **Key Zeroization**: All key material is automatically zeroized when dropped
3. **AAD Binding**:
   - Data ciphertexts are bound to `content_id` using Additional Authenticated Data
   - EDEKs are bound to `dek_id`
4. **Unique Nonces**: Each encryption generates a fresh random nonce (12 bytes)
5. **User Isolation**: Each user's data can only be decrypted with their specific KEK
6. **Version Tracking**: Old KEKs remain accessible for decrypting old data

## API Reference

### Core Types

```rust
// Service
pub struct PostgresEnvelopeService { /* ... */ }

// Storage
pub struct PostgresStorage { /* ... */ }

// Result types
pub struct GeneratedDek {
    pub dek_id: Uuid,
    pub dek: SecureKey,
    pub edek_blob: Vec<u8>,
    pub kek_version: i64,
}

pub struct BulkRotationResult {
    pub keks_marked_retired: i64,
    pub keks_rotated: i64,
}

pub struct UserKekRotationResult {
    pub user_id: Uuid,
    pub old_version: i64,
    pub new_version: i64,
}

pub struct StoredKek {
    pub user_id: Uuid,
    pub version: i64,
    pub kek_plaintext: Vec<u8>,
    pub status: KekStatus,
    pub created_at: DateTime<Utc>,
    pub last_accessed_at: Option<DateTime<Utc>>,
    pub last_rotated_at: Option<DateTime<Utc>>,
}

pub enum KekStatus {
    Active,
    Retired,
    Disabled,
}

// Crypto primitives
pub struct AesGcmCipher;
pub struct SecureKey { /* ... */ }
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub tag: Vec<u8>,
}
```

### Main Functions

```rust
// Service initialization
impl PostgresEnvelopeService {
    pub async fn new(storage: PostgresStorage) -> Result<Self>;

    // DEK operations
    pub async fn generate_dek(&self, user_id: &Uuid) -> Result<GeneratedDek>;
    pub async fn decrypt_edek(
        &self,
        dek_id: &Uuid,
        edek_blob: &[u8],
        user_id: &Uuid,
        kek_version: i64
    ) -> Result<SecureKey>;

    // KEK rotation
    pub async fn rotate_user_kek(&self, user_id: &Uuid) -> Result<UserKekRotationResult>;
    pub async fn bulk_rotate_all_keks(&self) -> Result<BulkRotationResult>;

    // KEK lifecycle
    pub async fn disable_kek(&self, user_id: &Uuid, version: i64) -> Result<bool>;
    pub async fn delete_kek(&self, user_id: &Uuid, version: i64) -> Result<bool>;

    // Statistics
    pub async fn get_kek_stats(&self) -> Result<Vec<(String, i64)>>;
    pub fn get_cached_dek_count(&self) -> usize;
}

// Crypto operations
impl AesGcmCipher {
    pub fn encrypt(
        key: &SecureKey,
        plaintext: &[u8],
        aad: Option<&[u8]>
    ) -> Result<EncryptedData>;

    pub fn decrypt(
        key: &SecureKey,
        encrypted: &EncryptedData,
        aad: Option<&[u8]>
    ) -> Result<Vec<u8>>;
}
```

## Testing

Run all tests:
```bash
cargo test
```

Run PostgreSQL integration tests:
```bash
# Ensure PostgreSQL is running with schema loaded
psql -U postgres -f schema.sql

# Run tests
cargo test --features postgres
```

## Performance

- **Bulk Rotation**: Processes KEKs in batches of 50 with `SKIP LOCKED` for concurrent workers
- **Lazy Rotation**: Automatically rotates on-demand when RETIRED KEKs are accessed
- **Indexed Queries**: Optimized PostgreSQL indexes for hot paths
  - `idx_user_keks_active`: Fast lookup of ACTIVE KEKs
  - `idx_user_keks_retired_for_rotation`: Efficient batch rotation

## Error Handling

```rust
use envelope_encryption::{EnvelopeError, Result};

match service.generate_dek(&user_id).await {
    Ok(dek) => println!("Success: {}", dek.dek_id),
    Err(EnvelopeError::KeyNotFound(msg)) => eprintln!("Key not found: {}", msg),
    Err(EnvelopeError::Crypto(msg)) => eprintln!("Crypto error: {}", msg),
    Err(EnvelopeError::Storage(msg)) => eprintln!("Storage error: {}", msg),
    Err(e) => eprintln!("Other error: {}", e),
}
```

## Production Deployment

1. **Enable PostgreSQL encryption at rest**: Configure your database for encryption
2. **Connection pooling**: Already included via `sqlx::PgPool`
3. **Monitoring**: Use `get_kek_stats()` to track KEK lifecycle
4. **Backup strategy**: Regular database backups include all KEKs
5. **Key rotation policy**: Rotate KEKs periodically using bulk or individual rotation

## License

MIT
