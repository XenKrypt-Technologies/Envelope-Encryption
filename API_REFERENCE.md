# API Reference

Complete API reference for the envelope encryption library.

## Table of Contents

- [Core Service](#core-service)
- [DEK Operations](#dek-operations)
- [KEK Rotation](#kek-rotation)
- [KEK Lifecycle](#kek-lifecycle)
- [Statistics](#statistics)
- [Crypto Operations](#crypto-operations)
- [Types](#types)
- [Error Handling](#error-handling)

---

## Core Service

### `PostgresEnvelopeService::new`

Initialize the envelope encryption service with PostgreSQL storage.

```rust
pub async fn new(storage: PostgresStorage) -> Result<Self>
```

**Parameters:**
- `storage: PostgresStorage` - Initialized PostgreSQL storage backend

**Returns:**
- `Result<PostgresEnvelopeService>` - Initialized service

**Example:**
```rust
use envelope_encryption::{PostgresStorage, PostgresEnvelopeService};
use sqlx::PgPool;

let pool = PgPool::connect("postgresql://localhost/envelope_encryption").await?;
let storage = PostgresStorage::new(pool);
let service = PostgresEnvelopeService::new(storage).await?;
```

---

## DEK Operations

### `generate_dek`

Generate a Data Encryption Key for a user. Automatically creates a KEK if the user doesn't have one.

```rust
pub async fn generate_dek(&self, user_id: &Uuid) -> Result<GeneratedDek>
```

**Parameters:**
- `user_id: &Uuid` - User identifier

**Returns:**
- `Result<GeneratedDek>` - DEK with EDEK blob and metadata

**Behavior:**
- Creates user's first KEK (version 1) if it doesn't exist
- Performs lazy rotation if user's KEK is RETIRED
- Returns DEK encrypted with user's ACTIVE KEK

**Example:**
```rust
use uuid::Uuid;

let user_id = Uuid::new_v4();
let dek = service.generate_dek(&user_id).await?;

println!("DEK ID: {}", dek.dek_id);
println!("KEK Version: {}", dek.kek_version);
println!("EDEK Blob: {} bytes", dek.edek_blob.len());
```

### `decrypt_edek`

Decrypt an EDEK (Encrypted DEK) to recover the original DEK.

```rust
pub async fn decrypt_edek(
    &self,
    dek_id: &Uuid,
    edek_blob: &[u8],
    user_id: &Uuid,
    kek_version: i64
) -> Result<SecureKey>
```

**Parameters:**
- `dek_id: &Uuid` - DEK identifier (used as AAD)
- `edek_blob: &[u8]` - EDEK in AEAD format (60 bytes: nonce 12 + ciphertext 32 + tag 16)
- `user_id: &Uuid` - User identifier
- `kek_version: i64` - KEK version used to encrypt the DEK

**Returns:**
- `Result<SecureKey>` - Recovered DEK

**Behavior:**
- Retrieves the specified KEK version from storage
- Performs lazy rotation if the KEK is RETIRED
- Decrypts and returns the DEK

**Example:**
```rust
let recovered_dek = service.decrypt_edek(
    &dek.dek_id,
    &dek.edek_blob,
    &user_id,
    dek.kek_version
).await?;
```

---

## KEK Rotation

### `rotate_user_kek`

Rotate a specific user's KEK on demand.

```rust
pub async fn rotate_user_kek(&self, user_id: &Uuid) -> Result<UserKekRotationResult>
```

**Parameters:**
- `user_id: &Uuid` - User identifier

**Returns:**
- `Result<UserKekRotationResult>` - Rotation result with old and new versions

**Behavior:**
1. Gets user's current ACTIVE KEK
2. Marks it as RETIRED
3. Generates new ACTIVE KEK (version incremented)

**Errors:**
- `KeyNotFound` - User has no ACTIVE KEK (must call `generate_dek` first)

**Example:**
```rust
let result = service.rotate_user_kek(&user_id).await?;

println!("User: {}", result.user_id);
println!("Old version: {}", result.old_version);
println!("New version: {}", result.new_version);
```

### `bulk_rotate_all_keks`

Rotate all users' KEKs in batches of 50.

```rust
pub async fn bulk_rotate_all_keks(&self) -> Result<BulkRotationResult>
```

**Returns:**
- `Result<BulkRotationResult>` - Rotation statistics

**Behavior:**
1. Marks ALL ACTIVE KEKs as RETIRED
2. Processes RETIRED KEKs in batches of 50
3. For each RETIRED KEK:
   - Generates new 32-byte key
   - Creates new ACTIVE version
4. Uses `SKIP LOCKED` for concurrent worker safety

**Performance:**
- Batch size: 50 KEKs per iteration
- Supports concurrent workers via database row locking
- Safety limit: 10 iterations maximum

**Example:**
```rust
let result = service.bulk_rotate_all_keks().await?;

println!("KEKs marked as RETIRED: {}", result.keks_marked_retired);
println!("KEKs rotated to ACTIVE: {}", result.keks_rotated);
```

---

## KEK Lifecycle

### `disable_kek`

Mark a RETIRED KEK as DISABLED (safe to delete).

```rust
pub async fn disable_kek(&self, user_id: &Uuid, version: i64) -> Result<bool>
```

**Parameters:**
- `user_id: &Uuid` - User identifier
- `version: i64` - KEK version to disable

**Returns:**
- `Result<bool>` - `true` if status changed, `false` if already disabled

**Errors:**
- Cannot disable ACTIVE KEKs (must rotate first)

**Example:**
```rust
let disabled = service.disable_kek(&user_id, 1).await?;

if disabled {
    println!("KEK version 1 disabled");
}
```

### `delete_kek`

Delete a DISABLED KEK from the database.

```rust
pub async fn delete_kek(&self, user_id: &Uuid, version: i64) -> Result<bool>
```

**Parameters:**
- `user_id: &Uuid` - User identifier
- `version: i64` - KEK version to delete

**Returns:**
- `Result<bool>` - `true` if deleted, `false` if not found

**Errors:**
- Cannot delete non-DISABLED KEKs (must disable first)

**Example:**
```rust
let deleted = service.delete_kek(&user_id, 1).await?;

if deleted {
    println!("KEK version 1 deleted");
}
```

---

## Statistics

### `get_kek_stats`

Get KEK statistics grouped by status.

```rust
pub async fn get_kek_stats(&self) -> Result<Vec<(String, i64)>>
```

**Returns:**
- `Result<Vec<(String, i64)>>` - List of (status, count) tuples

**Example:**
```rust
let stats = service.get_kek_stats().await?;

for (status, count) in stats {
    println!("{}: {}", status, count);
}
// Output:
// ACTIVE: 125
// RETIRED: 50
// DISABLED: 10
```

### `get_cached_dek_count`

Get count of cached DEKs in memory (for testing).

```rust
pub fn get_cached_dek_count(&self) -> usize
```

**Returns:**
- `usize` - Number of DEKs cached in memory

**Example:**
```rust
let count = service.get_cached_dek_count();
println!("Cached DEKs: {}", count);
```

---

## Crypto Operations

### `AesGcmCipher::encrypt`

Encrypt plaintext using AES-256-GCM.

```rust
pub fn encrypt(
    key: &SecureKey,
    plaintext: &[u8],
    aad: Option<&[u8]>
) -> Result<EncryptedData>
```

**Parameters:**
- `key: &SecureKey` - 32-byte encryption key
- `plaintext: &[u8]` - Data to encrypt
- `aad: Option<&[u8]>` - Optional Additional Authenticated Data

**Returns:**
- `Result<EncryptedData>` - Encrypted data with nonce and tag

**Example:**
```rust
use envelope_encryption::AesGcmCipher;

let plaintext = b"Sensitive data";
let content_id = uuid::Uuid::new_v4();

let encrypted = AesGcmCipher::encrypt(
    &dek.dek,
    plaintext,
    Some(content_id.as_bytes())
)?;
```

### `AesGcmCipher::decrypt`

Decrypt ciphertext using AES-256-GCM.

```rust
pub fn decrypt(
    key: &SecureKey,
    encrypted: &EncryptedData,
    aad: Option<&[u8]>
) -> Result<Vec<u8>>
```

**Parameters:**
- `key: &SecureKey` - 32-byte decryption key
- `encrypted: &EncryptedData` - Encrypted data with nonce and tag
- `aad: Option<&[u8]>` - Optional Additional Authenticated Data (must match encryption)

**Returns:**
- `Result<Vec<u8>>` - Decrypted plaintext

**Example:**
```rust
let decrypted = AesGcmCipher::decrypt(
    &recovered_dek,
    &encrypted,
    Some(content_id.as_bytes())
)?;

assert_eq!(plaintext, &decrypted[..]);
```

---

## Types

### `GeneratedDek`

Result of DEK generation.

```rust
pub struct GeneratedDek {
    pub dek_id: Uuid,           // Unique DEK identifier
    pub dek: SecureKey,          // 32-byte DEK (zeroized on drop)
    pub edek_blob: Vec<u8>,      // EDEK in AEAD format (60 bytes)
    pub kek_version: i64,        // KEK version used to encrypt DEK
}
```

**EDEK Blob Format (60 bytes):**
- Bytes 0-11: Nonce (12 bytes)
- Bytes 12-43: Ciphertext (32 bytes)
- Bytes 44-59: Authentication tag (16 bytes)

### `BulkRotationResult`

Result of bulk KEK rotation.

```rust
pub struct BulkRotationResult {
    pub keks_marked_retired: i64,  // KEKs marked as RETIRED
    pub keks_rotated: i64,         // KEKs rotated to new ACTIVE version
}
```

### `UserKekRotationResult`

Result of single user KEK rotation.

```rust
pub struct UserKekRotationResult {
    pub user_id: Uuid,      // User whose KEK was rotated
    pub old_version: i64,   // Previous KEK version (now RETIRED)
    pub new_version: i64,   // New ACTIVE KEK version
}
```

### `StoredKek`

KEK stored in database with metadata.

```rust
pub struct StoredKek {
    pub user_id: Uuid,
    pub version: i64,
    pub kek_plaintext: Vec<u8>,               // 32-byte KEK
    pub status: KekStatus,                     // ACTIVE, RETIRED, or DISABLED
    pub created_at: DateTime<Utc>,
    pub last_accessed_at: Option<DateTime<Utc>>,
    pub last_rotated_at: Option<DateTime<Utc>>,
}
```

### `KekStatus`

KEK lifecycle status.

```rust
pub enum KekStatus {
    Active,    // Current KEK (encrypt + decrypt)
    Retired,   // Old KEK (decrypt only, pending rotation)
    Disabled,  // Marked for deletion (safe to delete)
}
```

### `EncryptedData`

AES-GCM encrypted data.

```rust
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,  // Encrypted data
    pub nonce: Vec<u8>,       // 12-byte nonce
    pub tag: Vec<u8>,         // 16-byte authentication tag
}
```

### `SecureKey`

Secure key wrapper with automatic zeroization.

```rust
pub struct SecureKey { /* private */ }
```

**Features:**
- Automatically zeroizes key material on drop
- Prevents key material from being copied
- Provides secure access to key bytes

---

## Error Handling

### `EnvelopeError`

Error types for envelope encryption operations.

```rust
pub enum EnvelopeError {
    Crypto(String),          // Encryption/decryption errors
    KeyNotFound(String),     // Key not found in storage
    InvalidKeyState(String), // Invalid key state transition
    Storage(String),         // Database/storage errors
    Serialization(String),   // Data serialization errors
    KeyRotation(String),     // Key rotation errors
    Config(String),          // Configuration errors
}
```

### `Result<T>`

Type alias for `std::result::Result<T, EnvelopeError>`.

```rust
pub type Result<T> = std::result::Result<T, EnvelopeError>;
```

**Usage:**
```rust
use envelope_encryption::{EnvelopeError, Result};

fn example() -> Result<()> {
    // Your code here
    Ok(())
}

// Error handling
match service.generate_dek(&user_id).await {
    Ok(dek) => println!("Success: {}", dek.dek_id),
    Err(EnvelopeError::KeyNotFound(msg)) => eprintln!("Key not found: {}", msg),
    Err(EnvelopeError::Crypto(msg)) => eprintln!("Crypto error: {}", msg),
    Err(EnvelopeError::Storage(msg)) => eprintln!("Storage error: {}", msg),
    Err(e) => eprintln!("Other error: {}", e),
}
```

---

## Complete Example

```rust
use envelope_encryption::{
    PostgresStorage, PostgresEnvelopeService, AesGcmCipher,
    UserKekRotationResult, BulkRotationResult
};
use sqlx::PgPool;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize service
    dotenvy::dotenv().ok();
    let database_url = std::env::var("DATABASE_URL")?;
    let pool = PgPool::connect(&database_url).await?;
    let storage = PostgresStorage::new(pool);
    let service = PostgresEnvelopeService::new(storage).await?;

    // Generate DEK for user
    let user_id = Uuid::new_v4();
    let dek = service.generate_dek(&user_id).await?;

    // Encrypt data
    let plaintext = b"Sensitive user data";
    let content_id = Uuid::new_v4();
    let encrypted = AesGcmCipher::encrypt(
        &dek.dek,
        plaintext,
        Some(content_id.as_bytes())
    )?;

    // Decrypt data
    let recovered_dek = service.decrypt_edek(
        &dek.dek_id,
        &dek.edek_blob,
        &user_id,
        dek.kek_version
    ).await?;
    let decrypted = AesGcmCipher::decrypt(
        &recovered_dek,
        &encrypted,
        Some(content_id.as_bytes())
    )?;

    // Rotate user's KEK
    let rotation = service.rotate_user_kek(&user_id).await?;
    println!("Rotated: v{} -> v{}", rotation.old_version, rotation.new_version);

    // Bulk rotate all KEKs
    let bulk = service.bulk_rotate_all_keks().await?;
    println!("Bulk rotated: {} KEKs", bulk.keks_rotated);

    // Get statistics
    let stats = service.get_kek_stats().await?;
    for (status, count) in stats {
        println!("{}: {}", status, count);
    }

    Ok(())
}
```

---

## See Also

- [README.md](README.md) - Project overview and setup
- [QUICKSTART.md](QUICKSTART.md) - Quick start guide
- [schema.sql](schema.sql) - Database schema
- [Documentation](doc/index.html) - Program docs
