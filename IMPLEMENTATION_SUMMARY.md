# PostgreSQL Envelope Encryption Implementation Summary

## Deliverables Completed ✅

### 1. SQL Schema (`migrations/001_init_schema.sql`)

**Three Tables:**

```sql
-- Server Key version tracking
CREATE TABLE server_keys (
    version INTEGER PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

-- User KEKs (EKEK = KEK encrypted by Server Key)
CREATE TABLE user_keks (
    user_id UUID NOT NULL,
    version INTEGER NOT NULL,
    server_key_version INTEGER NOT NULL REFERENCES server_keys(version),
    ekek_ciphertext BYTEA NOT NULL,  -- 32B KEK + 16B GCM tag
    ekek_nonce BYTEA NOT NULL CHECK (octet_length(ekek_nonce) = 12),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (user_id, version)
);

-- User DEKs (EDEK = DEK encrypted by KEK)
CREATE TABLE user_deks (
    dek_id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    kek_version INTEGER NOT NULL,
    content_id UUID,
    edek_ciphertext BYTEA NOT NULL,  -- 32B DEK + 16B GCM tag
    edek_nonce BYTEA NOT NULL CHECK (octet_length(edek_nonce) = 12),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    FOREIGN KEY (user_id, kek_version) REFERENCES user_keks(user_id, version)
        ON DELETE RESTRICT
);
```

**Indexes (minimal, performance-critical only):**
- `idx_user_keks_active` - Find active KEK for user (hot path)
- `idx_user_deks_user_kek` - Find DEKs by user and KEK version
- `idx_user_deks_content_id` - Content ID lookup
- `idx_user_keks_server_version` - Server key rotation

**Referential Integrity:**
- KEKs cannot be deleted while DEKs reference them (ON DELETE RESTRICT)
- Trigger prevents KEK deactivation if active DEKs reference it
- Only one active KEK per user enforced by unique constraint

### 2. Rust Structs

**Storage Types (`src/postgres_storage.rs`):**

```rust
pub struct PostgresStorage {
    pool: PgPool,
}

pub struct StoredKek {
    pub user_id: Uuid,
    pub version: i32,
    pub server_key_version: i32,
    pub ekek_ciphertext: Vec<u8>,  // KEK + GCM tag
    pub ekek_nonce: Vec<u8>,       // 12 bytes
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}

pub struct StoredDek {
    pub dek_id: Uuid,
    pub user_id: Uuid,
    pub kek_version: i32,
    pub content_id: Option<Uuid>,
    pub edek_ciphertext: Vec<u8>,  // DEK + GCM tag
    pub edek_nonce: Vec<u8>,       // 12 bytes
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}
```

**Service Types (`src/postgres_envelope.rs`):**

```rust
pub struct PostgresEnvelopeService {
    storage: PostgresStorage,
    server_key: SecureKey,         // Loaded from .env
    server_key_version: i32,
}

pub struct GeneratedDek {
    pub dek_id: Uuid,
    pub dek: SecureKey,
    pub edek_ciphertext: Vec<u8>,  // Without tag
    pub edek_nonce: Vec<u8>,
    pub tag: Vec<u8>,              // 16-byte GCM tag
    pub kek_version: i32,
}

pub struct KekRotationResult {
    pub user_id: Uuid,
    pub old_version: i32,
    pub new_version: i32,
    pub deks_rewrapped: usize,
}
```

### 3. SQL Queries

All queries implemented in `src/postgres_storage.rs`:

**Get Active KEK:**
```rust
pub async fn get_active_kek(&self, user_id: &Uuid) -> Result<Option<StoredKek>> {
    sqlx::query("SELECT * FROM user_keks WHERE user_id = $1 AND is_active = TRUE")
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
}
```

**Get KEK by Version:**
```rust
pub async fn get_kek_by_version(&self, user_id: &Uuid, version: i32)
    -> Result<Option<StoredKek>>
```

**Store KEK:**
```rust
pub async fn store_kek(&self, kek: &StoredKek) -> Result<()>
```

**Get DEK:**
```rust
pub async fn get_dek(&self, dek_id: &Uuid) -> Result<Option<StoredDek>>
```

**Store DEK:**
```rust
pub async fn store_dek(&self, dek: &StoredDek) -> Result<()>
```

**Get DEKs by KEK:**
```rust
pub async fn get_deks_by_kek(&self, user_id: &Uuid, kek_version: i32)
    -> Result<Vec<StoredDek>>
```

**Count Active DEKs:**
```rust
pub async fn count_active_deks_for_kek(&self, user_id: &Uuid, kek_version: i32)
    -> Result<i64>
```

**Disable KEK:**
```rust
pub async fn disable_kek(&self, user_id: &Uuid, kek_version: i32) -> Result<()>
```

**Update DEK KEK Version:**
```rust
pub async fn update_dek_kek_version(
    &self,
    dek_id: &Uuid,
    new_kek_version: i32,
    new_edek_ciphertext: &[u8],
    new_edek_nonce: &[u8],
) -> Result<()>
```

### 4. Rust APIs

All implemented in `src/postgres_envelope.rs`:

#### API: `generate_dek(user_id) -> (dek, edek, nonce, tag, kek_version)`

```rust
pub async fn generate_dek(&self, user_id: &Uuid) -> Result<GeneratedDek> {
    // 1. Fetch ACTIVE KEK for user (or create if doesn't exist)
    let kek_info = self.get_or_create_user_kek(user_id).await?;

    // 2. Decrypt EKEK using Server Key (AAD = user_id)
    // (done in get_or_create_user_kek)

    // 3. Generate fresh DEK (random 32 bytes)
    let dek = SecureKey::generate();
    let dek_id = Uuid::new_v4();

    // 4. Encrypt DEK using KEK with AES-GCM (AAD = dek_id)
    let edek = AesGcmCipher::encrypt(&kek_info.kek, dek.as_bytes(), Some(dek_id.as_bytes()))?;

    // 5. Store EDEK in PostgreSQL
    let stored_dek = StoredDek { /* ... */ };
    self.storage.store_dek(&stored_dek).await?;

    // 6. Return (dek, edek_ciphertext, edek_nonce, tag, kek_version)
    Ok(GeneratedDek { /* ... */ })
}
```

#### API: `decrypt_edek(dek_id) -> dek`

```rust
pub async fn decrypt_edek(&self, dek_id: &Uuid) -> Result<SecureKey> {
    // 1. Fetch EDEK from PostgreSQL by dek_id
    let stored_dek = self.storage.get_dek(dek_id).await?;

    // 2. Fetch KEK by (user_id, kek_version)
    let kek_info = self.get_kek_by_version(&stored_dek.user_id, stored_dek.kek_version).await?;

    // 3. Decrypt EKEK using Server Key (AAD = user_id)
    // (done in get_kek_by_version)

    // 4. Decrypt EDEK using KEK (AAD = dek_id)
    let edek = EncryptedData::new(stored_dek.edek_nonce, stored_dek.edek_ciphertext);
    let dek_bytes = AesGcmCipher::decrypt(&kek_info.kek, &edek, Some(dek_id.as_bytes()))?;

    Ok(SecureKey::new(dek_bytes))
}
```

#### API: `rotate_user_kek(user_id)`

```rust
pub async fn rotate_user_kek(&self, user_id: &Uuid) -> Result<KekRotationResult> {
    // 1. Get old active KEK
    let old_kek = self.storage.get_active_kek(user_id).await?;

    // 2. Decrypt old EKEK using Server Key
    let old_kek_key = /* decrypt old EKEK */;

    // 3. Generate new KEK
    let new_kek = SecureKey::generate();
    let new_version = old_version + 1;

    // 4. Encrypt new KEK with Server Key (new EKEK)
    let new_ekek = AesGcmCipher::encrypt(&self.server_key, new_kek.as_bytes(), Some(user_id.as_bytes()))?;

    // 5. Store new KEK as active (incremented version)
    self.storage.store_kek(&new_stored_kek).await?;

    // 6. Get all active DEKs for old KEK
    let deks = self.storage.get_deks_by_kek(user_id, old_version).await?;

    // 7. For each DEK: decrypt EDEK with old KEK, re-encrypt with new KEK, update DB
    for dek in deks {
        let dek_bytes = AesGcmCipher::decrypt(&old_kek_key, &old_edek, Some(dek.dek_id.as_bytes()))?;
        let new_edek = AesGcmCipher::encrypt(&new_kek, &dek_bytes, Some(dek.dek_id.as_bytes()))?;
        self.storage.update_dek_kek_version(&dek.dek_id, new_version, &new_edek.ciphertext, &new_edek.nonce).await?;
        rewrapped_count += 1;
    }

    // 8. Deactivate old KEK
    self.storage.disable_kek(user_id, old_version).await?;

    Ok(KekRotationResult { /* ... */ })
}
```

#### API: `disable_kek_if_unused(user_id, kek_version) -> bool`

```rust
pub async fn disable_kek_if_unused(&self, user_id: &Uuid, kek_version: i32) -> Result<bool> {
    // Check if KEK has any active DEKs
    let count = self.storage.count_active_deks_for_kek(user_id, kek_version).await?;

    if count > 0 {
        return Ok(false); // Cannot disable, DEKs still reference it
    }

    // Safe to disable (also enforced by database trigger)
    self.storage.disable_kek(user_id, kek_version).await?;
    Ok(true)
}
```

### 5. Crypto Operations

All use **AES-256-GCM only**, no HKDF or KDFs.

**Encryption:**
```rust
// Implemented in src/crypto.rs
pub fn encrypt(key: &SecureKey, plaintext: &[u8], aad: Option<&[u8]>)
    -> Result<EncryptedData>
{
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())?;

    // Generate fresh random 12-byte nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt with AAD
    let ciphertext = match aad {
        Some(aad_data) => cipher.encrypt(nonce, Payload { msg: plaintext, aad: aad_data })?,
        None => cipher.encrypt(nonce, plaintext)?,
    };

    Ok(EncryptedData { nonce: nonce_bytes.to_vec(), ciphertext })
}
```

**Decryption:**
```rust
pub fn decrypt(key: &SecureKey, encrypted: &EncryptedData, aad: Option<&[u8]>)
    -> Result<Vec<u8>>
{
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())?;
    let nonce = Nonce::from_slice(&encrypted.nonce);

    // Decrypt with AAD verification
    let plaintext = match aad {
        Some(aad_data) => cipher.decrypt(nonce, Payload { msg: &encrypted.ciphertext, aad: aad_data })?,
        None => cipher.decrypt(nonce, encrypted.ciphertext.as_slice())?,
    };

    Ok(plaintext)
}
```

**AAD Bindings:**
| Operation | AAD Value | Purpose |
|-----------|-----------|---------|
| Encrypt KEK → EKEK | `user_id` | Binds KEK to user |
| Encrypt DEK → EDEK | `dek_id` | Binds DEK to ID |
| Encrypt Data | `content_id` | Binds data to content |

**Nonce Generation:**
- Every encryption generates a fresh random 12-byte nonce using `OsRng`
- Never reused with the same key (cryptographic requirement)

## Constraints Satisfied ✅

1. **No plaintext keys stored:**
   - Server Key: Only in `.env` (memory at runtime)
   - KEKs: Stored as EKEK (encrypted by Server Key)
   - DEKs: Stored as EDEK (encrypted by KEK)
   - All keys zeroized when dropped

2. **KEKs may only be disabled when zero DEKs reference them:**
   - Enforced by `ON DELETE RESTRICT` foreign key
   - Enforced by trigger `prevent_kek_disable_with_deks`
   - Enforced by API `disable_kek_if_unused` checking count

3. **Production-grade idiomatic Rust:**
   - Async/await with tokio
   - Result types with custom errors
   - Type-safe UUIDs
   - Zero-copy optimizations where possible
   - Comprehensive error handling

4. **No crypto simplifications:**
   - Full AES-256-GCM implementation
   - Proper nonce handling
   - AAD binding implemented correctly
   - Tag verification enforced

5. **Explicit versioning:**
   - Server keys have version tracking
   - Each user's KEK has version (increments on rotation)
   - DEK version always 1 (one-time use)

## Configuration

**Environment Variables (.env):**
```bash
DATABASE_URL=postgresql://username:password@localhost:5432/envelope_encryption
SERVER_KEY_BASE64=<32-byte-base64-encoded-key>  # openssl rand -base64 32
SERVER_KEY_VERSION=1
```

## Usage

**In-Memory Demo:**
```bash
cargo run
```

**PostgreSQL Demo:**
```bash
# Setup
docker run -d -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres
psql -U postgres -c "CREATE DATABASE envelope_encryption;"
psql -U postgres -d envelope_encryption -f migrations/001_init_schema.sql
echo "SERVER_KEY_BASE64=$(openssl rand -base64 32)" > .env

# Run
cargo run -- --postgres
```

## Files Created/Modified

1. `migrations/001_init_schema.sql` - PostgreSQL schema
2. `src/postgres_storage.rs` - PostgreSQL storage implementation
3. `src/postgres_envelope.rs` - PostgreSQL envelope service
4. `src/lib.rs` - Module exports
5. `src/main.rs` - Unified demo (in-memory + PostgreSQL)
6. `.env.example` - Environment configuration template
7. `Cargo.toml` - Added sqlx, tokio, dotenvy dependencies
8. `POSTGRES_README.md` - Comprehensive documentation
9. `IMPLEMENTATION_SUMMARY.md` - This file

## Testing

Build and run tests:
```bash
cargo test
cargo run        # In-memory demo
cargo run -- --postgres  # PostgreSQL demo (requires setup)
```

All deliverables completed successfully! ✅
