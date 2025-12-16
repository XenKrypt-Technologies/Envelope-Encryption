# PostgreSQL-Backed Envelope Encryption

Production-grade envelope encryption with PostgreSQL key storage for Rust services.

## Architecture

**Strict Requirements Met:**
- ✅ AES-256-GCM only (no other ciphers)
- ✅ No HKDF or key derivation functions
- ✅ Server Key loaded from `.env` as hardcoded 32-byte base64 value
- ✅ Each user has their own KEK
- ✅ KEKs encrypted by Server Key (EKEK) stored in PostgreSQL
- ✅ DEKs encrypted by user KEKs (EDEK) stored in PostgreSQL
- ✅ Explicit version tracking for all keys
- ✅ Fresh random nonce for each encryption
- ✅ Referential integrity enforced in PostgreSQL
- ✅ Performance-critical indexes only

## Key Hierarchy

```
┌─────────────────────────────────────────┐
│       Server Key (from .env)            │
│   32-byte base64, version tracked       │
└──────────────────┬──────────────────────┘
                   │
        ┌──────────┴──────────┐
        │                     │
        ▼                     ▼
┌────────────────┐   ┌────────────────┐
│  EKEK (User 1) │   │  EKEK (User 2) │
│  PostgreSQL    │   │  PostgreSQL    │
│  user_keks     │   │  user_keks     │
└───────┬────────┘   └───────┬────────┘
        │                    │
    ┌───┴───┐            ┌───┴───┐
    ▼       ▼            ▼       ▼
┌──────┐ ┌──────┐   ┌──────┐ ┌──────┐
│ EDEK │ │ EDEK │   │ EDEK │ │ EDEK │
│  PG  │ │  PG  │   │  PG  │ │  PG  │
└──┬───┘ └──┬───┘   └──┬───┘ └──┬───┘
   │        │          │        │
   ▼        ▼          ▼        ▼
 Data1    Data2      Data3    Data4
```

## PostgreSQL Schema

### Tables

#### 1. `server_keys`
Tracks Server Key versions (key itself stored in `.env`):
```sql
CREATE TABLE server_keys (
    version INTEGER PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);
```

#### 2. `user_keks`
Stores per-user KEKs encrypted by Server Key (EKEK):
```sql
CREATE TABLE user_keks (
    user_id UUID NOT NULL,
    version INTEGER NOT NULL,
    server_key_version INTEGER NOT NULL REFERENCES server_keys(version),
    ekek_ciphertext BYTEA NOT NULL,  -- KEK encrypted by Server Key + GCM tag
    ekek_nonce BYTEA NOT NULL CHECK (octet_length(ekek_nonce) = 12),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (user_id, version)
);
```

**Indexes:**
- `idx_user_keks_active` - Find active KEK for user (WHERE is_active = TRUE)
- `idx_user_keks_server_version` - Server key rotation

**AAD Binding:** EKEK uses `user_id` as Additional Authenticated Data

#### 3. `user_deks`
Stores per-encryption DEKs encrypted by user's KEK (EDEK):
```sql
CREATE TABLE user_deks (
    dek_id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    kek_version INTEGER NOT NULL,
    content_id UUID,
    edek_ciphertext BYTEA NOT NULL,  -- DEK encrypted by KEK + GCM tag
    edek_nonce BYTEA NOT NULL CHECK (octet_length(edek_nonce) = 12),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    FOREIGN KEY (user_id, kek_version) REFERENCES user_keks(user_id, version)
        ON DELETE RESTRICT  -- Cannot delete KEK while DEKs reference it
);
```

**Indexes:**
- `idx_user_deks_user_kek` - Find DEKs by user and KEK version
- `idx_user_deks_content_id` - Lookup by content ID

**AAD Binding:** EDEK uses `dek_id` as Additional Authenticated Data

### Database Constraints

1. **One active KEK per user:**
   ```sql
   CONSTRAINT one_active_kek_per_user UNIQUE (user_id, is_active)
   ```

2. **KEK cannot be disabled if DEKs reference it:**
   - Enforced by trigger `prevent_kek_disable_with_deks`
   - Prevents orphaning DEKs

3. **Referential integrity:**
   - DEKs must reference valid KEK `(user_id, version)`
   - `ON DELETE RESTRICT` prevents accidental KEK deletion

## Rust API

### 1. Initialize Service

```rust
use envelope_encryption::{PostgresStorage, PostgresEnvelopeService};
use sqlx::PgPool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv()?;

    let database_url = std::env::var("DATABASE_URL")?;
    let pool = PgPool::connect(&database_url).await?;

    let storage = PostgresStorage::new(pool);
    let service = PostgresEnvelopeService::new(storage).await?;

    // Service ready to use
    Ok(())
}
```

### 2. Generate DEK

**API:** `generate_dek(user_id) -> (dek, edek, nonce, tag, kek_version)`

**Crypto Flow:**
1. Fetch ACTIVE KEK for user (or create if doesn't exist)
2. Decrypt EKEK using Server Key (AAD = `user_id`)
3. Generate fresh DEK (random 32 bytes)
4. Encrypt DEK using KEK with AES-GCM (AAD = `dek_id`)
5. Store EDEK in PostgreSQL
6. Return DEK + metadata

```rust
use uuid::Uuid;

let user_id = Uuid::new_v4();
let generated = service.generate_dek(&user_id).await?;

println!("DEK ID: {}", generated.dek_id);
println!("KEK Version: {}", generated.kek_version);
println!("EDEK Ciphertext: {} bytes", generated.edek_ciphertext.len());
println!("Nonce: {} bytes", generated.edek_nonce.len());
println!("Tag: {} bytes", generated.tag.len());

// Use DEK to encrypt application data
let encrypted = AesGcmCipher::encrypt(
    &generated.dek,
    plaintext,
    Some(content_id.as_bytes())
)?;
```

### 3. Decrypt EDEK

**API:** `decrypt_edek(dek_id) -> dek`

**Crypto Flow:**
1. Fetch EDEK from PostgreSQL by `dek_id`
2. Fetch KEK by `(user_id, kek_version)` from EDEK metadata
3. Decrypt EKEK using Server Key (AAD = `user_id`)
4. Decrypt EDEK using KEK (AAD = `dek_id`)
5. Return DEK

```rust
// Recover DEK from dek_id
let dek = service.decrypt_edek(&dek_id).await?;

// Use DEK to decrypt application data
let plaintext = AesGcmCipher::decrypt(&dek, &encrypted, Some(content_id.as_bytes()))?;
```

### 4. Rotate User KEK

**API:** `rotate_user_kek(user_id) -> rotation_result`

**Crypto Flow:**
1. Get old active KEK
2. Decrypt old EKEK using Server Key
3. Generate new KEK
4. Encrypt new KEK with Server Key (new EKEK)
5. Store new KEK as active (incremented version)
6. Get all active DEKs for old KEK
7. For each DEK:
   - Decrypt EDEK with old KEK
   - Re-encrypt DEK with new KEK (new EDEK)
   - Update EDEK in database with new version
8. Deactivate old KEK

```rust
let result = service.rotate_user_kek(&user_id).await?;

println!("Old KEK Version: {}", result.old_version);
println!("New KEK Version: {}", result.new_version);
println!("DEKs Re-wrapped: {}", result.deks_rewrapped);
```

### 5. Disable KEK if Unused

**API:** `disable_kek_if_unused(user_id, kek_version) -> bool`

Only disables KEK if zero active DEKs reference it. Enforced by database trigger.

```rust
let can_disable = service.disable_kek_if_unused(&user_id, kek_version).await?;

if can_disable {
    println!("KEK disabled successfully");
} else {
    println!("Cannot disable KEK: active DEKs still reference it");
}
```

## Setup

### 1. Prerequisites

```bash
# Start PostgreSQL
docker run -d \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 \
  postgres:15

# Create database
psql -U postgres -c "CREATE DATABASE envelope_encryption;"
```

### 2. Run Migrations

```bash
psql -U postgres -d envelope_encryption -f migrations/001_init_schema.sql
```

### 3. Configure Environment

Create `.env` file:

```bash
# Generate Server Key (CRITICAL - never commit this!)
openssl rand -base64 32

# .env file
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/envelope_encryption
SERVER_KEY_BASE64=<your-32-byte-base64-key>
SERVER_KEY_VERSION=1
```

### 4. Run Demo

```bash
cargo run --example postgres_demo
```

## Crypto Operations

### AES-256-GCM Details

**Encryption:**
```
Input:  plaintext, key (32 bytes), AAD
Output: ciphertext (includes 16-byte GCM tag), nonce (12 bytes)
```

**Decryption:**
```
Input:  ciphertext (with tag), key (32 bytes), nonce (12 bytes), AAD
Output: plaintext (or authentication failure)
```

### AAD (Additional Authenticated Data) Bindings

| Encryption | AAD Value | Purpose |
|------------|-----------|---------|
| **EKEK** (KEK encrypted by Server Key) | `user_id` | Binds KEK to specific user |
| **EDEK** (DEK encrypted by KEK) | `dek_id` | Binds DEK to specific ID |
| **Data** (encrypted by DEK) | `content_id` | Binds data to specific content |

This prevents ciphertext tampering and ensures keys/data cannot be swapped.

### Nonce Generation

Every encryption uses a fresh random 12-byte nonce:
```rust
use aes_gcm::{aead::OsRng};
let mut nonce_bytes = [0u8; 12];
OsRng.fill_bytes(&mut nonce_bytes);
```

**CRITICAL:** Never reuse a nonce with the same key!

## Security Considerations

### 1. Server Key Protection

**Production Requirements:**
- Store in AWS KMS, Azure Key Vault, or HashiCorp Vault
- Never commit `.env` file to version control
- Rotate regularly (requires re-encrypting all EKEKs)
- Use access controls (IAM roles, RBAC)

### 2. Key Zeroization

All `SecureKey` types automatically zeroize memory when dropped:
```rust
use zeroize::Zeroize;

impl Drop for SecureKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
```

### 3. Database Security

- Use TLS for PostgreSQL connections
- Restrict database access with RBAC
- Enable audit logging for key access
- Regular backups (encrypted)

### 4. No Plaintext Keys

**Guarantee:**
- Server Key: Only in `.env` (memory at runtime)
- KEKs: Only stored as EKEK (encrypted by Server Key)
- DEKs: Only stored as EDEK (encrypted by KEK)
- All keys zeroized after use

### 5. Version Tracking

- Server Key: Tracked in `server_keys` table
- KEK: Each user's KEK has explicit version
- DEK: Always version 1 (one-time use)

## Performance

### Database Indexes

**Minimal, performance-critical only:**

1. `idx_user_keks_active` - Hot path: Find active KEK
2. `idx_user_deks_user_kek` - KEK rotation: Find all DEKs
3. `idx_user_deks_content_id` - Content lookup

### Query Patterns

**Fast:**
- Get active KEK: O(1) with unique index
- Get DEK by ID: O(1) primary key lookup
- Decrypt EDEK: 2 queries (DEK + KEK)

**Slow (by design):**
- KEK rotation: O(n) where n = number of DEKs
  - Must re-wrap all DEKs (cryptographic requirement)

## Testing

### Unit Tests

```bash
cargo test
```

### Integration Tests

Requires PostgreSQL running:

```bash
# Start test database
docker run -d \
  -e POSTGRES_PASSWORD=test \
  -p 5433:5432 \
  --name pg-test \
  postgres:15

# Run integration tests
DATABASE_URL=postgresql://postgres:test@localhost:5433/test \
SERVER_KEY_BASE64=$(openssl rand -base64 32) \
SERVER_KEY_VERSION=1 \
cargo test --features integration
```

## Production Checklist

- [ ] Server Key stored in KMS/Vault (not `.env`)
- [ ] PostgreSQL over TLS
- [ ] Database RBAC configured
- [ ] Audit logging enabled
- [ ] Backup encryption configured
- [ ] Key rotation schedule established
- [ ] Monitoring and alerting set up
- [ ] Incident response plan documented
- [ ] Security review completed
- [ ] Penetration testing performed

## License

MIT
