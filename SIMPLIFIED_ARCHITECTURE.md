# Simplified Envelope Encryption Architecture

## ✅ Implementation Complete

**Key Change:** Database now stores **ONLY EKEKs** (encrypted KEKs). DEKs and EDEKs are generated and handled entirely in memory for testing purposes.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                 .env (Server Key)                       │
│              32-byte base64 hardcoded                   │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼ encrypts
         ┌─────────────────────────────┐
         │   PostgreSQL Database        │
         │   ONLY stores: EKEK          │
         │   (KEK encrypted by Server)  │
         └─────────────┬────────────────┘
                       │
                       ▼ decrypts in memory
              ┌────────────────┐
              │  KEK (in-memory) │
              └────────┬─────────┘
                       │
                       ▼ encrypts in memory
              ┌────────────────┐
              │ EDEK (in-memory) │
              │  (for testing)  │
              └────────┬─────────┘
                       │
                       ▼ decrypts in memory
              ┌────────────────┐
              │  DEK (in-memory) │
              └────────┬─────────┘
                       │
                       ▼ encrypts
              ┌────────────────┐
              │ Application Data│
              └─────────────────┘
```

## What's Stored Where

| Item | Location | Purpose |
|------|----------|---------|
| **Server Key** | `.env` file | Root key, never changes during runtime |
| **EKEK** | PostgreSQL (`user_keks` table) | KEK encrypted by Server Key |
| **KEK** | Memory only | Decrypted from EKEK when needed |
| **EDEK** | Memory cache (testing) | DEK encrypted by KEK |
| **DEK** | Memory only | Generated fresh for each operation |
| **Data** | Application storage | Encrypted by DEK |

## Database Schema (Simplified)

### Only 2 Tables

**1. `server_keys` (version tracking only):**
```sql
CREATE TABLE server_keys (
    version INTEGER PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);
```

**2. `user_keks` (stores EKEK only):**
```sql
CREATE TABLE user_keks (
    user_id UUID NOT NULL,
    version INTEGER NOT NULL,
    server_key_version INTEGER NOT NULL REFERENCES server_keys(version),
    ekek_ciphertext BYTEA NOT NULL,  -- KEK encrypted by Server Key + tag
    ekek_nonce BYTEA NOT NULL CHECK (octet_length(ekek_nonce) = 12),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (user_id, version)
);
```

**What's REMOVED:**
- ❌ `user_deks` table (was storing EDEK)
- ❌ Foreign key constraints between DEKs and KEKs
- ❌ Triggers preventing KEK deletion

## Crypto Flow

### Generate DEK

```
1. Fetch EKEK from PostgreSQL (by user_id)
   ↓
2. Decrypt EKEK → KEK (in memory, AAD = user_id)
   ↓
3. Generate random DEK (32 bytes, in memory)
   ↓
4. Encrypt DEK → EDEK (in memory, AAD = dek_id)
   ↓
5. Cache DEK + EDEK in memory (for testing)
   ↓
6. Return DEK + EDEK components
```

### Decrypt EDEK

```
1. Try to get DEK from memory cache
   ↓ (if not cached)
2. Fetch EKEK from PostgreSQL (by user_id, kek_version)
   ↓
3. Decrypt EKEK → KEK (in memory, AAD = user_id)
   ↓
4. Decrypt EDEK → DEK (in memory, AAD = dek_id)
   ↓
5. Return DEK
```

### Rotate KEK

```
1. Fetch old EKEK from PostgreSQL
   ↓
2. Decrypt old EKEK → old KEK (in memory)
   ↓
3. Generate new KEK (in memory)
   ↓
4. Encrypt new KEK → new EKEK (AAD = user_id)
   ↓
5. Store new EKEK in PostgreSQL (version++)
   ↓
6. Re-wrap cached EDEKs with new KEK (in memory only)
   ↓
7. Deactivate old EKEK in PostgreSQL
```

## API Changes

### Before (Complex - DB stored DEKs)
```rust
// Generate DEK - stored EDEK in database
let result = service.generate_dek(&user_id).await?;

// Decrypt - fetched EDEK from database
let dek = service.decrypt_edek(&dek_id).await?;
```

### After (Simplified - Memory only)
```rust
// Generate DEK - caches EDEK in memory
let result = service.generate_dek(&user_id).await?;
// Returns: dek, edek_ciphertext, edek_nonce, tag, kek_version

// Decrypt - from memory cache or by providing EDEK components
let dek = service.decrypt_edek(
    &dek_id,
    &edek_ciphertext,
    &edek_nonce,
    &user_id,
    kek_version
).await?;
```

## Code Changes

### 1. PostgreSQL Storage (`postgres_storage.rs`)
**REMOVED:**
- `StoredDek` struct
- `get_dek()` method
- `store_dek()` method
- `get_deks_by_kek()` method
- `count_active_deks_for_kek()` method
- `update_dek_kek_version()` method

**KEPT:**
- `StoredKek` struct
- All KEK-related operations
- Server key version tracking

### 2. Envelope Service (`postgres_envelope.rs`)
**ADDED:**
- In-memory DEK cache (`HashMap<Uuid, CachedDek>`)
- `get_cached_dek_count()` - for testing
- `clear_dek_cache()` - for testing
- Updated `decrypt_edek()` to accept EDEK components

**CHANGED:**
- `generate_dek()` now caches in memory instead of database
- `rotate_user_kek()` re-wraps cached EDEKs in memory

### 3. Main Demo (`main.rs`)
**UPDATED:**
- Shows DEK/EDEK stored in memory (not database)
- Demonstrates cache status
- Clarifies what's in database vs memory

## Migration from Previous Version

If you were using the previous version with `user_deks` table:

```bash
# Run simplified schema migration
psql -U postgres -d envelope_encryption -f migrations/002_simplified_schema.sql
```

This will:
- Drop `user_deks` table
- Remove triggers/constraints related to DEKs
- Simplify KEK constraints

## Testing

### In-Memory Demo
```bash
cargo run
```

**Output shows:**
- DEKs/EDEKs cached in memory
- KEKs (EKEK) stored in PostgreSQL
- Clear separation between database and memory storage

### PostgreSQL Demo
```bash
# Setup (if needed)
docker run -d -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres
psql -U postgres -c "CREATE DATABASE envelope_encryption;"
psql -U postgres -d envelope_encryption -f migrations/001_init_schema.sql
psql -U postgres -d envelope_encryption -f migrations/002_simplified_schema.sql

# Run demo
cargo run -- --postgres
```

## Security Properties

✅ **What's Protected:**
- Server Key: Only in `.env` and memory
- KEK: Only in memory (decrypted from EKEK)
- EKEK: Stored in database, encrypted by Server Key
- All keys zeroized when dropped

✅ **What's NOT in Database:**
- DEKs (generated fresh in memory)
- EDEKs (cached in memory for testing only)
- Plaintext KEKs (only EKEK stored)

✅ **AAD Bindings:**
- EKEK: `user_id` as AAD
- EDEK: `dek_id` as AAD
- Data: `content_id` as AAD

## Benefits of Simplified Architecture

1. **Simpler Database Schema**
   - Only 2 tables instead of 3
   - No complex foreign keys
   - No triggers needed

2. **Clearer Separation**
   - Database = persistent key storage (EKEK only)
   - Memory = ephemeral keys (KEK, DEK, EDEK)

3. **Testing Focused**
   - In-memory cache for DEK/EDEK testing
   - No database pollution with test data
   - Easy to clear cache between tests

4. **Same Security Guarantees**
   - All keys properly encrypted
   - AAD binding preserved
   - Fresh nonces per encryption
   - No plaintext keys in database

## Limitations

⚠️ **In-Memory Cache:**
- DEK cache lost on service restart
- Not suitable for production use without external storage
- For testing purposes only

⚠️ **EDEK Management:**
- Application must manage EDEK storage if needed
- Database doesn't track EDEK lifecycle
- Application responsible for EDEK→DEK mapping

## Production Considerations

For production use, you would:

1. **Store EKEKs in PostgreSQL** ✅ (Already done)
2. **Generate DEKs on-demand** ✅ (Already done)
3. **Store EDEKs with your data** ⚠️ (Application's responsibility)
4. **Provide EDEK to decrypt** ⚠️ (Application must pass components)

Example production flow:
```rust
// Encrypt
let generated = service.generate_dek(&user_id).await?;
let encrypted_data = encrypt_with_dek(&generated.dek, plaintext);

// Store together in your application database
db.store({
    content_id,
    encrypted_data,
    edek_ciphertext: generated.edek_ciphertext,
    edek_nonce: generated.edek_nonce,
    edek_tag: generated.tag,
    user_id,
    kek_version: generated.kek_version
});

// Decrypt
let record = db.fetch(content_id);
let dek = service.decrypt_edek(
    &record.dek_id,
    &record.edek_ciphertext,
    &record.edek_nonce,
    &record.user_id,
    record.kek_version
).await?;
let plaintext = decrypt_with_dek(&dek, &record.encrypted_data);
```

## Files Modified

1. ✅ `migrations/002_simplified_schema.sql` - New migration
2. ✅ `src/postgres_storage.rs` - Removed DEK operations
3. ✅ `src/postgres_envelope.rs` - Added memory cache
4. ✅ `src/main.rs` - Updated demo
5. ✅ `src/lib.rs` - Updated exports

## Summary

**Database:** Stores ONLY EKEKs (user KEKs encrypted by Server Key)
**Memory:** Handles all DEK/EDEK generation and caching
**Testing:** In-memory cache for DEK/EDEK pairs
**Security:** Same strong guarantees, simpler architecture

✅ All requirements met!
