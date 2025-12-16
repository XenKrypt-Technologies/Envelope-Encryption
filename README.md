# Envelope Encryption

A Rust implementation of envelope encryption with per-user key encryption keys and manual key rotation.

## Overview

Envelope encryption is a data protection strategy where:
1. **Data Encryption Key (DEK)** - One-time key that encrypts the actual data
2. **Key Encryption Key (KEK)** - Per-user master key that wraps/encrypts DEKs
3. **Server Key** - Per-server root key that protects all KEKs for DB and system security

This creates layers of protection and enables **key rotation without re-encrypting all data**.

## Key Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│                    Server Key (SK)                          │
│     Per-server key for DB and system security              │
└─────────────────────────┬───────────────────────────────────┘
                          │
              ┌───────────┴───────────┐
              │                       │
              ▼                       ▼
┌─────────────────────┐   ┌─────────────────────┐
│   KEK-1 (User 1)    │   │   KEK-2 (User 2)    │
│  Encrypted by SK    │   │  Encrypted by SK    │
│  (EKEK stored)      │   │  (EKEK stored)      │
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

- **AES-256-GCM**: Industry-standard authenticated encryption
- **No HKDF**: Pure envelope encryption without key derivation functions
- **Per-User KEKs**: Each user has their own Key Encryption Key
- **Manual Key Rotation**: Rotate Server Keys or per-user KEKs independently
- **Version Tracking**: Both Server Keys and KEKs maintain version numbers
- **One-Time DEKs**: DEKs are generated per encryption operation (no rotation needed)
- **Pluggable Storage**: In-memory (included), PostgreSQL (planned)
- **Zero-copy Security**: Keys are zeroized from memory when dropped
- **User Isolation**: Each user's data is protected by their unique KEK

## Quick Start

```rust
use envelope_encryption::{EnvelopeEncryption, InMemoryStorage};
use std::sync::Arc;
use uuid::Uuid;

// Create storage and encryption service
let storage = Arc::new(InMemoryStorage::new());
let mut service = EnvelopeEncryption::new(storage).unwrap();

// Create user ID
let user_id = Uuid::new_v4();

// Encrypt data for a user
let plaintext = b"Secret message";
let envelope = service.encrypt(plaintext, &user_id, None).unwrap();

// Decrypt data
let decrypted = service.decrypt(&envelope).unwrap();
assert_eq!(plaintext.to_vec(), decrypted);
```

## Key Rotation

### Server Key Rotation

Automatically re-wraps all user KEKs with the new server key:

```rust
let result = service.rotate_server_key().unwrap();
println!("Rotated: v{} -> v{}", result.old_version, result.new_version);
println!("KEKs re-wrapped: {}", result.keys_rewrapped);
```

### User KEK Rotation

Re-wraps all DEKs for a specific user under their new KEK:

```rust
let user_id = Uuid::new_v4();
let result = service.rotate_user_kek(&user_id).unwrap();
println!("DEKs re-wrapped: {}", result.keys_rewrapped);
```

### DEK Rotation

DEKs are one-time use keys generated for each encryption operation. They do not require rotation as they are unique per encryption.

## User Isolation

Each user automatically gets their own KEK:

```rust
let user1_id = Uuid::new_v4();
let user2_id = Uuid::new_v4();

// User 1's data - encrypted with User 1's KEK
let user1_envelope = service.encrypt(user1_data, &user1_id, None).unwrap();

// User 2's data - encrypted with User 2's KEK
let user2_envelope = service.encrypt(user2_data, &user2_id, None).unwrap();

// Each user has a different KEK
assert_ne!(user1_envelope.kek_id, user2_envelope.kek_id);
```

## Running the Demo

```bash
cargo run
```

## Running Tests

```bash
cargo test
```

## Architecture

### Modules

| Module | Description |
|--------|-------------|
| `crypto` | AES-256-GCM encryption |
| `storage` | Storage trait and in-memory implementation |
| `key_manager` | Key hierarchy management (ServerKey, KEK, DEK) |
| `envelope` | High-level envelope encryption API |

### Key Types

| Key Type | Purpose | Encrypted By | Rotation |
|----------|---------|--------------|----------|
| **ServerKey** | Per-server root key for DB and system security | Stored in HSM/KMS | Manual, re-wraps all KEKs |
| **KEK** | Per-user master key (actual encryption key per user) | ServerKey (stored as EKEK) | Manual, re-wraps user's DEKs |
| **DEK** | One-time data encryption key | User's KEK (stored as EDEK) | Not needed (one-time use) |

### Storage Backend

The `KeyStorage` trait allows for different storage backends:

```rust
pub trait KeyStorage: Send + Sync {
    fn store_key(&self, stored_key: StoredKey) -> Result<()>;
    fn get_key(&self, key_id: &Uuid) -> Result<Option<StoredKey>>;
    fn get_kek_by_user_id(&self, user_id: &Uuid) -> Result<Option<StoredKey>>;
    fn get_active_server_key(&self) -> Result<Option<StoredKey>>;
    // ... more methods
}
```

Currently implemented:
- `InMemoryStorage` - For development and testing

Planned:
- PostgreSQL storage (enable with `--features postgres`)

## Key Derivation

**Important**: This implementation does NOT use HKDF or any key derivation function. The architecture uses standard envelope encryption:

1. **Encryption Flow**:
   - Input: `user_id`, `plaintext`, optional `cid`
   - Generate one-time DEK (random 256-bit key)
   - Encrypt plaintext with DEK using AES-256-GCM (with `cid` as AAD)
   - Get or create user's KEK (per `user_id`)
   - Encrypt DEK with KEK to create EDEK (with `dek_id` as AAD)
   - Store EDEK with nonce and tag
   - Output: Encrypted data + EDEK metadata

2. **Decryption Flow**:
   - Input: `user_id`, EDEK (ciphertext + nonce + tag), `dek_id`
   - Get user's KEK using `user_id`
   - Decrypt EDEK using KEK to recover DEK (verifying `dek_id` as AAD)
   - Decrypt data using DEK (verifying `cid` as AAD)
   - Output: Plaintext

## Security Considerations

1. **Server Key Protection**: In production, the server key should be stored in an HSM or KMS
2. **Key Zeroization**: All key material is automatically zeroized when dropped
3. **AAD Binding**:
   - Data ciphertexts are bound to their `cid` using Additional Authenticated Data
   - EDEKs are bound to their `dek_id`
   - EKEKs are bound to their `user_id`
4. **Unique Nonces**: Each encryption generates a fresh random nonce
5. **User Isolation**: Each user's data can only be decrypted with their specific KEK

## Version Tracking

Both Server Keys and KEKs maintain version numbers:

- **Server Key Version**: Increments on each server key rotation
- **KEK Version**: Each user's KEK maintains its own version, increments on rotation
- **DEK Version**: Always 1 (one-time use, no rotation)

Example:
```rust
let stats = service.get_stats().unwrap();
println!("Server Key Version: v{}", stats.server_key_version);
println!("Active KEKs: {}", stats.active_keks);
println!("One-time DEKs: {}", stats.total_deks);
```

## License

MIT
