# Envelope Encryption

A Rust implementation of HSM-like envelope encryption with a hierarchical key management system.

## Overview

Envelope encryption is a data protection strategy where:
1. **Data Encryption Key (DEK)** - Encrypts the actual data
2. **Key Encryption Key (KEK)** - Wraps/encrypts the DEK
3. **Master Key (MK)** - Root of trust, protects all KEKs

This creates layers of protection and enables **key rotation without re-encrypting all data**.

## Key Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│                    Master Key (MK)                          │
│         Root of trust, protects all KEKs                   │
└─────────────────────────┬───────────────────────────────────┘
                          │
              ┌───────────┴───────────┐
              │                       │
              ▼                       ▼
┌─────────────────────┐   ┌─────────────────────┐
│   KEK-1 (wrapped)   │   │   KEK-2 (wrapped)   │
│  Key Encryption Key │   │  Key Encryption Key │
└──────────┬──────────┘   └──────────┬──────────┘
           │                         │
    ┌──────┴──────┐          ┌───────┴───────┐
    │             │          │               │
    ▼             ▼          ▼               ▼
┌───────┐    ┌───────┐  ┌───────┐      ┌───────┐
│ DEK-1 │    │ DEK-2 │  │ DEK-3 │      │ DEK-4 │
│(wrap) │    │(wrap) │  │(wrap) │      │(wrap) │
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
- **HKDF-SHA256**: Modern key derivation (upgraded from simple HMAC-SHA256)
- **Key Rotation**: Rotate Master Keys, KEKs, or DEKs independently
- **Pluggable Storage**: In-memory (included), PostgreSQL (planned)
- **Zero-copy Security**: Keys are zeroized from memory when dropped
- **Department Isolation**: Multiple KEKs for tenant/department separation
- **Stateless Mode**: HKDF-derived DEKs for deterministic encryption

## Quick Start

```rust
use envelope_encryption::{EnvelopeEncryption, InMemoryStorage};
use std::sync::Arc;

// Create storage and encryption service
let storage = Arc::new(InMemoryStorage::new());
let mut service = EnvelopeEncryption::new(storage).unwrap();
service.initialize().unwrap();

// Encrypt data
let plaintext = b"Secret message";
let envelope = service.encrypt(plaintext, None, None).unwrap();

// Decrypt data
let decrypted = service.decrypt(&envelope).unwrap();
assert_eq!(plaintext.to_vec(), decrypted);
```

## Key Rotation

### Master Key Rotation

Automatically re-wraps all KEKs with the new master key:

```rust
let result = service.rotate_master_key().unwrap();
println!("Rotated: v{} -> v{}", result.old_version, result.new_version);
println!("KEKs re-wrapped: {}", result.keys_rewrapped);
```

### KEK Rotation

Re-wraps all DEKs under the rotated KEK:

```rust
let result = service.rotate_kek(&kek_id).unwrap();
println!("DEKs re-wrapped: {}", result.keys_rewrapped);
```

## Department Isolation

Create separate KEKs for different departments/tenants:

```rust
let hr_kek = service.generate_kek().unwrap();
let finance_kek = service.generate_kek().unwrap();

// HR data uses HR KEK
let hr_envelope = service.encrypt_with_kek(hr_data, &hr_kek, None, None).unwrap();

// Finance data uses Finance KEK
let finance_envelope = service.encrypt_with_kek(finance_data, &finance_kek, None, None).unwrap();
```

## Stateless Encryption (HKDF-derived DEKs)

For scenarios where you don't want to store DEKs:

```rust
let data_id = Uuid::new_v4();

// DEK is derived from Master Key + Data ID using HKDF-SHA256
let encrypted = service.encrypt_stateless(plaintext, &data_id).unwrap();

// Same data_id will derive the same DEK
let decrypted = service.decrypt_stateless(&encrypted, &data_id).unwrap();
```

This is the **upgraded approach** from the previous HMAC-SHA256 key derivation, using HKDF which is specifically designed for key derivation with proper extract-and-expand phases.

## Running the Demo

```bash
cargo run --bin demo
```

## Running Tests

```bash
cargo test
```

## Architecture

### Modules

| Module | Description |
|--------|-------------|
| `crypto` | AES-256-GCM encryption, HKDF key derivation |
| `storage` | Storage trait and in-memory implementation |
| `key_manager` | Key hierarchy management (MK, KEK, DEK) |
| `envelope` | High-level envelope encryption API |

### Storage Backend

The `KeyStorage` trait allows for different storage backends:

```rust
pub trait KeyStorage: Send + Sync {
    fn store_key(&self, stored_key: StoredKey) -> Result<()>;
    fn get_key(&self, key_id: &Uuid) -> Result<Option<StoredKey>>;
    fn get_active_key(&self, key_type: &KeyType) -> Result<Option<StoredKey>>;
    // ... more methods
}
```

Currently implemented:
- `InMemoryStorage` - For development and testing

Planned:
- PostgreSQL storage (enable with `--features postgres`)

## Security Considerations

1. **Master Key Protection**: In production, the master key should be stored in an HSM or secure enclave
2. **Key Zeroization**: All key material is automatically zeroized when dropped
3. **AAD Binding**: Ciphertexts are bound to their data IDs using Additional Authenticated Data (AAD)
4. **Unique Nonces**: Each encryption generates a fresh random nonce

## License

MIT


