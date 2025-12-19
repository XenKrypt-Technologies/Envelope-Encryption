//! # Envelope Encryption
//!
//! A Rust implementation of envelope encryption with per-user key encryption keys and PostgreSQL-backed storage.
//!
//! ## Overview
//!
//! This library provides a complete envelope encryption solution where:
//! - **Data Encryption Keys (DEKs)** are one-time keys that encrypt actual data
//! - **Key Encryption Keys (KEKs)** are per-user master keys that wrap/encrypt DEKs
//! - **Database Encryption** protects KEKs at rest in PostgreSQL
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use envelope_encryption::{PostgresStorage, PostgresEnvelopeService, AesGcmCipher};
//! use sqlx::PgPool;
//! use uuid::Uuid;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize service
//! let pool = PgPool::connect("postgresql://localhost/envelope_encryption").await?;
//! let storage = PostgresStorage::new(pool);
//! let service = PostgresEnvelopeService::new(storage).await?;
//!
//! // Generate DEK for a user
//! let user_id = Uuid::new_v4();
//! let dek = service.generate_dek(&user_id).await?;
//!
//! // Encrypt data
//! let plaintext = b"Sensitive data";
//! let encrypted = AesGcmCipher::encrypt(&dek.dek, plaintext, None)?;
//!
//! // Decrypt data
//! let recovered_dek = service.decrypt_edek(
//!     &dek.dek_id,
//!     &dek.edek_blob,
//!     &user_id,
//!     dek.kek_version
//! ).await?;
//! let decrypted = AesGcmCipher::decrypt(&recovered_dek, &encrypted, None)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Key Features
//!
//! - **AES-256-GCM**: Industry-standard authenticated encryption
//! - **Per-User KEKs**: Each user has their own isolated KEK
//! - **KEK Rotation**: Rotate individual KEKs or all KEKs in bulk
//! - **Version Tracking**: Maintain backward compatibility with old KEKs
//! - **PostgreSQL Storage**: Production-ready persistent storage
//! - **Zero-copy Security**: Keys are zeroized from memory when dropped
//!
//! ## Modules
//!
//! - [`crypto`] - AES-256-GCM encryption primitives
//! - [`postgres_storage`] - PostgreSQL storage backend for KEKs
//! - [`postgres_envelope`] - High-level envelope encryption service
//! - [`error`] - Error types and Result aliases
//!
//! ## Core Types
//!
//! ### Service Types
//!
//! - [`PostgresEnvelopeService`] - Main service for envelope encryption operations
//! - [`PostgresStorage`] - PostgreSQL storage backend
//!
//! ### Data Types
//!
//! - [`GeneratedDek`] - Result of DEK generation with EDEK blob
//! - [`StoredKek`] - KEK stored in database with metadata
//! - [`KekStatus`] - KEK lifecycle status (Active, Retired, Disabled)
//!
//! ### Result Types
//!
//! - [`BulkRotationResult`] - Result of bulk KEK rotation
//! - [`UserKekRotationResult`] - Result of single user KEK rotation
//!
//! ### Crypto Types
//!
//! - [`AesGcmCipher`] - AES-256-GCM encryption/decryption
//! - [`SecureKey`] - Secure key wrapper with automatic zeroization
//! - [`EncryptedData`] - Encrypted data with nonce and authentication tag
//!
//! ## Examples
//!
//! ### Basic Encryption/Decryption
//!
//! ```rust,no_run
//! use envelope_encryption::{PostgresEnvelopeService, AesGcmCipher};
//! use uuid::Uuid;
//!
//! # async fn example(service: PostgresEnvelopeService) -> Result<(), Box<dyn std::error::Error>> {
//! let user_id = Uuid::new_v4();
//!
//! // Generate DEK (creates KEK automatically if needed)
//! let dek = service.generate_dek(&user_id).await?;
//!
//! // Encrypt data
//! let plaintext = b"Secret message";
//! let encrypted = AesGcmCipher::encrypt(&dek.dek, plaintext, None)?;
//!
//! // Later: decrypt data
//! let recovered_dek = service.decrypt_edek(
//!     &dek.dek_id,
//!     &dek.edek_blob,
//!     &user_id,
//!     dek.kek_version
//! ).await?;
//! let decrypted = AesGcmCipher::decrypt(&recovered_dek, &encrypted, None)?;
//! assert_eq!(plaintext, &decrypted[..]);
//! # Ok(())
//! # }
//! ```
//!
//! ### KEK Rotation
//!
//! ```rust,no_run
//! use envelope_encryption::{PostgresEnvelopeService, UserKekRotationResult};
//! use uuid::Uuid;
//!
//! # async fn example(service: PostgresEnvelopeService) -> Result<(), Box<dyn std::error::Error>> {
//! let user_id = Uuid::new_v4();
//!
//! // Rotate a specific user's KEK
//! let result = service.rotate_user_kek(&user_id).await?;
//! println!("Rotated KEK: v{} -> v{}", result.old_version, result.new_version);
//!
//! // Or rotate all KEKs in bulk
//! let bulk_result = service.bulk_rotate_all_keks().await?;
//! println!("Rotated {} KEKs", bulk_result.keks_rotated);
//! # Ok(())
//! # }
//! ```
//!
//! ### KEK Lifecycle Management
//!
//! ```rust,no_run
//! use envelope_encryption::PostgresEnvelopeService;
//! use uuid::Uuid;
//!
//! # async fn example(service: PostgresEnvelopeService) -> Result<(), Box<dyn std::error::Error>> {
//! let user_id = Uuid::new_v4();
//! let old_version = 1;
//!
//! // Disable a RETIRED KEK
//! service.disable_kek(&user_id, old_version).await?;
//!
//! // Delete a DISABLED KEK
//! service.delete_kek(&user_id, old_version).await?;
//!
//! // Monitor KEK statistics
//! let stats = service.get_kek_stats().await?;
//! for (status, count) in stats {
//!     println!("{}: {}", status, count);
//! }
//! # Ok(())
//! # }
//! ```

pub mod crypto;
pub mod error;
pub mod storage;
pub mod key_manager;
pub mod envelope;

// PostgreSQL backend modules
pub mod postgres_storage;
pub mod postgres_envelope;

// ============================================================================
// Crypto Exports
// ============================================================================

/// AES-256-GCM cipher for authenticated encryption.
///
/// Provides encrypt/decrypt operations with optional Additional Authenticated Data (AAD).
pub use crypto::AesGcmCipher;

/// Encrypted data with nonce and authentication tag.
pub use crypto::EncryptedData;

/// Secure key wrapper with automatic zeroization on drop.
pub use crypto::SecureKey;

/// AES-256 key size in bytes (32 bytes).
pub use crypto::AES_256_KEY_SIZE;

/// AES-GCM nonce size in bytes (12 bytes).
pub use crypto::NONCE_SIZE;

// ============================================================================
// Error Exports
// ============================================================================

/// Error types for envelope encryption operations.
pub use error::EnvelopeError;

/// Result type alias using [`EnvelopeError`].
pub use error::Result;

// ============================================================================
// Legacy Storage Exports (In-Memory)
// ============================================================================

/// Storage trait for key management backends.
pub use storage::KeyStorage;

/// In-memory storage implementation for testing.
pub use storage::InMemoryStorage;

/// Metadata for stored keys.
pub use storage::KeyMetadata;

/// Key type enumeration.
pub use storage::KeyType;

/// Stored key with metadata.
pub use storage::StoredKey;

/// Encrypted record wrapper.
pub use storage::EncryptedRecord;

// ============================================================================
// Legacy Key Manager Exports
// ============================================================================

/// Key manager for server key and KEK/DEK operations.
pub use key_manager::KeyManager;

/// DEK information returned by key manager.
pub use key_manager::DekInfo;

/// User KEK information.
pub use key_manager::UserKekInfo;

/// Key rotation result.
pub use key_manager::RotationResult;

/// Key statistics.
pub use key_manager::KeyStats;

// ============================================================================
// Legacy Envelope Exports
// ============================================================================

/// Legacy envelope encryption service (in-memory).
pub use envelope::EnvelopeEncryption;

/// Encrypted envelope structure.
pub use envelope::EncryptedEnvelope;

// ============================================================================
// PostgreSQL Exports (Primary API)
// ============================================================================

/// PostgreSQL storage backend for KEKs.
///
/// Stores KEKs as plaintext in PostgreSQL, relying on database encryption at rest.
pub use postgres_storage::PostgresStorage;

/// Stored KEK with lifecycle status and metadata.
pub use postgres_storage::StoredKek;

/// KEK lifecycle status: Active, Retired, or Disabled.
pub use postgres_storage::KekStatus;

/// PostgreSQL-backed envelope encryption service.
///
/// Main service for production use with persistent storage.
pub use postgres_envelope::PostgresEnvelopeService;

/// Result of DEK generation including EDEK blob.
pub use postgres_envelope::GeneratedDek;

/// Result of bulk KEK rotation operation.
pub use postgres_envelope::BulkRotationResult;

/// Result of single user KEK rotation.
pub use postgres_envelope::UserKekRotationResult;
