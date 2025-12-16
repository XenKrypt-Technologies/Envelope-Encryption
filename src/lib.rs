pub mod crypto;
pub mod error;
pub mod storage;
pub mod key_manager;
pub mod envelope;

// PostgreSQL backend modules
pub mod postgres_storage;
pub mod postgres_envelope;

pub use crypto::{AesGcmCipher, EncryptedData, SecureKey, AES_256_KEY_SIZE, NONCE_SIZE};
pub use error::{EnvelopeError, Result};
pub use storage::{KeyStorage, InMemoryStorage, KeyMetadata, KeyType, StoredKey, EncryptedRecord};
pub use key_manager::{KeyManager, DekInfo, UserKekInfo, RotationResult, KeyStats};
pub use envelope::{EnvelopeEncryption, EncryptedEnvelope};

// PostgreSQL exports
pub use postgres_storage::{PostgresStorage, StoredKek};
pub use postgres_envelope::{PostgresEnvelopeService, GeneratedDek, KekRotationResult};
