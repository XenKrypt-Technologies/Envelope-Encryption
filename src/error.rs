//! Error types for the envelope encryption module

use thiserror::Error;

/// Result type alias for envelope encryption operations
pub type Result<T> = std::result::Result<T, EnvelopeError>;

/// Errors that can occur during envelope encryption operations
#[derive(Error, Debug)]
pub enum EnvelopeError {
    /// Cryptographic operation failed
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Key not found in storage
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Invalid key state or version
    #[error("Invalid key state: {0}")]
    InvalidKeyState(String),

    /// Storage operation failed
    #[error("Storage error: {0}")]
    Storage(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Key rotation error
    #[error("Key rotation error: {0}")]
    KeyRotation(String),

    /// Invalid configuration
    #[error("Configuration error: {0}")]
    Config(String),

    /// Operation not permitted
    #[error("Operation not permitted: {0}")]
    NotPermitted(String),

    /// Data integrity error
    #[error("Data integrity error: {0}")]
    Integrity(String),
}

impl From<serde_json::Error> for EnvelopeError {
    fn from(err: serde_json::Error) -> Self {
        EnvelopeError::Serialization(err.to_string())
    }
}


