use thiserror::Error;

pub type Result<T> = std::result::Result<T, EnvelopeError>;

#[derive(Error, Debug)]
pub enum EnvelopeError {
    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Invalid key state: {0}")]
    InvalidKeyState(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Key rotation error: {0}")]
    KeyRotation(String),

    #[error("Config error: {0}")]
    Config(String),
}

impl From<serde_json::Error> for EnvelopeError {
    fn from(err: serde_json::Error) -> Self {
        EnvelopeError::Serialization(err.to_string())
    }
}
