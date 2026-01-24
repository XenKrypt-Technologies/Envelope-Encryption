use std::sync::Arc;
use chrono::Utc;
use uuid::Uuid;

use crate::crypto::{AesGcmCipher, EncryptedData, SecureKey};
use crate::error::{EnvelopeError, Result};
use crate::key_manager::{KeyManager, RotationResult, KeyStats};
use crate::storage::{EncryptedRecord, KeyStorage};

/// New envelope encryption architecture:
/// - Each server has its own ServerKey (for DB and system security)
/// - Each user has their own KEK (actual master key per user_id)
/// - DEKs are one-time use (no rotation needed)
/// - ServerKey and KEK support manual rotation with versioning
pub struct EnvelopeEncryption<S: KeyStorage> {
    key_manager: KeyManager<S>,
    storage: Arc<S>,
}

impl<S: KeyStorage> EnvelopeEncryption<S> {
    pub fn new(storage: Arc<S>) -> Result<Self> {
        let key_manager = KeyManager::new(Arc::clone(&storage))?;
        Ok(Self { key_manager, storage })
    }

    pub fn with_server_key(
        storage: Arc<S>,
        server_key: SecureKey,
        server_key_id: Uuid,
        version: u32,
    ) -> Self {
        let key_manager = KeyManager::with_server_key(
            Arc::clone(&storage),
            server_key,
            server_key_id,
            version,
        );
        Self { key_manager, storage }
    }

    pub fn server_key_id(&self) -> Uuid {
        self.key_manager.server_key_id()
    }

    pub fn server_key_version(&self) -> u32 {
        self.key_manager.server_key_version()
    }

    /// Encrypt data for a specific user
    /// - user_id: UUID of the user (required - determines which KEK to use)
    /// - cid: Optional content ID (auto-generated if not provided)
    pub fn encrypt(&self, plaintext: &[u8], user_id: &Uuid, cid: Option<Uuid>) -> Result<EncryptedEnvelope> {
        let actual_cid = cid.unwrap_or_else(Uuid::new_v4);

        // Generate one-time DEK for this user
        let dek_info = self.key_manager.generate_dek(user_id, Some(actual_cid))?;

        // Encrypt data with DEK (using cid as AAD)
        let encrypted = AesGcmCipher::encrypt(&dek_info.dek, plaintext, Some(actual_cid.as_bytes()))?;

        // Store encrypted record
        self.storage.store_record(EncryptedRecord {
            cid: actual_cid,
            dek_id: dek_info.dek_id,
            encrypted_data: encrypted.ciphertext.clone(),
            nonce: encrypted.nonce.clone(),
            created_at: Utc::now(),
        })?;

        Ok(EncryptedEnvelope {
            cid: actual_cid,
            user_id: *user_id,
            dek_id: dek_info.dek_id,
            kek_id: dek_info.kek_id,
            encrypted_data: encrypted,
        })
    }

    /// Decrypt using an envelope
    pub fn decrypt(&self, envelope: &EncryptedEnvelope) -> Result<Vec<u8>> {
        let dek = self.key_manager.unwrap_dek(&envelope.dek_id)?;
        AesGcmCipher::decrypt(&dek, &envelope.encrypted_data, Some(envelope.cid.as_bytes()))
    }

    /// Decrypt by content ID
    pub fn decrypt_by_cid(&self, cid: &Uuid) -> Result<Vec<u8>> {
        let record = self
            .storage
            .get_record(cid)?
            .ok_or_else(|| EnvelopeError::KeyNotFound(format!("Record {}", cid)))?;

        let dek = self.key_manager.unwrap_dek(&record.dek_id)?;
        let encrypted = EncryptedData::new(record.nonce, record.encrypted_data);
        AesGcmCipher::decrypt(&dek, &encrypted, Some(cid.as_bytes()))
    }

    /// Rotate server key and re-wrap all user KEKs
    pub fn rotate_server_key(&mut self) -> Result<RotationResult> {
        self.key_manager.rotate_server_key()
    }

    /// Rotate a specific user's KEK and re-wrap all their DEKs
    pub fn rotate_user_kek(&self, user_id: &Uuid) -> Result<RotationResult> {
        self.key_manager.rotate_user_kek(user_id)
    }

    pub fn get_stats(&self) -> Result<KeyStats> {
        self.key_manager.get_stats()
    }

    /// Export server key (to encrypt as EKEK for secure storage)
    pub fn export_server_key(&self) -> Vec<u8> {
        self.key_manager.export_server_key()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedEnvelope {
    pub cid: Uuid,
    pub user_id: Uuid,
    pub dek_id: Uuid,
    pub kek_id: Uuid,
    pub encrypted_data: EncryptedData,
}

impl EncryptedEnvelope {
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(EnvelopeError::from)
    }

    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(EnvelopeError::from)
    }

    pub fn ciphertext_base64(&self) -> String {
        self.encrypted_data.to_base64()
    }
}
