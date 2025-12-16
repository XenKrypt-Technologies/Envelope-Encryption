use std::sync::Arc;
use chrono::Utc;
use uuid::Uuid;

use crate::crypto::{AesGcmCipher, EncryptedData, SecureKey};
use crate::error::{EnvelopeError, Result};
use crate::key_manager::{KeyManager, RotationResult, KeyStats};
use crate::storage::{EncryptedRecord, KeyStorage};

/// HSM-like envelope encryption: KEK → DEK (EDEK)
pub struct EnvelopeEncryption<S: KeyStorage> {
    key_manager: KeyManager<S>,
    storage: Arc<S>,
}

impl<S: KeyStorage> EnvelopeEncryption<S> {
    pub fn new(storage: Arc<S>) -> Result<Self> {
        let key_manager = KeyManager::new(Arc::clone(&storage))?;
        Ok(Self { key_manager, storage })
    }

    pub fn with_kek(storage: Arc<S>, kek: SecureKey, kek_id: Uuid, version: u32) -> Self {
        let key_manager = KeyManager::with_kek(Arc::clone(&storage), kek, kek_id, version);
        Self { key_manager, storage }
    }

    pub fn kek_id(&self) -> Uuid {
        self.key_manager.kek_id()
    }

    pub fn kek_version(&self) -> u32 {
        self.key_manager.kek_version()
    }

    pub fn encrypt(&self, plaintext: &[u8], cid: Option<Uuid>) -> Result<EncryptedEnvelope> {
        let actual_cid = cid.unwrap_or_else(Uuid::new_v4);

        let dek_info = if let Some(existing) = self.key_manager.get_dek_for_cid(&actual_cid)? {
            existing
        } else {
            self.key_manager.generate_dek(Some(actual_cid))?
        };

        let encrypted = AesGcmCipher::encrypt(&dek_info.dek, plaintext, Some(actual_cid.as_bytes()))?;

        self.storage.store_record(EncryptedRecord {
            cid: actual_cid,
            dek_id: dek_info.dek_id,
            encrypted_data: encrypted.ciphertext.clone(),
            nonce: encrypted.nonce.clone(),
            created_at: Utc::now(),
        })?;

        Ok(EncryptedEnvelope {
            cid: actual_cid,
            dek_id: dek_info.dek_id,
            kek_id: dek_info.kek_id,
            encrypted_data: encrypted,
        })
    }

    pub fn decrypt(&self, envelope: &EncryptedEnvelope) -> Result<Vec<u8>> {
        let dek = self.key_manager.unwrap_dek(&envelope.dek_id)?;
        AesGcmCipher::decrypt(&dek, &envelope.encrypted_data, Some(envelope.cid.as_bytes()))
    }

    pub fn decrypt_by_cid(&self, cid: &Uuid) -> Result<Vec<u8>> {
        let record = self.storage.get_record(cid)?
            .ok_or_else(|| EnvelopeError::KeyNotFound(format!("Record {}", cid)))?;

        let dek = self.key_manager.unwrap_dek(&record.dek_id)?;
        let encrypted = EncryptedData::new(record.nonce, record.encrypted_data);
        AesGcmCipher::decrypt(&dek, &encrypted, Some(cid.as_bytes()))
    }

    pub fn rotate_kek(&mut self) -> Result<RotationResult> {
        self.key_manager.rotate_kek()
    }

    pub fn get_stats(&self) -> Result<KeyStats> {
        self.key_manager.get_stats()
    }

    /// Export KEK (to encrypt as EKEK for server storage)
    pub fn export_kek(&self) -> Vec<u8> {
        self.key_manager.export_kek()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedEnvelope {
    pub cid: Uuid,
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
