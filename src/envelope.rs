//! Envelope Encryption Module
//! 
//! Provides high-level APIs for envelope encryption operations,
//! combining key management and cryptographic operations.

use std::sync::Arc;
use chrono::Utc;
use uuid::Uuid;
use std::collections::HashMap;

use crate::crypto::{AesGcmCipher, EncryptedData, SecureKey};
use crate::error::{EnvelopeError, Result};
use crate::key_manager::{KeyManager, RotationResult, KeyStats};
use crate::storage::{EncryptedRecord, KeyStorage};

/// Envelope encryption service
/// 
/// This is the main entry point for envelope encryption operations.
/// It manages the key hierarchy and provides encrypt/decrypt operations.
pub struct EnvelopeEncryption<S: KeyStorage> {
    key_manager: KeyManager<S>,
    storage: Arc<S>,
    /// Default KEK ID for new data encryption
    default_kek_id: Option<Uuid>,
}

impl<S: KeyStorage> EnvelopeEncryption<S> {
    /// Create a new EnvelopeEncryption service
    pub fn new(storage: Arc<S>) -> Result<Self> {
        let key_manager = KeyManager::new(Arc::clone(&storage))?;
        
        Ok(Self {
            key_manager,
            storage,
            default_kek_id: None,
        })
    }

    /// Create with an existing master key (for recovery)
    pub fn with_master_key(
        storage: Arc<S>,
        master_key: SecureKey,
        key_id: Uuid,
        version: u32,
    ) -> Self {
        let key_manager = KeyManager::with_master_key(
            Arc::clone(&storage),
            master_key,
            key_id,
            version,
        );
        
        Self {
            key_manager,
            storage,
            default_kek_id: None,
        }
    }

    /// Initialize the service with a default KEK
    /// 
    /// This creates a default KEK that will be used for all encrypt operations
    /// unless a specific KEK is provided.
    pub fn initialize(&mut self) -> Result<Uuid> {
        let kek_id = self.key_manager.generate_kek()?;
        self.default_kek_id = Some(kek_id);
        Ok(kek_id)
    }

    /// Set the default KEK to use for encryption
    pub fn set_default_kek(&mut self, kek_id: Uuid) {
        self.default_kek_id = Some(kek_id);
    }

    /// Get the default KEK ID
    pub fn default_kek_id(&self) -> Option<Uuid> {
        self.default_kek_id
    }

    /// Encrypt data using envelope encryption
    /// 
    /// This method:
    /// 1. Generates a new DEK (or reuses existing one for the data_id)
    /// 2. Encrypts the data with the DEK
    /// 3. Stores the encrypted data and key references
    /// 
    /// # Arguments
    /// * `plaintext` - The data to encrypt
    /// * `data_id` - Optional data identifier (for key reuse)
    /// * `metadata` - Optional metadata to store with the encrypted data
    /// 
    /// # Returns
    /// An `EncryptedEnvelope` containing all information needed for decryption
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        data_id: Option<Uuid>,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<EncryptedEnvelope> {
        let kek_id = self.default_kek_id
            .ok_or_else(|| EnvelopeError::Config("No default KEK set. Call initialize() first.".into()))?;
        
        self.encrypt_with_kek(plaintext, &kek_id, data_id, metadata)
    }

    /// Encrypt data using a specific KEK
    pub fn encrypt_with_kek(
        &self,
        plaintext: &[u8],
        kek_id: &Uuid,
        data_id: Option<Uuid>,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<EncryptedEnvelope> {
        let actual_data_id = data_id.unwrap_or_else(Uuid::new_v4);
        
        // Try to get existing DEK for this data_id, or generate new one
        let dek_info = if let Some(existing) = self.key_manager.get_dek_for_data(&actual_data_id)? {
            existing
        } else {
            self.key_manager.generate_dek(kek_id, Some(actual_data_id))?
        };
        
        // Encrypt the data with DEK
        let aad = actual_data_id.as_bytes(); // Bind ciphertext to data ID
        let encrypted_data = AesGcmCipher::encrypt(&dek_info.dek, plaintext, Some(aad))?;
        
        // Create encrypted record for storage
        let record = EncryptedRecord {
            record_id: actual_data_id,
            dek_id: dek_info.dek_id,
            dek_version: 1,
            encrypted_data: encrypted_data.ciphertext.clone(),
            nonce: encrypted_data.nonce.clone(),
            created_at: Utc::now(),
            metadata: metadata.unwrap_or_default(),
        };
        
        self.storage.store_record(record)?;
        
        Ok(EncryptedEnvelope {
            data_id: actual_data_id,
            dek_id: dek_info.dek_id,
            kek_id: dek_info.kek_id,
            encrypted_data,
        })
    }

    /// Decrypt data using envelope encryption
    /// 
    /// # Arguments
    /// * `envelope` - The encrypted envelope to decrypt
    /// 
    /// # Returns
    /// The decrypted plaintext
    pub fn decrypt(&self, envelope: &EncryptedEnvelope) -> Result<Vec<u8>> {
        // Unwrap the DEK
        let dek = self.key_manager.unwrap_dek(&envelope.dek_id)?;
        
        // Decrypt the data
        let aad = envelope.data_id.as_bytes();
        let plaintext = AesGcmCipher::decrypt(&dek, &envelope.encrypted_data, Some(aad))?;
        
        Ok(plaintext)
    }

    /// Decrypt data by data ID (looks up from storage)
    pub fn decrypt_by_id(&self, data_id: &Uuid) -> Result<Vec<u8>> {
        let record = self.storage.get_record(data_id)?
            .ok_or_else(|| EnvelopeError::KeyNotFound(format!("Record {}", data_id)))?;
        
        let dek = self.key_manager.unwrap_dek(&record.dek_id)?;
        
        let encrypted_data = EncryptedData::new(record.nonce, record.encrypted_data);
        let aad = data_id.as_bytes();
        
        let plaintext = AesGcmCipher::decrypt(&dek, &encrypted_data, Some(aad))?;
        
        Ok(plaintext)
    }

    /// Re-encrypt data with a new DEK (for key rotation)
    pub fn reencrypt(&self, data_id: &Uuid, new_kek_id: Option<&Uuid>) -> Result<EncryptedEnvelope> {
        // Decrypt the data first
        let plaintext = self.decrypt_by_id(data_id)?;
        
        // Delete old record
        self.storage.delete_record(data_id)?;
        
        // Delete old DEK association
        if let Some(_dek_info) = self.key_manager.get_dek_for_data(data_id)? {
            // Mark the old DEK as inactive (we'll create a new one)
            // In a production system, you might want to keep the old DEK
            // for audit purposes
        }
        
        // Re-encrypt with new KEK (or default)
        let kek_id = new_kek_id
            .cloned()
            .or(self.default_kek_id)
            .ok_or_else(|| EnvelopeError::Config("No KEK available".into()))?;
        
        // Generate a fresh data_id for the re-encrypted data
        let new_data_id = Uuid::new_v4();
        self.encrypt_with_kek(&plaintext, &kek_id, Some(new_data_id), None)
    }

    // === Key Management Operations ===

    /// Generate a new KEK
    pub fn generate_kek(&self) -> Result<Uuid> {
        self.key_manager.generate_kek()
    }

    /// Rotate the master key
    pub fn rotate_master_key(&mut self) -> Result<RotationResult> {
        self.key_manager.rotate_master_key()
    }

    /// Rotate a specific KEK
    pub fn rotate_kek(&self, kek_id: &Uuid) -> Result<RotationResult> {
        self.key_manager.rotate_kek(kek_id)
    }

    /// Get key hierarchy statistics
    pub fn get_stats(&self) -> Result<KeyStats> {
        self.key_manager.get_stats()
    }

    /// Get the current master key ID
    pub fn master_key_id(&self) -> Uuid {
        self.key_manager.master_key_id()
    }

    /// Get the current master key version
    pub fn master_key_version(&self) -> u32 {
        self.key_manager.master_key_version()
    }

    /// Export master key for backup (use with extreme caution!)
    pub fn export_master_key(&self) -> Vec<u8> {
        self.key_manager.export_master_key()
    }

    /// Derive a deterministic DEK for a data ID
    /// 
    /// This is useful for stateless encryption scenarios where you
    /// don't want to store DEKs but need reproducible keys.
    pub fn derive_dek_for_data(&self, data_id: &Uuid) -> Result<SecureKey> {
        self.key_manager.derive_dek(&data_id, "data-encryption")
    }

    /// Encrypt data using a derived DEK (stateless mode)
    /// 
    /// This doesn't store anything - the DEK is derived from the data_id.
    /// Useful for scenarios where you need deterministic encryption.
    pub fn encrypt_stateless(&self, plaintext: &[u8], data_id: &Uuid) -> Result<EncryptedData> {
        let dek = self.derive_dek_for_data(data_id)?;
        AesGcmCipher::encrypt(&dek, plaintext, Some(data_id.as_bytes()))
    }

    /// Decrypt data using a derived DEK (stateless mode)
    pub fn decrypt_stateless(&self, encrypted: &EncryptedData, data_id: &Uuid) -> Result<Vec<u8>> {
        let dek = self.derive_dek_for_data(data_id)?;
        AesGcmCipher::decrypt(&dek, encrypted, Some(data_id.as_bytes()))
    }
}

/// Result of an envelope encryption operation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedEnvelope {
    /// Unique identifier for this encrypted data
    pub data_id: Uuid,
    /// The DEK ID used for encryption
    pub dek_id: Uuid,
    /// The KEK ID that wraps the DEK
    pub kek_id: Uuid,
    /// The actual encrypted data
    pub encrypted_data: EncryptedData,
}

impl EncryptedEnvelope {
    /// Convert to JSON string for storage/transmission
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(EnvelopeError::from)
    }

    /// Parse from JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(EnvelopeError::from)
    }

    /// Get the ciphertext as base64
    pub fn ciphertext_base64(&self) -> String {
        self.encrypted_data.to_base64()
    }
}

/// Builder for envelope encryption configuration
pub struct EnvelopeEncryptionBuilder<S: KeyStorage> {
    storage: Arc<S>,
    master_key: Option<(SecureKey, Uuid, u32)>,
    auto_initialize: bool,
}

impl<S: KeyStorage> EnvelopeEncryptionBuilder<S> {
    /// Create a new builder with the given storage backend
    pub fn new(storage: Arc<S>) -> Self {
        Self {
            storage,
            master_key: None,
            auto_initialize: true,
        }
    }

    /// Use an existing master key
    pub fn with_master_key(mut self, key: SecureKey, id: Uuid, version: u32) -> Self {
        self.master_key = Some((key, id, version));
        self
    }

    /// Disable auto-initialization of default KEK
    pub fn skip_initialization(mut self) -> Self {
        self.auto_initialize = false;
        self
    }

    /// Build the EnvelopeEncryption service
    pub fn build(self) -> Result<EnvelopeEncryption<S>> {
        let mut service = match self.master_key {
            Some((key, id, version)) => {
                EnvelopeEncryption::with_master_key(self.storage, key, id, version)
            }
            None => EnvelopeEncryption::new(self.storage)?,
        };

        if self.auto_initialize {
            service.initialize()?;
        }

        Ok(service)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryStorage;

    #[test]
    fn test_envelope_encryption_roundtrip() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut service = EnvelopeEncryption::new(storage).unwrap();
        service.initialize().unwrap();

        let plaintext = b"Hello, Envelope Encryption!";
        
        let envelope = service.encrypt(plaintext, None, None).unwrap();
        let decrypted = service.decrypt(&envelope).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_stateless_encryption() {
        let storage = Arc::new(InMemoryStorage::new());
        let service = EnvelopeEncryption::new(storage).unwrap();

        let plaintext = b"Stateless encryption test";
        let data_id = Uuid::new_v4();
        
        let encrypted = service.encrypt_stateless(plaintext, &data_id).unwrap();
        let decrypted = service.decrypt_stateless(&encrypted, &data_id).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
        
        // Same data_id should produce same DEK (but different nonce)
        let encrypted2 = service.encrypt_stateless(plaintext, &data_id).unwrap();
        let decrypted2 = service.decrypt_stateless(&encrypted2, &data_id).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted2);
    }

    #[test]
    fn test_decrypt_by_id() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut service = EnvelopeEncryption::new(storage).unwrap();
        service.initialize().unwrap();

        let plaintext = b"Test data for ID lookup";
        let data_id = Uuid::new_v4();
        
        service.encrypt(plaintext, Some(data_id), None).unwrap();
        let decrypted = service.decrypt_by_id(&data_id).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_envelope_json_serialization() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut service = EnvelopeEncryption::new(storage).unwrap();
        service.initialize().unwrap();

        let plaintext = b"JSON test";
        let envelope = service.encrypt(plaintext, None, None).unwrap();
        
        let json = envelope.to_json().unwrap();
        let restored = EncryptedEnvelope::from_json(&json).unwrap();
        
        assert_eq!(envelope.data_id, restored.data_id);
        assert_eq!(envelope.dek_id, restored.dek_id);
        assert_eq!(envelope.kek_id, restored.kek_id);
        
        let decrypted = service.decrypt(&restored).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_builder_pattern() {
        let storage = Arc::new(InMemoryStorage::new());
        let service = EnvelopeEncryptionBuilder::new(storage)
            .build()
            .unwrap();

        assert!(service.default_kek_id().is_some());
    }

    #[test]
    fn test_key_rotation_preserves_data() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut service = EnvelopeEncryption::new(storage).unwrap();
        service.initialize().unwrap();

        let plaintext = b"Data to survive rotation";
        let envelope = service.encrypt(plaintext, None, None).unwrap();
        
        // Rotate master key
        let rotation_result = service.rotate_master_key().unwrap();
        assert!(rotation_result.keys_rewrapped >= 1);
        
        // Data should still be decryptable
        let decrypted = service.decrypt(&envelope).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }
}

