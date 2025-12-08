//! Key Management Module
//! 
//! Implements the key hierarchy for envelope encryption:
//! - Master Key (MK): Root of trust, used to derive/wrap KEKs
//! - Key Encryption Key (KEK): Used to wrap DEKs
//! - Data Encryption Key (DEK): Used to encrypt actual data

use std::sync::Arc;
use chrono::Utc;
use uuid::Uuid;

use crate::crypto::{AesGcmCipher, EncryptedData, KeyDerivation, SecureKey};
use crate::error::{EnvelopeError, Result};
use crate::storage::{KeyMetadata, KeyStorage, KeyType, StoredKey};

/// Key Manager responsible for the entire key hierarchy
pub struct KeyManager<S: KeyStorage> {
    storage: Arc<S>,
    /// Current master key (in a real HSM, this would be hardware-protected)
    master_key: SecureKey,
    /// Master key ID for tracking
    master_key_id: Uuid,
    /// Master key version
    master_key_version: u32,
}

impl<S: KeyStorage> KeyManager<S> {
    /// Initialize a new KeyManager with a fresh master key
    pub fn new(storage: Arc<S>) -> Result<Self> {
        let master_key = SecureKey::generate();
        let master_key_id = Uuid::new_v4();
        
        // Store master key metadata (in production, the key itself would be in HSM)
        let mut metadata = KeyMetadata::new(KeyType::MasterKey);
        metadata.key_id = master_key_id;
        metadata.version = 1;
        
        // For in-memory demo, we store a placeholder
        // In real HSM scenario, the actual key would be hardware-protected
        let stored_mk = StoredKey {
            metadata,
            encrypted_key: vec![], // Master key is not encrypted, it's the root
            nonce: vec![],
        };
        
        storage.store_key(stored_mk)?;
        
        Ok(Self {
            storage,
            master_key,
            master_key_id,
            master_key_version: 1,
        })
    }

    /// Initialize KeyManager with an existing master key (for recovery/import)
    pub fn with_master_key(storage: Arc<S>, master_key: SecureKey, key_id: Uuid, version: u32) -> Self {
        Self {
            storage,
            master_key,
            master_key_id: key_id,
            master_key_version: version,
        }
    }

    /// Get the current master key ID
    pub fn master_key_id(&self) -> Uuid {
        self.master_key_id
    }

    /// Get the current master key version
    pub fn master_key_version(&self) -> u32 {
        self.master_key_version
    }

    /// Rotate the master key
    /// 
    /// This generates a new master key and re-wraps all existing KEKs.
    /// Old master key should be securely destroyed after rotation.
    pub fn rotate_master_key(&mut self) -> Result<RotationResult> {
        let old_version = self.master_key_version;
        let new_master_key = SecureKey::generate();
        let new_master_key_id = Uuid::new_v4();
        let new_version = old_version + 1;
        
        // Get all KEKs that need re-wrapping
        let keks = self.storage.get_keys_by_type(&KeyType::KeyEncryptionKey)?;
        let mut rewrapped_count = 0;
        
        for stored_kek in keks {
            if !stored_kek.metadata.is_active {
                continue;
            }
            
            // Unwrap KEK with old master key
            let encrypted_kek = EncryptedData::new(
                stored_kek.nonce.clone(),
                stored_kek.encrypted_key.clone(),
            );
            
            let kek_bytes = AesGcmCipher::decrypt(
                &self.master_key,
                &encrypted_kek,
                Some(stored_kek.metadata.key_id.as_bytes()),
            )?;
            
            // Re-wrap KEK with new master key
            let new_encrypted = AesGcmCipher::encrypt(
                &new_master_key,
                &kek_bytes,
                Some(stored_kek.metadata.key_id.as_bytes()),
            )?;
            
            // Update stored KEK
            let mut new_metadata = stored_kek.metadata.clone();
            new_metadata.attributes.insert(
                "last_rewrap".to_string(),
                Utc::now().to_rfc3339(),
            );
            new_metadata.attributes.insert(
                "wrapped_by_mk_version".to_string(),
                new_version.to_string(),
            );
            
            let updated_kek = StoredKey {
                metadata: new_metadata.clone(),
                encrypted_key: new_encrypted.ciphertext,
                nonce: new_encrypted.nonce,
            };
            
            // Delete old and store new
            self.storage.delete_key(&stored_kek.metadata.key_id)?;
            self.storage.store_key(updated_kek)?;
            rewrapped_count += 1;
        }
        
        // Deactivate old master key metadata
        if let Some(old_mk) = self.storage.get_key(&self.master_key_id)? {
            let mut old_metadata = old_mk.metadata;
            old_metadata.is_active = false;
            old_metadata.attributes.insert(
                "rotated_at".to_string(),
                Utc::now().to_rfc3339(),
            );
            self.storage.update_key_metadata(&self.master_key_id, old_metadata)?;
        }
        
        // Store new master key metadata
        let mut new_mk_metadata = KeyMetadata::new(KeyType::MasterKey);
        new_mk_metadata.key_id = new_master_key_id;
        new_mk_metadata.version = new_version;
        
        let new_stored_mk = StoredKey {
            metadata: new_mk_metadata,
            encrypted_key: vec![],
            nonce: vec![],
        };
        self.storage.store_key(new_stored_mk)?;
        
        // Update internal state
        let old_master_key_id = self.master_key_id;
        self.master_key = new_master_key;
        self.master_key_id = new_master_key_id;
        self.master_key_version = new_version;
        
        Ok(RotationResult {
            old_key_id: old_master_key_id,
            new_key_id: new_master_key_id,
            old_version,
            new_version,
            keys_rewrapped: rewrapped_count,
        })
    }

    /// Generate and store a new Key Encryption Key (KEK)
    pub fn generate_kek(&self) -> Result<Uuid> {
        let kek = SecureKey::generate();
        let kek_id = Uuid::new_v4();
        
        // Wrap KEK with master key
        let encrypted_kek = AesGcmCipher::encrypt(
            &self.master_key,
            kek.as_bytes(),
            Some(kek_id.as_bytes()), // AAD binds key to its ID
        )?;
        
        // Create and store KEK
        let mut metadata = KeyMetadata::new(KeyType::KeyEncryptionKey);
        metadata.key_id = kek_id;
        metadata.parent_key_id = Some(self.master_key_id);
        metadata.attributes.insert(
            "wrapped_by_mk_version".to_string(),
            self.master_key_version.to_string(),
        );
        
        let stored_kek = StoredKey {
            metadata,
            encrypted_key: encrypted_kek.ciphertext,
            nonce: encrypted_kek.nonce,
        };
        
        self.storage.store_key(stored_kek)?;
        
        Ok(kek_id)
    }

    /// Get and unwrap a KEK for use
    pub fn unwrap_kek(&self, kek_id: &Uuid) -> Result<SecureKey> {
        let stored_kek = self.storage.get_key(kek_id)?
            .ok_or_else(|| EnvelopeError::KeyNotFound(format!("KEK {}", kek_id)))?;
        
        if stored_kek.metadata.key_type != KeyType::KeyEncryptionKey {
            return Err(EnvelopeError::InvalidKeyState(
                format!("Key {} is not a KEK", kek_id)
            ));
        }
        
        let encrypted_kek = EncryptedData::new(
            stored_kek.nonce,
            stored_kek.encrypted_key,
        );
        
        let kek_bytes = AesGcmCipher::decrypt(
            &self.master_key,
            &encrypted_kek,
            Some(kek_id.as_bytes()),
        )?;
        
        Ok(SecureKey::new(kek_bytes))
    }

    /// Generate and store a new Data Encryption Key (DEK) for a specific data ID
    pub fn generate_dek(&self, kek_id: &Uuid, data_id: Option<Uuid>) -> Result<DekInfo> {
        // First, unwrap the KEK
        let kek = self.unwrap_kek(kek_id)?;
        
        // Generate new DEK
        let dek = SecureKey::generate();
        let dek_id = Uuid::new_v4();
        
        // Wrap DEK with KEK
        let encrypted_dek = AesGcmCipher::encrypt(
            &kek,
            dek.as_bytes(),
            Some(dek_id.as_bytes()),
        )?;
        
        // Create and store DEK metadata
        let mut metadata = KeyMetadata::new(KeyType::DataEncryptionKey);
        metadata.key_id = dek_id;
        metadata.parent_key_id = Some(*kek_id);
        metadata.data_id = data_id;
        
        let stored_dek = StoredKey {
            metadata,
            encrypted_key: encrypted_dek.ciphertext,
            nonce: encrypted_dek.nonce,
        };
        
        self.storage.store_key(stored_dek)?;
        
        Ok(DekInfo {
            dek_id,
            kek_id: *kek_id,
            data_id,
            dek, // Return the unwrapped DEK for immediate use
        })
    }

    /// Generate a DEK derived from master key using HKDF (deterministic)
    /// 
    /// This is useful for scenarios where you want consistent DEKs for
    /// specific data IDs without storing them.
    pub fn derive_dek(&self, data_id: &Uuid, purpose: &str) -> Result<SecureKey> {
        KeyDerivation::derive_key_for_data_id(&self.master_key, data_id, purpose)
    }

    /// Unwrap an existing DEK for use
    pub fn unwrap_dek(&self, dek_id: &Uuid) -> Result<SecureKey> {
        let stored_dek = self.storage.get_key(dek_id)?
            .ok_or_else(|| EnvelopeError::KeyNotFound(format!("DEK {}", dek_id)))?;
        
        if stored_dek.metadata.key_type != KeyType::DataEncryptionKey {
            return Err(EnvelopeError::InvalidKeyState(
                format!("Key {} is not a DEK", dek_id)
            ));
        }
        
        // Get the parent KEK
        let kek_id = stored_dek.metadata.parent_key_id
            .ok_or_else(|| EnvelopeError::InvalidKeyState("DEK has no parent KEK".into()))?;
        
        let kek = self.unwrap_kek(&kek_id)?;
        
        let encrypted_dek = EncryptedData::new(
            stored_dek.nonce,
            stored_dek.encrypted_key,
        );
        
        let dek_bytes = AesGcmCipher::decrypt(
            &kek,
            &encrypted_dek,
            Some(dek_id.as_bytes()),
        )?;
        
        Ok(SecureKey::new(dek_bytes))
    }

    /// Get DEK for a specific data ID
    pub fn get_dek_for_data(&self, data_id: &Uuid) -> Result<Option<DekInfo>> {
        if let Some(stored_dek) = self.storage.get_key_by_data_id(data_id)? {
            let dek = self.unwrap_dek(&stored_dek.metadata.key_id)?;
            let kek_id = stored_dek.metadata.parent_key_id
                .ok_or_else(|| EnvelopeError::InvalidKeyState("DEK has no parent KEK".into()))?;
            
            Ok(Some(DekInfo {
                dek_id: stored_dek.metadata.key_id,
                kek_id,
                data_id: Some(*data_id),
                dek,
            }))
        } else {
            Ok(None)
        }
    }

    /// Rotate a KEK and re-wrap all associated DEKs
    pub fn rotate_kek(&self, old_kek_id: &Uuid) -> Result<RotationResult> {
        // Unwrap old KEK
        let old_kek = self.unwrap_kek(old_kek_id)?;
        
        // Generate new KEK
        let new_kek = SecureKey::generate();
        let new_kek_id = Uuid::new_v4();
        
        // Get old KEK metadata
        let old_stored_kek = self.storage.get_key(old_kek_id)?
            .ok_or_else(|| EnvelopeError::KeyNotFound(format!("KEK {}", old_kek_id)))?;
        let old_version = old_stored_kek.metadata.version;
        let new_version = old_version + 1;
        
        // Re-wrap all DEKs under this KEK
        let all_keys = self.storage.list_key_ids()?;
        let mut rewrapped_count = 0;
        
        for key_id in all_keys {
            if let Some(stored_key) = self.storage.get_key(&key_id)? {
                if stored_key.metadata.key_type == KeyType::DataEncryptionKey 
                    && stored_key.metadata.parent_key_id == Some(*old_kek_id)
                    && stored_key.metadata.is_active
                {
                    // Unwrap DEK with old KEK
                    let encrypted_dek = EncryptedData::new(
                        stored_key.nonce.clone(),
                        stored_key.encrypted_key.clone(),
                    );
                    
                    let dek_bytes = AesGcmCipher::decrypt(
                        &old_kek,
                        &encrypted_dek,
                        Some(stored_key.metadata.key_id.as_bytes()),
                    )?;
                    
                    // Re-wrap DEK with new KEK
                    let new_encrypted = AesGcmCipher::encrypt(
                        &new_kek,
                        &dek_bytes,
                        Some(stored_key.metadata.key_id.as_bytes()),
                    )?;
                    
                    // Update stored DEK
                    let mut new_metadata = stored_key.metadata.clone();
                    new_metadata.parent_key_id = Some(new_kek_id);
                    new_metadata.attributes.insert(
                        "last_rewrap".to_string(),
                        Utc::now().to_rfc3339(),
                    );
                    
                    let updated_dek = StoredKey {
                        metadata: new_metadata.clone(),
                        encrypted_key: new_encrypted.ciphertext,
                        nonce: new_encrypted.nonce,
                    };
                    
                    self.storage.delete_key(&stored_key.metadata.key_id)?;
                    self.storage.store_key(updated_dek)?;
                    rewrapped_count += 1;
                }
            }
        }
        
        // Wrap new KEK with master key
        let encrypted_new_kek = AesGcmCipher::encrypt(
            &self.master_key,
            new_kek.as_bytes(),
            Some(new_kek_id.as_bytes()),
        )?;
        
        // Store new KEK
        let mut new_kek_metadata = KeyMetadata::new(KeyType::KeyEncryptionKey);
        new_kek_metadata.key_id = new_kek_id;
        new_kek_metadata.version = new_version;
        new_kek_metadata.parent_key_id = Some(self.master_key_id);
        new_kek_metadata.attributes.insert(
            "wrapped_by_mk_version".to_string(),
            self.master_key_version.to_string(),
        );
        new_kek_metadata.attributes.insert(
            "rotated_from".to_string(),
            old_kek_id.to_string(),
        );
        
        let new_stored_kek = StoredKey {
            metadata: new_kek_metadata,
            encrypted_key: encrypted_new_kek.ciphertext,
            nonce: encrypted_new_kek.nonce,
        };
        self.storage.store_key(new_stored_kek)?;
        
        // Deactivate old KEK
        let mut old_metadata = old_stored_kek.metadata;
        old_metadata.is_active = false;
        old_metadata.attributes.insert(
            "rotated_at".to_string(),
            Utc::now().to_rfc3339(),
        );
        old_metadata.attributes.insert(
            "rotated_to".to_string(),
            new_kek_id.to_string(),
        );
        self.storage.update_key_metadata(old_kek_id, old_metadata)?;
        
        Ok(RotationResult {
            old_key_id: *old_kek_id,
            new_key_id: new_kek_id,
            old_version,
            new_version,
            keys_rewrapped: rewrapped_count,
        })
    }

    /// Get statistics about the key hierarchy
    pub fn get_stats(&self) -> Result<KeyStats> {
        let all_keys = self.storage.list_key_ids()?;
        let mut mk_count = 0;
        let mut kek_count = 0;
        let mut dek_count = 0;
        let mut active_mk = 0;
        let mut active_kek = 0;
        let mut active_dek = 0;
        
        for key_id in all_keys {
            if let Some(stored) = self.storage.get_key(&key_id)? {
                match stored.metadata.key_type {
                    KeyType::MasterKey => {
                        mk_count += 1;
                        if stored.metadata.is_active { active_mk += 1; }
                    }
                    KeyType::KeyEncryptionKey => {
                        kek_count += 1;
                        if stored.metadata.is_active { active_kek += 1; }
                    }
                    KeyType::DataEncryptionKey => {
                        dek_count += 1;
                        if stored.metadata.is_active { active_dek += 1; }
                    }
                }
            }
        }
        
        Ok(KeyStats {
            total_master_keys: mk_count,
            active_master_keys: active_mk,
            total_keks: kek_count,
            active_keks: active_kek,
            total_deks: dek_count,
            active_deks: active_dek,
            current_mk_version: self.master_key_version,
        })
    }

    /// Export the current master key (for backup purposes)
    /// WARNING: Handle with extreme care in production!
    pub fn export_master_key(&self) -> Vec<u8> {
        self.master_key.as_bytes().to_vec()
    }
}

/// Information about a DEK
#[derive(Debug)]
pub struct DekInfo {
    /// DEK unique identifier
    pub dek_id: Uuid,
    /// Parent KEK identifier
    pub kek_id: Uuid,
    /// Associated data identifier
    pub data_id: Option<Uuid>,
    /// The unwrapped DEK (for immediate use)
    pub dek: SecureKey,
}

/// Result of a key rotation operation
#[derive(Debug)]
pub struct RotationResult {
    /// Old key ID
    pub old_key_id: Uuid,
    /// New key ID
    pub new_key_id: Uuid,
    /// Old version number
    pub old_version: u32,
    /// New version number
    pub new_version: u32,
    /// Number of child keys re-wrapped
    pub keys_rewrapped: usize,
}

impl std::fmt::Display for RotationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Rotation: {} (v{}) -> {} (v{}), {} keys re-wrapped",
            self.old_key_id, self.old_version,
            self.new_key_id, self.new_version,
            self.keys_rewrapped
        )
    }
}

/// Statistics about the key hierarchy
#[derive(Debug)]
pub struct KeyStats {
    pub total_master_keys: usize,
    pub active_master_keys: usize,
    pub total_keks: usize,
    pub active_keks: usize,
    pub total_deks: usize,
    pub active_deks: usize,
    pub current_mk_version: u32,
}

impl std::fmt::Display for KeyStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Key Hierarchy Statistics:")?;
        writeln!(f, "  Master Keys: {} total, {} active (current v{})", 
            self.total_master_keys, self.active_master_keys, self.current_mk_version)?;
        writeln!(f, "  KEKs: {} total, {} active", self.total_keks, self.active_keks)?;
        writeln!(f, "  DEKs: {} total, {} active", self.total_deks, self.active_deks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::AES_256_KEY_SIZE;
    use crate::storage::InMemoryStorage;

    #[test]
    fn test_key_manager_creation() {
        let storage = Arc::new(InMemoryStorage::new());
        let km = KeyManager::new(storage).unwrap();
        
        assert_eq!(km.master_key_version(), 1);
    }

    #[test]
    fn test_kek_generation() {
        let storage = Arc::new(InMemoryStorage::new());
        let km = KeyManager::new(storage).unwrap();
        
        let kek_id = km.generate_kek().unwrap();
        let unwrapped = km.unwrap_kek(&kek_id).unwrap();
        
        assert_eq!(unwrapped.len(), AES_256_KEY_SIZE);
    }

    #[test]
    fn test_dek_generation() {
        let storage = Arc::new(InMemoryStorage::new());
        let km = KeyManager::new(storage).unwrap();
        
        let kek_id = km.generate_kek().unwrap();
        let data_id = Uuid::new_v4();
        let dek_info = km.generate_dek(&kek_id, Some(data_id)).unwrap();
        
        assert_eq!(dek_info.kek_id, kek_id);
        assert_eq!(dek_info.data_id, Some(data_id));
        assert_eq!(dek_info.dek.len(), AES_256_KEY_SIZE);
    }

    #[test]
    fn test_master_key_rotation() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut km = KeyManager::new(storage).unwrap();
        
        // Create some KEKs
        let kek1 = km.generate_kek().unwrap();
        let kek2 = km.generate_kek().unwrap();
        
        // Rotate master key
        let result = km.rotate_master_key().unwrap();
        
        assert_eq!(result.old_version, 1);
        assert_eq!(result.new_version, 2);
        assert_eq!(result.keys_rewrapped, 2);
        
        // Verify KEKs still work
        let unwrapped1 = km.unwrap_kek(&kek1).unwrap();
        let unwrapped2 = km.unwrap_kek(&kek2).unwrap();
        
        assert_eq!(unwrapped1.len(), AES_256_KEY_SIZE);
        assert_eq!(unwrapped2.len(), AES_256_KEY_SIZE);
    }

    #[test]
    fn test_kek_rotation() {
        let storage = Arc::new(InMemoryStorage::new());
        let km = KeyManager::new(storage).unwrap();
        
        // Create KEK and DEKs
        let kek_id = km.generate_kek().unwrap();
        let dek1 = km.generate_dek(&kek_id, Some(Uuid::new_v4())).unwrap();
        let dek2 = km.generate_dek(&kek_id, Some(Uuid::new_v4())).unwrap();
        
        // Store original DEK values for comparison
        let original_dek1_bytes = dek1.dek.as_bytes().to_vec();
        let original_dek2_bytes = dek2.dek.as_bytes().to_vec();
        
        // Rotate KEK
        let result = km.rotate_kek(&kek_id).unwrap();
        
        assert_eq!(result.keys_rewrapped, 2);
        
        // Verify DEKs still produce same key material
        let unwrapped1 = km.unwrap_dek(&dek1.dek_id).unwrap();
        let unwrapped2 = km.unwrap_dek(&dek2.dek_id).unwrap();
        
        assert_eq!(unwrapped1.as_bytes(), &original_dek1_bytes);
        assert_eq!(unwrapped2.as_bytes(), &original_dek2_bytes);
    }
}

