//! Storage abstraction for key management
//! 
//! This module provides a trait-based storage interface that can be
//! implemented for various backends (in-memory, PostgreSQL, etc.)

use std::collections::HashMap;
use parking_lot::RwLock;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{EnvelopeError, Result};

/// Metadata associated with stored keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Unique identifier for the key
    pub key_id: Uuid,
    /// Type of key (MK, KEK, DEK)
    pub key_type: KeyType,
    /// Version number (for key rotation)
    pub version: u32,
    /// When the key was created
    pub created_at: DateTime<Utc>,
    /// When the key expires (if applicable)
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether this key is currently active
    pub is_active: bool,
    /// Parent key ID (for key hierarchy)
    pub parent_key_id: Option<Uuid>,
    /// Associated data ID (for DEKs)
    pub data_id: Option<Uuid>,
    /// Custom attributes
    pub attributes: HashMap<String, String>,
}

impl KeyMetadata {
    /// Create new key metadata
    pub fn new(key_type: KeyType) -> Self {
        Self {
            key_id: Uuid::new_v4(),
            key_type,
            version: 1,
            created_at: Utc::now(),
            expires_at: None,
            is_active: true,
            parent_key_id: None,
            data_id: None,
            attributes: HashMap::new(),
        }
    }

    /// Create metadata for a new version (rotation)
    pub fn new_version(&self) -> Self {
        Self {
            key_id: Uuid::new_v4(),
            key_type: self.key_type.clone(),
            version: self.version + 1,
            created_at: Utc::now(),
            expires_at: None,
            is_active: true,
            parent_key_id: self.parent_key_id,
            data_id: self.data_id,
            attributes: self.attributes.clone(),
        }
    }
}

/// Type of cryptographic key
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum KeyType {
    /// Master Key - root of the key hierarchy
    MasterKey,
    /// Key Encryption Key - wraps DEKs
    KeyEncryptionKey,
    /// Data Encryption Key - encrypts actual data
    DataEncryptionKey,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::MasterKey => write!(f, "MK"),
            KeyType::KeyEncryptionKey => write!(f, "KEK"),
            KeyType::DataEncryptionKey => write!(f, "DEK"),
        }
    }
}

/// Stored key entry combining encrypted key material and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKey {
    /// Key metadata
    pub metadata: KeyMetadata,
    /// Encrypted key material (wrapped by parent key)
    /// For Master Keys, this might be the raw key or HSM-protected
    pub encrypted_key: Vec<u8>,
    /// Nonce used for encryption
    pub nonce: Vec<u8>,
}

/// Encrypted data record for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedRecord {
    /// Unique identifier for this record
    pub record_id: Uuid,
    /// The DEK key ID used to encrypt this record
    pub dek_id: Uuid,
    /// DEK version at time of encryption
    pub dek_version: u32,
    /// Encrypted data (nonce + ciphertext)
    pub encrypted_data: Vec<u8>,
    /// Nonce for the data encryption
    pub nonce: Vec<u8>,
    /// When the record was created
    pub created_at: DateTime<Utc>,
    /// Custom metadata
    pub metadata: HashMap<String, String>,
}

/// Storage trait for key management backend
pub trait KeyStorage: Send + Sync {
    /// Store a key
    fn store_key(&self, stored_key: StoredKey) -> Result<()>;

    /// Retrieve a key by ID
    fn get_key(&self, key_id: &Uuid) -> Result<Option<StoredKey>>;

    /// Get the latest active key of a specific type
    fn get_active_key(&self, key_type: &KeyType) -> Result<Option<StoredKey>>;

    /// Get all keys of a specific type
    fn get_keys_by_type(&self, key_type: &KeyType) -> Result<Vec<StoredKey>>;

    /// Get key by data ID (for DEKs)
    fn get_key_by_data_id(&self, data_id: &Uuid) -> Result<Option<StoredKey>>;

    /// Update key metadata (e.g., deactivate old keys)
    fn update_key_metadata(&self, key_id: &Uuid, metadata: KeyMetadata) -> Result<()>;

    /// Delete a key (use with caution!)
    fn delete_key(&self, key_id: &Uuid) -> Result<()>;

    /// List all key IDs
    fn list_key_ids(&self) -> Result<Vec<Uuid>>;

    /// Store encrypted data record
    fn store_record(&self, record: EncryptedRecord) -> Result<()>;

    /// Get encrypted data record
    fn get_record(&self, record_id: &Uuid) -> Result<Option<EncryptedRecord>>;

    /// Delete encrypted data record
    fn delete_record(&self, record_id: &Uuid) -> Result<()>;

    /// Get all records encrypted with a specific DEK
    fn get_records_by_dek(&self, dek_id: &Uuid) -> Result<Vec<EncryptedRecord>>;
}

/// In-memory implementation of KeyStorage
/// 
/// Suitable for development, testing, and single-instance deployments.
/// Data is lost when the process terminates.
pub struct InMemoryStorage {
    keys: RwLock<HashMap<Uuid, StoredKey>>,
    records: RwLock<HashMap<Uuid, EncryptedRecord>>,
}

impl InMemoryStorage {
    /// Create a new in-memory storage instance
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            records: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStorage for InMemoryStorage {
    fn store_key(&self, stored_key: StoredKey) -> Result<()> {
        let mut keys = self.keys.write();
        keys.insert(stored_key.metadata.key_id, stored_key);
        Ok(())
    }

    fn get_key(&self, key_id: &Uuid) -> Result<Option<StoredKey>> {
        let keys = self.keys.read();
        Ok(keys.get(key_id).cloned())
    }

    fn get_active_key(&self, key_type: &KeyType) -> Result<Option<StoredKey>> {
        let keys = self.keys.read();
        let active_key = keys
            .values()
            .filter(|k| &k.metadata.key_type == key_type && k.metadata.is_active)
            .max_by_key(|k| k.metadata.version)
            .cloned();
        Ok(active_key)
    }

    fn get_keys_by_type(&self, key_type: &KeyType) -> Result<Vec<StoredKey>> {
        let keys = self.keys.read();
        let filtered: Vec<_> = keys
            .values()
            .filter(|k| &k.metadata.key_type == key_type)
            .cloned()
            .collect();
        Ok(filtered)
    }

    fn get_key_by_data_id(&self, data_id: &Uuid) -> Result<Option<StoredKey>> {
        let keys = self.keys.read();
        let key = keys
            .values()
            .find(|k| k.metadata.data_id.as_ref() == Some(data_id) && k.metadata.is_active)
            .cloned();
        Ok(key)
    }

    fn update_key_metadata(&self, key_id: &Uuid, metadata: KeyMetadata) -> Result<()> {
        let mut keys = self.keys.write();
        if let Some(stored_key) = keys.get_mut(key_id) {
            stored_key.metadata = metadata;
            Ok(())
        } else {
            Err(EnvelopeError::KeyNotFound(key_id.to_string()))
        }
    }

    fn delete_key(&self, key_id: &Uuid) -> Result<()> {
        let mut keys = self.keys.write();
        keys.remove(key_id);
        Ok(())
    }

    fn list_key_ids(&self) -> Result<Vec<Uuid>> {
        let keys = self.keys.read();
        Ok(keys.keys().cloned().collect())
    }

    fn store_record(&self, record: EncryptedRecord) -> Result<()> {
        let mut records = self.records.write();
        records.insert(record.record_id, record);
        Ok(())
    }

    fn get_record(&self, record_id: &Uuid) -> Result<Option<EncryptedRecord>> {
        let records = self.records.read();
        Ok(records.get(record_id).cloned())
    }

    fn delete_record(&self, record_id: &Uuid) -> Result<()> {
        let mut records = self.records.write();
        records.remove(record_id);
        Ok(())
    }

    fn get_records_by_dek(&self, dek_id: &Uuid) -> Result<Vec<EncryptedRecord>> {
        let records = self.records.read();
        let filtered: Vec<_> = records
            .values()
            .filter(|r| &r.dek_id == dek_id)
            .cloned()
            .collect();
        Ok(filtered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_storage() {
        let storage = InMemoryStorage::new();
        
        let mut metadata = KeyMetadata::new(KeyType::MasterKey);
        metadata.key_id = Uuid::new_v4();
        
        let stored_key = StoredKey {
            metadata: metadata.clone(),
            encrypted_key: vec![1, 2, 3, 4],
            nonce: vec![5, 6, 7, 8],
        };
        
        storage.store_key(stored_key.clone()).unwrap();
        
        let retrieved = storage.get_key(&metadata.key_id).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().metadata.key_id, metadata.key_id);
    }

    #[test]
    fn test_get_active_key() {
        let storage = InMemoryStorage::new();
        
        // Store two versions of a key
        let mut meta1 = KeyMetadata::new(KeyType::KeyEncryptionKey);
        meta1.version = 1;
        meta1.is_active = false;
        
        let mut meta2 = KeyMetadata::new(KeyType::KeyEncryptionKey);
        meta2.version = 2;
        meta2.is_active = true;
        
        storage.store_key(StoredKey {
            metadata: meta1,
            encrypted_key: vec![1],
            nonce: vec![1],
        }).unwrap();
        
        storage.store_key(StoredKey {
            metadata: meta2.clone(),
            encrypted_key: vec![2],
            nonce: vec![2],
        }).unwrap();
        
        let active = storage.get_active_key(&KeyType::KeyEncryptionKey).unwrap();
        assert!(active.is_some());
        assert_eq!(active.unwrap().metadata.version, 2);
    }
}


