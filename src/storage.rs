use std::collections::HashMap;
use parking_lot::RwLock;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{EnvelopeError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub key_id: Uuid,
    pub key_type: KeyType,
    pub version: u32,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
    pub parent_key_id: Option<Uuid>,
    pub cid: Option<Uuid>,
}

impl KeyMetadata {
    pub fn new(key_type: KeyType) -> Self {
        Self {
            key_id: Uuid::new_v4(),
            key_type,
            version: 1,
            created_at: Utc::now(),
            is_active: true,
            parent_key_id: None,
            cid: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum KeyType {
    KEK,
    DEK,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::KEK => write!(f, "KEK"),
            KeyType::DEK => write!(f, "DEK"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKey {
    pub metadata: KeyMetadata,
    pub encrypted_key: Vec<u8>, // EKEK or EDEK
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedRecord {
    pub cid: Uuid,
    pub dek_id: Uuid,
    pub encrypted_data: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

pub trait KeyStorage: Send + Sync {
    fn store_key(&self, key: StoredKey) -> Result<()>;
    fn get_key(&self, key_id: &Uuid) -> Result<Option<StoredKey>>;
    fn get_keys_by_type(&self, key_type: &KeyType) -> Result<Vec<StoredKey>>;
    fn get_key_by_cid(&self, cid: &Uuid) -> Result<Option<StoredKey>>;
    fn update_key_metadata(&self, key_id: &Uuid, metadata: KeyMetadata) -> Result<()>;
    fn delete_key(&self, key_id: &Uuid) -> Result<()>;
    fn list_key_ids(&self) -> Result<Vec<Uuid>>;
    fn store_record(&self, record: EncryptedRecord) -> Result<()>;
    fn get_record(&self, cid: &Uuid) -> Result<Option<EncryptedRecord>>;
    fn delete_record(&self, cid: &Uuid) -> Result<()>;
}

pub struct InMemoryStorage {
    keys: RwLock<HashMap<Uuid, StoredKey>>,
    records: RwLock<HashMap<Uuid, EncryptedRecord>>,
}

impl InMemoryStorage {
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
    fn store_key(&self, key: StoredKey) -> Result<()> {
        self.keys.write().insert(key.metadata.key_id, key);
        Ok(())
    }

    fn get_key(&self, key_id: &Uuid) -> Result<Option<StoredKey>> {
        Ok(self.keys.read().get(key_id).cloned())
    }

    fn get_keys_by_type(&self, key_type: &KeyType) -> Result<Vec<StoredKey>> {
        Ok(self.keys.read()
            .values()
            .filter(|k| &k.metadata.key_type == key_type)
            .cloned()
            .collect())
    }

    fn get_key_by_cid(&self, cid: &Uuid) -> Result<Option<StoredKey>> {
        Ok(self.keys.read()
            .values()
            .find(|k| k.metadata.cid.as_ref() == Some(cid) && k.metadata.is_active)
            .cloned())
    }

    fn update_key_metadata(&self, key_id: &Uuid, metadata: KeyMetadata) -> Result<()> {
        let mut keys = self.keys.write();
        if let Some(key) = keys.get_mut(key_id) {
            key.metadata = metadata;
            Ok(())
        } else {
            Err(EnvelopeError::KeyNotFound(key_id.to_string()))
        }
    }

    fn delete_key(&self, key_id: &Uuid) -> Result<()> {
        self.keys.write().remove(key_id);
        Ok(())
    }

    fn list_key_ids(&self) -> Result<Vec<Uuid>> {
        Ok(self.keys.read().keys().cloned().collect())
    }

    fn store_record(&self, record: EncryptedRecord) -> Result<()> {
        self.records.write().insert(record.cid, record);
        Ok(())
    }

    fn get_record(&self, cid: &Uuid) -> Result<Option<EncryptedRecord>> {
        Ok(self.records.read().get(cid).cloned())
    }

    fn delete_record(&self, cid: &Uuid) -> Result<()> {
        self.records.write().remove(cid);
        Ok(())
    }
}
