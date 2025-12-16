use std::sync::Arc;
use uuid::Uuid;

use crate::crypto::{AesGcmCipher, EncryptedData, SecureKey};
use crate::error::{EnvelopeError, Result};
use crate::storage::{KeyMetadata, KeyStorage, KeyType, StoredKey};

/// Key Manager: KEK (root) → DEK (stored as EDEK)
pub struct KeyManager<S: KeyStorage> {
    storage: Arc<S>,
    kek: SecureKey,
    kek_id: Uuid,
    kek_version: u32,
}

impl<S: KeyStorage> KeyManager<S> {
    pub fn new(storage: Arc<S>) -> Result<Self> {
        let kek = SecureKey::generate();
        let kek_id = Uuid::new_v4();

        let metadata = KeyMetadata {
            key_id: kek_id,
            key_type: KeyType::KEK,
            version: 1,
            created_at: chrono::Utc::now(),
            is_active: true,
            parent_key_id: None,
            cid: None,
        };

        let stored_kek = StoredKey {
            metadata,
            encrypted_key: vec![], // KEK stored separately as EKEK on server
            nonce: vec![],
        };
        storage.store_key(stored_kek)?;

        Ok(Self { storage, kek, kek_id, kek_version: 1 })
    }

    pub fn with_kek(storage: Arc<S>, kek: SecureKey, kek_id: Uuid, version: u32) -> Self {
        Self { storage, kek, kek_id, kek_version: version }
    }

    pub fn kek_id(&self) -> Uuid {
        self.kek_id
    }

    pub fn kek_version(&self) -> u32 {
        self.kek_version
    }

    /// Rotate KEK and re-wrap all EDEKs
    pub fn rotate_kek(&mut self) -> Result<RotationResult> {
        let old_version = self.kek_version;
        let new_kek = SecureKey::generate();
        let new_kek_id = Uuid::new_v4();
        let new_version = old_version + 1;

        let deks = self.storage.get_keys_by_type(&KeyType::DEK)?;
        let mut rewrapped = 0;

        for stored_dek in deks {
            if !stored_dek.metadata.is_active {
                continue;
            }

            // Decrypt EDEK with old KEK
            let edek = EncryptedData::new(stored_dek.nonce.clone(), stored_dek.encrypted_key.clone());
            let dek_bytes = AesGcmCipher::decrypt(&self.kek, &edek, Some(stored_dek.metadata.key_id.as_bytes()))?;

            // Re-encrypt with new KEK
            let new_edek = AesGcmCipher::encrypt(&new_kek, &dek_bytes, Some(stored_dek.metadata.key_id.as_bytes()))?;

            let updated = StoredKey {
                metadata: stored_dek.metadata.clone(),
                encrypted_key: new_edek.ciphertext,
                nonce: new_edek.nonce,
            };

            self.storage.delete_key(&stored_dek.metadata.key_id)?;
            self.storage.store_key(updated)?;
            rewrapped += 1;
        }

        // Deactivate old KEK metadata
        if let Some(old_kek) = self.storage.get_key(&self.kek_id)? {
            let mut old_meta = old_kek.metadata;
            old_meta.is_active = false;
            self.storage.update_key_metadata(&self.kek_id, old_meta)?;
        }

        // Store new KEK metadata
        let new_meta = KeyMetadata {
            key_id: new_kek_id,
            key_type: KeyType::KEK,
            version: new_version,
            created_at: chrono::Utc::now(),
            is_active: true,
            parent_key_id: None,
            cid: None,
        };
        self.storage.store_key(StoredKey {
            metadata: new_meta,
            encrypted_key: vec![],
            nonce: vec![],
        })?;

        let old_kek_id = self.kek_id;
        self.kek = new_kek;
        self.kek_id = new_kek_id;
        self.kek_version = new_version;

        Ok(RotationResult {
            old_key_id: old_kek_id,
            new_key_id: new_kek_id,
            old_version,
            new_version,
            keys_rewrapped: rewrapped,
        })
    }

    /// Generate DEK and store as EDEK
    pub fn generate_dek(&self, cid: Option<Uuid>) -> Result<DekInfo> {
        let dek = SecureKey::generate();
        let dek_id = Uuid::new_v4();

        let edek = AesGcmCipher::encrypt(&self.kek, dek.as_bytes(), Some(dek_id.as_bytes()))?;

        let metadata = KeyMetadata {
            key_id: dek_id,
            key_type: KeyType::DEK,
            version: 1,
            created_at: chrono::Utc::now(),
            is_active: true,
            parent_key_id: Some(self.kek_id),
            cid,
        };

        self.storage.store_key(StoredKey {
            metadata,
            encrypted_key: edek.ciphertext,
            nonce: edek.nonce,
        })?;

        Ok(DekInfo { dek_id, kek_id: self.kek_id, cid, dek })
    }

    /// Unwrap EDEK to get DEK
    pub fn unwrap_dek(&self, dek_id: &Uuid) -> Result<SecureKey> {
        let stored = self.storage.get_key(dek_id)?
            .ok_or_else(|| EnvelopeError::KeyNotFound(format!("DEK {}", dek_id)))?;

        if stored.metadata.key_type != KeyType::DEK {
            return Err(EnvelopeError::InvalidKeyState(format!("{} is not a DEK", dek_id)));
        }

        let edek = EncryptedData::new(stored.nonce, stored.encrypted_key);
        let dek_bytes = AesGcmCipher::decrypt(&self.kek, &edek, Some(dek_id.as_bytes()))?;

        Ok(SecureKey::new(dek_bytes))
    }

    /// Get DEK for a CID
    pub fn get_dek_for_cid(&self, cid: &Uuid) -> Result<Option<DekInfo>> {
        if let Some(stored) = self.storage.get_key_by_cid(cid)? {
            let dek = self.unwrap_dek(&stored.metadata.key_id)?;
            Ok(Some(DekInfo {
                dek_id: stored.metadata.key_id,
                kek_id: self.kek_id,
                cid: Some(*cid),
                dek,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn get_stats(&self) -> Result<KeyStats> {
        let keys = self.storage.list_key_ids()?;
        let mut stats = KeyStats { total_keks: 0, active_keks: 0, total_deks: 0, active_deks: 0, kek_version: self.kek_version };

        for id in keys {
            if let Some(k) = self.storage.get_key(&id)? {
                match k.metadata.key_type {
                    KeyType::KEK => {
                        stats.total_keks += 1;
                        if k.metadata.is_active { stats.active_keks += 1; }
                    }
                    KeyType::DEK => {
                        stats.total_deks += 1;
                        if k.metadata.is_active { stats.active_deks += 1; }
                    }
                }
            }
        }
        Ok(stats)
    }

    /// Export KEK bytes (to be encrypted as EKEK for server storage)
    pub fn export_kek(&self) -> Vec<u8> {
        self.kek.as_bytes().to_vec()
    }
}

#[derive(Debug)]
pub struct DekInfo {
    pub dek_id: Uuid,
    pub kek_id: Uuid,
    pub cid: Option<Uuid>,
    pub dek: SecureKey,
}

#[derive(Debug)]
pub struct RotationResult {
    pub old_key_id: Uuid,
    pub new_key_id: Uuid,
    pub old_version: u32,
    pub new_version: u32,
    pub keys_rewrapped: usize,
}

impl std::fmt::Display for RotationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{} -> v{}, {} DEKs re-wrapped", self.old_version, self.new_version, self.keys_rewrapped)
    }
}

#[derive(Debug)]
pub struct KeyStats {
    pub total_keks: usize,
    pub active_keks: usize,
    pub total_deks: usize,
    pub active_deks: usize,
    pub kek_version: u32,
}
