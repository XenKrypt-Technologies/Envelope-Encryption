use std::sync::Arc;
use uuid::Uuid;

use crate::crypto::{AesGcmCipher, EncryptedData, SecureKey};
use crate::error::{EnvelopeError, Result};
use crate::storage::{KeyMetadata, KeyStorage, KeyType, StoredKey};

/// New Architecture:
/// - ServerKey: Each server has its own key for DB and system security
/// - KEK: Per-user Key Encryption Key (one per user_id)
/// - DEK: One-time Data Encryption Key (generated per encryption operation)
///
/// Hierarchy: ServerKey -> EKEK (encrypted KEK) -> EDEK (encrypted DEK) -> Encrypted Data
pub struct KeyManager<S: KeyStorage> {
    storage: Arc<S>,
    server_key: SecureKey,
    server_key_id: Uuid,
    server_key_version: u32,
}

impl<S: KeyStorage> KeyManager<S> {
    /// Create new KeyManager with a fresh server key
    pub fn new(storage: Arc<S>) -> Result<Self> {
        let server_key = SecureKey::generate();
        let server_key_id = Uuid::new_v4();

        let metadata = KeyMetadata {
            key_id: server_key_id,
            key_type: KeyType::ServerKey,
            version: 1,
            created_at: chrono::Utc::now(),
            is_active: true,
            parent_key_id: None,
            user_id: None,
            cid: None,
        };

        let stored_server_key = StoredKey {
            metadata,
            encrypted_key: vec![], // ServerKey stored securely (HSM/KMS in production)
            nonce: vec![],
        };
        storage.store_key(stored_server_key)?;

        Ok(Self {
            storage,
            server_key,
            server_key_id,
            server_key_version: 1,
        })
    }

    /// Initialize with existing server key
    pub fn with_server_key(
        storage: Arc<S>,
        server_key: SecureKey,
        server_key_id: Uuid,
        version: u32,
    ) -> Self {
        Self {
            storage,
            server_key,
            server_key_id,
            server_key_version: version,
        }
    }

    pub fn server_key_id(&self) -> Uuid {
        self.server_key_id
    }

    pub fn server_key_version(&self) -> u32 {
        self.server_key_version
    }

    /// Generate or get KEK for a user
    /// Each user has their own KEK, encrypted by the server key
    pub fn get_or_create_user_kek(&self, user_id: &Uuid) -> Result<UserKekInfo> {
        // Try to get existing KEK for this user
        if let Some(stored_kek) = self.storage.get_kek_by_user_id(user_id)? {
            // Decrypt EKEK to get KEK
            let ekek = EncryptedData::new(stored_kek.nonce.clone(), stored_kek.encrypted_key.clone());
            let kek_bytes = AesGcmCipher::decrypt(
                &self.server_key,
                &ekek,
                Some(user_id.as_bytes()),
            )?;
            let kek = SecureKey::new(kek_bytes);

            return Ok(UserKekInfo {
                kek_id: stored_kek.metadata.key_id,
                kek_version: stored_kek.metadata.version,
                user_id: *user_id,
                kek,
            });
        }

        // Create new KEK for this user
        let kek = SecureKey::generate();
        let kek_id = Uuid::new_v4();

        // Encrypt KEK with server key (using user_id as AAD)
        let ekek = AesGcmCipher::encrypt(&self.server_key, kek.as_bytes(), Some(user_id.as_bytes()))?;

        let metadata = KeyMetadata {
            key_id: kek_id,
            key_type: KeyType::KEK,
            version: 1,
            created_at: chrono::Utc::now(),
            is_active: true,
            parent_key_id: Some(self.server_key_id),
            user_id: Some(*user_id),
            cid: None,
        };

        self.storage.store_key(StoredKey {
            metadata,
            encrypted_key: ekek.ciphertext,
            nonce: ekek.nonce,
        })?;

        Ok(UserKekInfo {
            kek_id,
            kek_version: 1,
            user_id: *user_id,
            kek,
        })
    }

    /// Generate a one-time DEK for encrypting data
    /// DEK is encrypted by the user's KEK and returned (not permanently stored beyond EDEK)
    pub fn generate_dek(&self, user_id: &Uuid, cid: Option<Uuid>) -> Result<DekInfo> {
        let user_kek = self.get_or_create_user_kek(user_id)?;

        // Generate one-time DEK
        let dek = SecureKey::generate();
        let dek_id = Uuid::new_v4();

        // Encrypt DEK with user's KEK (using dek_id as AAD for binding)
        let edek = AesGcmCipher::encrypt(&user_kek.kek, dek.as_bytes(), Some(dek_id.as_bytes()))?;

        let metadata = KeyMetadata {
            key_id: dek_id,
            key_type: KeyType::DEK,
            version: 1,
            created_at: chrono::Utc::now(),
            is_active: true,
            parent_key_id: Some(user_kek.kek_id),
            user_id: Some(*user_id),
            cid,
        };

        // Store EDEK for later decryption
        self.storage.store_key(StoredKey {
            metadata,
            encrypted_key: edek.ciphertext.clone(),
            nonce: edek.nonce.clone(),
        })?;

        Ok(DekInfo {
            dek_id,
            kek_id: user_kek.kek_id,
            user_id: *user_id,
            cid,
            dek,
            edek_nonce: edek.nonce,
            edek_ciphertext: edek.ciphertext,
        })
    }

    /// Unwrap EDEK to get DEK
    /// Input: user_id, EDEK (encrypted_key + nonce), outputs DEK
    pub fn unwrap_dek(&self, dek_id: &Uuid) -> Result<SecureKey> {
        let stored_dek = self
            .storage
            .get_key(dek_id)?
            .ok_or_else(|| EnvelopeError::KeyNotFound(format!("DEK {}", dek_id)))?;

        if stored_dek.metadata.key_type != KeyType::DEK {
            return Err(EnvelopeError::InvalidKeyState(format!(
                "{} is not a DEK",
                dek_id
            )));
        }

        let user_id = stored_dek
            .metadata
            .user_id
            .ok_or_else(|| EnvelopeError::InvalidKeyState("DEK has no user_id".into()))?;

        // Get user's KEK
        let user_kek = self.get_or_create_user_kek(&user_id)?;

        // Decrypt EDEK to get DEK
        let edek = EncryptedData::new(stored_dek.nonce, stored_dek.encrypted_key);
        let dek_bytes = AesGcmCipher::decrypt(&user_kek.kek, &edek, Some(dek_id.as_bytes()))?;

        Ok(SecureKey::new(dek_bytes))
    }

    /// Rotate server key and re-wrap all KEKs
    pub fn rotate_server_key(&mut self) -> Result<RotationResult> {
        let old_version = self.server_key_version;
        let new_server_key = SecureKey::generate();
        let new_server_key_id = Uuid::new_v4();
        let new_version = old_version + 1;

        // Get all KEKs
        let keks = self.storage.get_keys_by_type(&KeyType::KEK)?;
        let mut rewrapped = 0;

        for stored_kek in keks {
            if !stored_kek.metadata.is_active {
                continue;
            }

            let user_id = stored_kek
                .metadata
                .user_id
                .ok_or_else(|| EnvelopeError::InvalidKeyState("KEK has no user_id".into()))?;

            // Decrypt EKEK with old server key
            let ekek = EncryptedData::new(stored_kek.nonce.clone(), stored_kek.encrypted_key.clone());
            let kek_bytes = AesGcmCipher::decrypt(&self.server_key, &ekek, Some(user_id.as_bytes()))?;

            // Re-encrypt with new server key
            let new_ekek = AesGcmCipher::encrypt(&new_server_key, &kek_bytes, Some(user_id.as_bytes()))?;

            let updated = StoredKey {
                metadata: stored_kek.metadata.clone(),
                encrypted_key: new_ekek.ciphertext,
                nonce: new_ekek.nonce,
            };

            self.storage.delete_key(&stored_kek.metadata.key_id)?;
            self.storage.store_key(updated)?;
            rewrapped += 1;
        }

        // Deactivate old server key metadata
        if let Some(old_sk) = self.storage.get_key(&self.server_key_id)? {
            let mut old_meta = old_sk.metadata;
            old_meta.is_active = false;
            self.storage.update_key_metadata(&self.server_key_id, old_meta)?;
        }

        // Store new server key metadata
        let new_meta = KeyMetadata {
            key_id: new_server_key_id,
            key_type: KeyType::ServerKey,
            version: new_version,
            created_at: chrono::Utc::now(),
            is_active: true,
            parent_key_id: None,
            user_id: None,
            cid: None,
        };
        self.storage.store_key(StoredKey {
            metadata: new_meta,
            encrypted_key: vec![],
            nonce: vec![],
        })?;

        let old_server_key_id = self.server_key_id;
        self.server_key = new_server_key;
        self.server_key_id = new_server_key_id;
        self.server_key_version = new_version;

        Ok(RotationResult {
            old_key_id: old_server_key_id,
            new_key_id: new_server_key_id,
            old_version,
            new_version,
            keys_rewrapped: rewrapped,
        })
    }

    /// Rotate a specific user's KEK and re-wrap all their DEKs
    pub fn rotate_user_kek(&self, user_id: &Uuid) -> Result<RotationResult> {
        // Get old KEK
        let old_kek_stored = self
            .storage
            .get_kek_by_user_id(user_id)?
            .ok_or_else(|| EnvelopeError::KeyNotFound(format!("KEK for user {}", user_id)))?;

        let old_version = old_kek_stored.metadata.version;
        let old_kek_id = old_kek_stored.metadata.key_id;

        // Decrypt old KEK
        let old_ekek = EncryptedData::new(old_kek_stored.nonce, old_kek_stored.encrypted_key);
        let old_kek_bytes = AesGcmCipher::decrypt(&self.server_key, &old_ekek, Some(user_id.as_bytes()))?;
        let old_kek = SecureKey::new(old_kek_bytes);

        // Generate new KEK
        let new_kek = SecureKey::generate();
        let new_kek_id = Uuid::new_v4();
        let new_version = old_version + 1;

        // Get all DEKs for this user
        let all_deks = self.storage.get_keys_by_type(&KeyType::DEK)?;
        let user_deks: Vec<_> = all_deks
            .into_iter()
            .filter(|d| d.metadata.user_id.as_ref() == Some(user_id) && d.metadata.is_active)
            .collect();

        let mut rewrapped = 0;

        for stored_dek in user_deks {
            // Decrypt EDEK with old KEK
            let edek = EncryptedData::new(stored_dek.nonce.clone(), stored_dek.encrypted_key.clone());
            let dek_bytes = AesGcmCipher::decrypt(&old_kek, &edek, Some(stored_dek.metadata.key_id.as_bytes()))?;

            // Re-encrypt with new KEK
            let new_edek = AesGcmCipher::encrypt(&new_kek, &dek_bytes, Some(stored_dek.metadata.key_id.as_bytes()))?;

            let mut updated_meta = stored_dek.metadata.clone();
            updated_meta.parent_key_id = Some(new_kek_id);

            let updated = StoredKey {
                metadata: updated_meta,
                encrypted_key: new_edek.ciphertext,
                nonce: new_edek.nonce,
            };

            self.storage.delete_key(&stored_dek.metadata.key_id)?;
            self.storage.store_key(updated)?;
            rewrapped += 1;
        }

        // Deactivate old KEK
        let mut old_meta = old_kek_stored.metadata;
        old_meta.is_active = false;
        self.storage.update_key_metadata(&old_kek_id, old_meta)?;

        // Encrypt new KEK with server key
        let new_ekek = AesGcmCipher::encrypt(&self.server_key, new_kek.as_bytes(), Some(user_id.as_bytes()))?;

        // Store new KEK
        let new_meta = KeyMetadata {
            key_id: new_kek_id,
            key_type: KeyType::KEK,
            version: new_version,
            created_at: chrono::Utc::now(),
            is_active: true,
            parent_key_id: Some(self.server_key_id),
            user_id: Some(*user_id),
            cid: None,
        };
        self.storage.store_key(StoredKey {
            metadata: new_meta,
            encrypted_key: new_ekek.ciphertext,
            nonce: new_ekek.nonce,
        })?;

        Ok(RotationResult {
            old_key_id: old_kek_id,
            new_key_id: new_kek_id,
            old_version,
            new_version,
            keys_rewrapped: rewrapped,
        })
    }

    pub fn get_stats(&self) -> Result<KeyStats> {
        let keys = self.storage.list_key_ids()?;
        let mut stats = KeyStats {
            total_server_keys: 0,
            active_server_keys: 0,
            total_keks: 0,
            active_keks: 0,
            total_deks: 0,
            active_deks: 0,
            server_key_version: self.server_key_version,
        };

        for id in keys {
            if let Some(k) = self.storage.get_key(&id)? {
                match k.metadata.key_type {
                    KeyType::ServerKey => {
                        stats.total_server_keys += 1;
                        if k.metadata.is_active {
                            stats.active_server_keys += 1;
                        }
                    }
                    KeyType::KEK => {
                        stats.total_keks += 1;
                        if k.metadata.is_active {
                            stats.active_keks += 1;
                        }
                    }
                    KeyType::DEK => {
                        stats.total_deks += 1;
                        if k.metadata.is_active {
                            stats.active_deks += 1;
                        }
                    }
                }
            }
        }
        Ok(stats)
    }

    /// Export server key bytes (to be stored securely in HSM/KMS in production)
    pub fn export_server_key(&self) -> Vec<u8> {
        self.server_key.as_bytes().to_vec()
    }
}

#[derive(Debug)]
pub struct UserKekInfo {
    pub kek_id: Uuid,
    pub kek_version: u32,
    pub user_id: Uuid,
    pub kek: SecureKey,
}

#[derive(Debug)]
pub struct DekInfo {
    pub dek_id: Uuid,
    pub kek_id: Uuid,
    pub user_id: Uuid,
    pub cid: Option<Uuid>,
    pub dek: SecureKey,
    pub edek_nonce: Vec<u8>,
    pub edek_ciphertext: Vec<u8>,
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
        write!(
            f,
            "v{} -> v{}, {} keys re-wrapped",
            self.old_version, self.new_version, self.keys_rewrapped
        )
    }
}

#[derive(Debug)]
pub struct KeyStats {
    pub total_server_keys: usize,
    pub active_server_keys: usize,
    pub total_keks: usize,
    pub active_keks: usize,
    pub total_deks: usize,
    pub active_deks: usize,
    pub server_key_version: u32,
}
