use uuid::Uuid;
use chrono::Utc;
use base64::{engine::general_purpose::STANDARD, Engine};

use crate::crypto::{AesGcmCipher, EncryptedData, SecureKey};
use crate::error::{EnvelopeError, Result};
use crate::postgres_storage::{PostgresStorage, StoredKek, StoredDek};

/// Production-grade envelope encryption service with PostgreSQL backend
/// Strict requirements:
/// - AES-256-GCM only
/// - No HKDF or KDFs
/// - Server Key loaded from .env as hardcoded 32-byte base64 value
/// - Each user has their own KEK
/// - KEKs encrypted by Server Key (EKEK) stored in PostgreSQL
/// - DEKs encrypted by user KEKs (EDEK) stored in PostgreSQL
/// - Explicit version tracking for KEKs and DEKs
/// - Fresh random nonce for each encryption
pub struct PostgresEnvelopeService {
    storage: PostgresStorage,
    server_key: SecureKey,
    server_key_version: i32,
}

impl PostgresEnvelopeService {
    /// Initialize service with Server Key from environment
    pub async fn new(storage: PostgresStorage) -> Result<Self> {
        // Load Server Key from environment (must be exactly 32 bytes base64)
        let server_key_b64 = std::env::var("SERVER_KEY_BASE64")
            .map_err(|_| EnvelopeError::Config("SERVER_KEY_BASE64 not set in .env".into()))?;

        let server_key_bytes = STANDARD
            .decode(&server_key_b64)
            .map_err(|e| EnvelopeError::Config(format!("Invalid SERVER_KEY_BASE64: {}", e)))?;

        if server_key_bytes.len() != 32 {
            return Err(EnvelopeError::Config(format!(
                "SERVER_KEY_BASE64 must decode to exactly 32 bytes, got {}",
                server_key_bytes.len()
            )));
        }

        let server_key = SecureKey::new(server_key_bytes);

        // Get server key version from environment or database
        let server_key_version = std::env::var("SERVER_KEY_VERSION")
            .ok()
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or_else(|| 1);

        // Verify server key version matches database
        let db_version = storage.get_active_server_key_version().await?;
        if server_key_version != db_version {
            return Err(EnvelopeError::Config(format!(
                "SERVER_KEY_VERSION mismatch: env={}, db={}",
                server_key_version, db_version
            )));
        }

        Ok(Self {
            storage,
            server_key,
            server_key_version,
        })
    }

    /// API: generate_dek(user_id) -> (dek, edek, nonce, tag, kek_version)
    ///
    /// Crypto flow:
    /// 1. Fetch ACTIVE KEK for user
    ///    - If no KEK exists, create one
    /// 2. Decrypt EKEK using Server Key (AAD = user_id)
    /// 3. Generate fresh DEK (random 32 bytes)
    /// 4. Encrypt DEK using KEK with AES-GCM (AAD = dek_id)
    /// 5. Store EDEK in PostgreSQL
    /// 6. Return (dek, edek_ciphertext, edek_nonce, tag, kek_version)
    pub async fn generate_dek(&self, user_id: &Uuid) -> Result<GeneratedDek> {
        // Step 1: Get or create user's KEK
        let kek_info = self.get_or_create_user_kek(user_id).await?;

        // Step 2: Generate fresh DEK (random 32 bytes)
        let dek = SecureKey::generate();
        let dek_id = Uuid::new_v4();

        // Step 3: Encrypt DEK with user's KEK (AAD = dek_id for binding)
        let edek = AesGcmCipher::encrypt(&kek_info.kek, dek.as_bytes(), Some(dek_id.as_bytes()))?;

        // Extract tag (last 16 bytes of ciphertext)
        let ciphertext_len = edek.ciphertext.len();
        if ciphertext_len < 16 {
            return Err(EnvelopeError::Crypto("Invalid EDEK ciphertext length".into()));
        }
        let edek_without_tag = &edek.ciphertext[..ciphertext_len - 16];
        let tag = &edek.ciphertext[ciphertext_len - 16..];

        // Step 4: Store EDEK in PostgreSQL
        let stored_dek = StoredDek {
            dek_id,
            user_id: *user_id,
            kek_version: kek_info.version,
            content_id: None,
            edek_ciphertext: edek.ciphertext.clone(),
            edek_nonce: edek.nonce.clone(),
            created_at: Utc::now(),
            is_active: true,
        };

        self.storage.store_dek(&stored_dek).await?;

        // Step 5: Return generated DEK with metadata
        Ok(GeneratedDek {
            dek_id,
            dek,
            edek_ciphertext: edek_without_tag.to_vec(),
            edek_nonce: edek.nonce,
            tag: tag.to_vec(),
            kek_version: kek_info.version,
        })
    }

    /// API: decrypt_edek(user_id, edek, nonce, tag, kek_version) -> dek
    ///
    /// Crypto flow:
    /// 1. Fetch KEK by (user_id, kek_version)
    /// 2. Decrypt EKEK using Server Key (AAD = user_id)
    /// 3. Decrypt EDEK using KEK (AAD = dek_id)
    /// 4. Return DEK
    pub async fn decrypt_edek(
        &self,
        dek_id: &Uuid,
    ) -> Result<SecureKey> {
        // Step 1: Get stored EDEK
        let stored_dek = self
            .storage
            .get_dek(dek_id)
            .await?
            .ok_or_else(|| EnvelopeError::KeyNotFound(format!("DEK {}", dek_id)))?;

        // Step 2: Get user's KEK for this DEK's version
        let kek_info = self.get_kek_by_version(&stored_dek.user_id, stored_dek.kek_version).await?;

        // Step 3: Decrypt EDEK to get DEK
        let edek = EncryptedData::new(stored_dek.edek_nonce, stored_dek.edek_ciphertext);
        let dek_bytes = AesGcmCipher::decrypt(&kek_info.kek, &edek, Some(dek_id.as_bytes()))?;

        Ok(SecureKey::new(dek_bytes))
    }

    /// API: rotate_user_kek(user_id)
    ///
    /// Crypto flow:
    /// 1. Get old active KEK
    /// 2. Decrypt old EKEK using Server Key
    /// 3. Generate new KEK
    /// 4. Encrypt new KEK with Server Key (new EKEK)
    /// 5. Store new KEK as active (incremented version)
    /// 6. Get all active DEKs for old KEK
    /// 7. For each DEK:
    ///    a. Decrypt EDEK with old KEK
    ///    b. Re-encrypt DEK with new KEK (new EDEK)
    ///    c. Update EDEK in database with new version
    /// 8. Deactivate old KEK
    pub async fn rotate_user_kek(&self, user_id: &Uuid) -> Result<KekRotationResult> {
        // Step 1: Get old active KEK
        let old_kek = self
            .storage
            .get_active_kek(user_id)
            .await?
            .ok_or_else(|| EnvelopeError::KeyNotFound(format!("No active KEK for user {}", user_id)))?;

        let old_version = old_kek.version;

        // Step 2: Decrypt old KEK
        let old_ekek = EncryptedData::new(old_kek.ekek_nonce, old_kek.ekek_ciphertext);
        let old_kek_bytes = AesGcmCipher::decrypt(&self.server_key, &old_ekek, Some(user_id.as_bytes()))?;
        let old_kek_key = SecureKey::new(old_kek_bytes);

        // Step 3: Generate new KEK
        let new_kek = SecureKey::generate();
        let new_version = old_version + 1;

        // Step 4: Encrypt new KEK with Server Key
        let new_ekek = AesGcmCipher::encrypt(&self.server_key, new_kek.as_bytes(), Some(user_id.as_bytes()))?;

        // Step 5: Store new KEK as active
        let new_stored_kek = StoredKek {
            user_id: *user_id,
            version: new_version,
            server_key_version: self.server_key_version,
            ekek_ciphertext: new_ekek.ciphertext,
            ekek_nonce: new_ekek.nonce,
            created_at: Utc::now(),
            is_active: true,
        };

        self.storage.store_kek(&new_stored_kek).await?;

        // Step 6: Get all active DEKs for old KEK
        let deks = self.storage.get_deks_by_kek(user_id, old_version).await?;
        let mut rewrapped_count = 0;

        // Step 7: Re-wrap all DEKs
        for dek in deks {
            // Decrypt EDEK with old KEK
            let old_edek = EncryptedData::new(dek.edek_nonce, dek.edek_ciphertext);
            let dek_bytes = AesGcmCipher::decrypt(&old_kek_key, &old_edek, Some(dek.dek_id.as_bytes()))?;

            // Re-encrypt DEK with new KEK
            let new_edek = AesGcmCipher::encrypt(&new_kek, &dek_bytes, Some(dek.dek_id.as_bytes()))?;

            // Update EDEK in database
            self.storage
                .update_dek_kek_version(&dek.dek_id, new_version, &new_edek.ciphertext, &new_edek.nonce)
                .await?;

            rewrapped_count += 1;
        }

        // Step 8: Deactivate old KEK
        self.storage.disable_kek(user_id, old_version).await?;

        Ok(KekRotationResult {
            user_id: *user_id,
            old_version,
            new_version,
            deks_rewrapped: rewrapped_count,
        })
    }

    /// API: disable_kek_if_unused(user_id, kek_version)
    ///
    /// Only disables KEK if zero active DEKs reference it
    /// Enforced by database trigger
    pub async fn disable_kek_if_unused(&self, user_id: &Uuid, kek_version: i32) -> Result<bool> {
        // Check if KEK has any active DEKs
        let count = self.storage.count_active_deks_for_kek(user_id, kek_version).await?;

        if count > 0 {
            return Ok(false); // Cannot disable, DEKs still reference it
        }

        // Safe to disable
        self.storage.disable_kek(user_id, kek_version).await?;
        Ok(true)
    }

    /// Internal: Get or create user's KEK
    async fn get_or_create_user_kek(&self, user_id: &Uuid) -> Result<KekInfo> {
        // Try to get existing active KEK
        if let Some(stored_kek) = self.storage.get_active_kek(user_id).await? {
            // Decrypt EKEK to get KEK
            let ekek = EncryptedData::new(stored_kek.ekek_nonce, stored_kek.ekek_ciphertext);
            let kek_bytes = AesGcmCipher::decrypt(&self.server_key, &ekek, Some(user_id.as_bytes()))?;
            let kek = SecureKey::new(kek_bytes);

            return Ok(KekInfo {
                version: stored_kek.version,
                kek,
            });
        }

        // Create new KEK for user
        let kek = SecureKey::generate();
        let version = 1;

        // Encrypt KEK with Server Key (AAD = user_id for binding)
        let ekek = AesGcmCipher::encrypt(&self.server_key, kek.as_bytes(), Some(user_id.as_bytes()))?;

        // Store EKEK in PostgreSQL
        let stored_kek = StoredKek {
            user_id: *user_id,
            version,
            server_key_version: self.server_key_version,
            ekek_ciphertext: ekek.ciphertext,
            ekek_nonce: ekek.nonce,
            created_at: Utc::now(),
            is_active: true,
        };

        self.storage.store_kek(&stored_kek).await?;

        Ok(KekInfo { version, kek })
    }

    /// Internal: Get KEK by version
    async fn get_kek_by_version(&self, user_id: &Uuid, version: i32) -> Result<KekInfo> {
        let stored_kek = self
            .storage
            .get_kek_by_version(user_id, version)
            .await?
            .ok_or_else(|| {
                EnvelopeError::KeyNotFound(format!("KEK for user {} version {}", user_id, version))
            })?;

        // Decrypt EKEK to get KEK
        let ekek = EncryptedData::new(stored_kek.ekek_nonce, stored_kek.ekek_ciphertext);
        let kek_bytes = AesGcmCipher::decrypt(&self.server_key, &ekek, Some(user_id.as_bytes()))?;
        let kek = SecureKey::new(kek_bytes);

        Ok(KekInfo { version, kek })
    }
}

/// Result of generate_dek operation
#[derive(Debug)]
pub struct GeneratedDek {
    pub dek_id: Uuid,
    pub dek: SecureKey,
    pub edek_ciphertext: Vec<u8>, // EDEK without tag
    pub edek_nonce: Vec<u8>,      // 12-byte nonce
    pub tag: Vec<u8>,             // 16-byte GCM authentication tag
    pub kek_version: i32,
}

/// Result of KEK rotation
#[derive(Debug)]
pub struct KekRotationResult {
    pub user_id: Uuid,
    pub old_version: i32,
    pub new_version: i32,
    pub deks_rewrapped: usize,
}

/// Internal KEK info
struct KekInfo {
    version: i32,
    kek: SecureKey,
}
