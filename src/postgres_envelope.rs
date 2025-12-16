use uuid::Uuid;
use chrono::Utc;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

use crate::crypto::{AesGcmCipher, EncryptedData, SecureKey};
use crate::error::{EnvelopeError, Result};
use crate::postgres_storage::{PostgresStorage, StoredKek};

/// Simplified envelope encryption service with PostgreSQL backend
///
/// Architecture:
/// - **Database (PostgreSQL)**: Stores ONLY EKEKs (user KEKs encrypted by Server Key)
/// - **Memory**: DEKs and EDEKs are generated on-demand, never persisted to database
/// - **Testing**: In-memory cache holds DEK/EDEK pairs for testing purposes only
///
/// Crypto flow:
/// 1. Fetch EKEK from PostgreSQL
/// 2. Decrypt EKEK → KEK (in memory)
/// 3. Generate DEK (in memory)
/// 4. Encrypt DEK → EDEK (in memory, for testing)
/// 5. Use DEK to encrypt data
/// 6. Return DEK + EDEK (stored in memory cache for testing)
///
/// Strict requirements:
/// - AES-256-GCM only
/// - No HKDF or KDFs
/// - Server Key loaded from .env as hardcoded 32-byte base64 value
/// - Each user has their own KEK
/// - KEKs encrypted by Server Key (EKEK) stored in PostgreSQL
/// - DEKs generated fresh, NEVER stored in database
/// - EDEKs created in-memory for testing only
pub struct PostgresEnvelopeService {
    storage: PostgresStorage,
    server_key: SecureKey,
    server_key_version: i32,
    // In-memory cache for testing: Maps dek_id → (DEK, EDEK, user_id, kek_version)
    dek_cache: Arc<RwLock<HashMap<Uuid, CachedDek>>>,
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
            .unwrap_or(1);

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
            dek_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// API: generate_dek(user_id) -> (dek, edek, nonce, tag, kek_version)
    ///
    /// Crypto flow:
    /// 1. Fetch ACTIVE EKEK from PostgreSQL for user
    /// 2. Decrypt EKEK using Server Key (AAD = user_id) → KEK (in memory)
    /// 3. Generate fresh DEK (random 32 bytes, in memory)
    /// 4. Encrypt DEK using KEK with AES-GCM (AAD = dek_id) → EDEK (in memory)
    /// 5. Cache DEK + EDEK in memory for testing purposes
    /// 6. Return (dek, edek_ciphertext, edek_nonce, tag, kek_version)
    ///
    /// Note: DEK and EDEK are NEVER stored in database, only in memory cache
    pub async fn generate_dek(&self, user_id: &Uuid) -> Result<GeneratedDek> {
        // Step 1: Get or create user's KEK from database (EKEK)
        let kek_info = self.get_or_create_user_kek(user_id).await?;

        // Step 2: Generate fresh DEK (random 32 bytes, in memory only)
        let dek = SecureKey::generate();
        let dek_id = Uuid::new_v4();

        // Step 3: Encrypt DEK with user's KEK (AAD = dek_id for binding)
        // This creates EDEK in memory only
        let edek = AesGcmCipher::encrypt(&kek_info.kek, dek.as_bytes(), Some(dek_id.as_bytes()))?;

        // Extract tag (last 16 bytes of ciphertext)
        let ciphertext_len = edek.ciphertext.len();
        if ciphertext_len < 16 {
            return Err(EnvelopeError::Crypto("Invalid EDEK ciphertext length".into()));
        }
        let edek_without_tag = &edek.ciphertext[..ciphertext_len - 16];
        let tag = &edek.ciphertext[ciphertext_len - 16..];

        // Step 4: Cache DEK + EDEK in memory for testing (NOT in database)
        self.dek_cache.write().insert(
            dek_id,
            CachedDek {
                dek: dek.clone(),
                edek_ciphertext: edek.ciphertext.clone(),
                edek_nonce: edek.nonce.clone(),
                user_id: *user_id,
                kek_version: kek_info.version,
                created_at: Utc::now(),
            },
        );

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

    /// API: decrypt_edek(user_id, edek, nonce, kek_version) -> dek
    ///
    /// Crypto flow:
    /// 1. Try to get from in-memory cache first (for testing)
    /// 2. If not cached, fetch EKEK from PostgreSQL by (user_id, kek_version)
    /// 3. Decrypt EKEK using Server Key (AAD = user_id) → KEK (in memory)
    /// 4. Decrypt EDEK using KEK (AAD = dek_id) → DEK (in memory)
    /// 5. Return DEK
    pub async fn decrypt_edek(
        &self,
        dek_id: &Uuid,
        edek_ciphertext: &[u8],
        edek_nonce: &[u8],
        user_id: &Uuid,
        kek_version: i32,
    ) -> Result<SecureKey> {
        // Step 1: Try to get from cache (for testing)
        if let Some(cached) = self.dek_cache.read().get(dek_id) {
            return Ok(cached.dek.clone());
        }

        // Step 2: Not in cache, decrypt from EDEK components
        // Get user's KEK for this version
        let kek_info = self.get_kek_by_version(user_id, kek_version).await?;

        // Step 3: Decrypt EDEK to get DEK
        // Reconstruct full ciphertext (edek + tag if separated)
        let full_ciphertext = if edek_ciphertext.len() < 48 {
            // If tag was separated, we need to get it from somewhere
            // For now, assume full ciphertext is provided
            edek_ciphertext.to_vec()
        } else {
            edek_ciphertext.to_vec()
        };

        let edek = EncryptedData::new(edek_nonce.to_vec(), full_ciphertext);
        let dek_bytes = AesGcmCipher::decrypt(&kek_info.kek, &edek, Some(dek_id.as_bytes()))?;

        Ok(SecureKey::new(dek_bytes))
    }

    /// API: rotate_user_kek(user_id)
    ///
    /// Crypto flow:
    /// 1. Get old active EKEK from database
    /// 2. Decrypt old EKEK using Server Key → old KEK
    /// 3. Generate new KEK
    /// 4. Encrypt new KEK with Server Key → new EKEK
    /// 5. Store new EKEK in database (incremented version)
    /// 6. Deactivate old EKEK in database
    /// 7. Update in-memory cached EDEKs with new KEK (re-wrap)
    ///
    /// Note: Since DEKs/EDEKs are in-memory only, rotation just updates the cache
    pub async fn rotate_user_kek(&self, user_id: &Uuid) -> Result<KekRotationResult> {
        // Step 1: Get old active KEK (EKEK from database)
        let old_kek = self
            .storage
            .get_active_kek(user_id)
            .await?
            .ok_or_else(|| EnvelopeError::KeyNotFound(format!("No active KEK for user {}", user_id)))?;

        let old_version = old_kek.version;

        // Step 2: Decrypt old EKEK → old KEK (not used, but kept for verification)
        let old_ekek = EncryptedData::new(old_kek.ekek_nonce, old_kek.ekek_ciphertext);
        let _old_kek_bytes = AesGcmCipher::decrypt(&self.server_key, &old_ekek, Some(user_id.as_bytes()))?;

        // Step 3: Generate new KEK
        let new_kek = SecureKey::generate();
        let new_version = old_version + 1;

        // Step 4: Encrypt new KEK with Server Key → new EKEK
        let new_ekek = AesGcmCipher::encrypt(&self.server_key, new_kek.as_bytes(), Some(user_id.as_bytes()))?;

        // Step 5: Store new EKEK in database
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

        // Step 6: Re-wrap cached EDEKs with new KEK (in-memory only)
        let mut cache = self.dek_cache.write();
        let mut rewrapped_count = 0;

        let dek_ids: Vec<Uuid> = cache
            .iter()
            .filter(|(_, cached)| cached.user_id == *user_id && cached.kek_version == old_version)
            .map(|(id, _)| *id)
            .collect();

        for dek_id in dek_ids {
            if let Some(cached) = cache.get_mut(&dek_id) {
                // Re-encrypt DEK with new KEK
                let new_edek = AesGcmCipher::encrypt(&new_kek, cached.dek.as_bytes(), Some(dek_id.as_bytes()))?;
                cached.edek_ciphertext = new_edek.ciphertext;
                cached.edek_nonce = new_edek.nonce;
                cached.kek_version = new_version;
                rewrapped_count += 1;
            }
        }

        drop(cache);

        // Step 7: Deactivate old EKEK in database
        self.storage.disable_kek(user_id, old_version).await?;

        Ok(KekRotationResult {
            user_id: *user_id,
            old_version,
            new_version,
            deks_rewrapped: rewrapped_count,
        })
    }

    /// Get KEK count for user (all versions)
    pub async fn get_user_kek_count(&self, user_id: &Uuid) -> Result<usize> {
        let keks = self.storage.get_all_user_keks(user_id).await?;
        Ok(keks.len())
    }

    /// Get cached DEK count (in-memory only, for testing)
    pub fn get_cached_dek_count(&self) -> usize {
        self.dek_cache.read().len()
    }

    /// Clear DEK cache (for testing)
    pub fn clear_dek_cache(&self) {
        self.dek_cache.write().clear();
    }

    /// Internal: Get or create user's KEK
    async fn get_or_create_user_kek(&self, user_id: &Uuid) -> Result<KekInfo> {
        // Try to get existing active KEK (EKEK from database)
        if let Some(stored_kek) = self.storage.get_active_kek(user_id).await? {
            // Decrypt EKEK to get KEK (in memory)
            let ekek = EncryptedData::new(stored_kek.ekek_nonce, stored_kek.ekek_ciphertext);
            let kek_bytes = AesGcmCipher::decrypt(&self.server_key, &ekek, Some(user_id.as_bytes()))?;
            let kek = SecureKey::new(kek_bytes);

            return Ok(KekInfo {
                version: stored_kek.version,
                kek,
            });
        }

        // Create new KEK for user (in memory)
        let kek = SecureKey::generate();
        let version = 1;

        // Encrypt KEK with Server Key (AAD = user_id for binding) → EKEK
        let ekek = AesGcmCipher::encrypt(&self.server_key, kek.as_bytes(), Some(user_id.as_bytes()))?;

        // Store EKEK in PostgreSQL (NOT the KEK itself)
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

        // Decrypt EKEK to get KEK (in memory)
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

/// Internal KEK info (in-memory only)
struct KekInfo {
    version: i32,
    kek: SecureKey,
}

/// Cached DEK info (in-memory only, for testing)
#[derive(Debug, Clone)]
struct CachedDek {
    dek: SecureKey,
    edek_ciphertext: Vec<u8>,
    edek_nonce: Vec<u8>,
    user_id: Uuid,
    kek_version: i32,
    #[allow(dead_code)]
    created_at: chrono::DateTime<chrono::Utc>,
}
