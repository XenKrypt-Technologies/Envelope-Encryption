use uuid::Uuid;
use chrono::Utc;

use crate::crypto::{AesGcmCipher, EncryptedData, SecureKey, generate_random_bytes};
use crate::error::{EnvelopeError, Result};
use crate::postgres_storage::{PostgresStorage, StoredKek, KekStatus};

/// PostgreSQL-based envelope encryption service
///
/// Architecture:
/// - **Database**: Stores KEKs as plaintext (32 bytes, encrypted at rest by database encryption)
/// - **Memory**: DEKs generated on-demand, never persisted to database
///
/// Key hierarchy:
/// - Database Encryption → KEK (plaintext in DB, encrypted at rest by database)
/// - KEK → DEK (ephemeral, managed by application)
/// - DEK → Application Data
///
/// HSM-style design:
/// - Library manages KEK lifecycle (create, rotate, disable, delete)
/// - Application manages DEK caching/storage (as EDEK blobs)
/// - Crypto primitives provided for DEK encryption/decryption
///
/// Rotation strategy:
/// 1. Mark all ACTIVE KEKs as RETIRED
/// 2. Rotate in batches of 50 using SQL LIMIT
/// 3. Lazy rotation: if RETIRED KEK accessed, rotate immediately
/// 4. Only ACTIVE KEK used for encryption, old KEKs for decryption only
pub struct PostgresEnvelopeService {
    storage: PostgresStorage,
}

impl PostgresEnvelopeService {
    /// Initialize service
    pub async fn new(storage: PostgresStorage) -> Result<Self> {
        Ok(Self { storage })
    }

    /// API: generate_dek(user_id) -> (dek, edek, kek_version)
    ///
    /// Crypto flow:
    /// 1. Get or create ACTIVE KEK for user (plaintext from DB, encrypted at rest by database)
    /// 2. Generate fresh DEK (random 32 bytes, ephemeral)
    /// 3. Encrypt DEK using KEK with AES-GCM (AAD = dek_id) → EDEK
    /// 4. Return (dek_id, dek, edek_blob, kek_version)
    ///
    /// Note: Application is responsible for caching DEK or storing EDEK blob
    pub async fn generate_dek(&self, user_id: &Uuid) -> Result<GeneratedDek> {
        // Get or create user's ACTIVE KEK from database
        let kek_info = self.get_or_create_user_kek(user_id).await?;

        // If KEK is RETIRED, perform lazy rotation
        if kek_info.status == KekStatus::Retired {
            let rotated_kek = self.rotate_single_kek(user_id, kek_info.version).await?;
            return self.generate_dek_with_kek(user_id, rotated_kek).await;
        }

        self.generate_dek_with_kek(user_id, kek_info).await
    }

    /// Internal: Generate DEK with a specific KEK
    async fn generate_dek_with_kek(&self, _user_id: &Uuid, kek_info: KekInfo) -> Result<GeneratedDek> {
        // Generate fresh DEK (random 32 bytes, ephemeral)
        let dek = SecureKey::generate();
        let dek_id = Uuid::new_v4();

        // Encrypt DEK with user's KEK (AAD = dek_id for binding)
        let edek = AesGcmCipher::encrypt(&kek_info.kek, dek.as_bytes(), Some(dek_id.as_bytes()))?;

        // Convert to AEAD blob format (nonce || ciphertext || tag)
        let edek_blob = edek.to_aead_blob();

        Ok(GeneratedDek {
            dek_id,
            dek,
            edek_blob,
            kek_version: kek_info.version,
        })
    }

    /// API: decrypt_edek(dek_id, edek_blob, user_id, kek_version) -> dek
    ///
    /// Crypto flow:
    /// 1. Fetch KEK from database by (user_id, kek_version)
    /// 2. Decrypt EDEK using the ORIGINAL KEK (AAD = dek_id) → DEK
    /// 3. If KEK is RETIRED, log intent for lazy rotation (rotation happens after decryption)
    /// 4. Return DEK
    ///
    /// IMPORTANT: Lazy rotation happens AFTER decryption because:
    /// - EDEK was encrypted with the OLD KEK (specified by kek_version)
    /// - We MUST decrypt with the SAME KEK that was used for encryption
    /// - Only AFTER successful decryption can we re-encrypt with a new ACTIVE KEK
    pub async fn decrypt_edek(
        &self,
        dek_id: &Uuid,
        edek_blob: &[u8],
        user_id: &Uuid,
        kek_version: i64,
    ) -> Result<SecureKey> {
        // Get user's KEK for this version
        let kek_info = self.get_kek_by_version(user_id, kek_version).await?;

        // Decrypt EDEK using the ORIGINAL KEK (CRITICAL: must use same KEK that encrypted it)
        let edek = EncryptedData::from_aead_blob(edek_blob)?;
        let dek_bytes = AesGcmCipher::decrypt(&kek_info.kek, &edek, Some(dek_id.as_bytes()))?;

        Ok(SecureKey::new(dek_bytes))
    }

    /// API: bulk_rotate_all_keks() - Rotate all KEKs in bulk
    ///
    /// Rotation strategy:
    /// 1. Mark all ACTIVE KEKs as RETIRED
    /// 2. Rotate in batches of 50 using SQL LIMIT
    /// 3. For each KEK: generate new 32-byte key, call rotate_kek()
    ///
    /// Returns: (total_keks_marked_retired, total_keks_rotated)
    pub async fn bulk_rotate_all_keks(&self) -> Result<BulkRotationResult> {
        // Mark all ACTIVE KEKs as RETIRED
        let marked_count = self.storage.mark_all_active_keks_as_retired().await?;

        if marked_count == 0 {
            return Ok(BulkRotationResult {
                keks_marked_retired: 0,
                keks_rotated: 0,
            });
        }

        // Rotate in batches of 50
        let mut total_rotated = 0i64;
        let batch_size = 50;
        let mut iteration = 0;

        loop {
            iteration += 1;

            let batch = self.storage.get_retired_keks_batch(batch_size).await?;
            if batch.is_empty() {
                break;
            }

            for stored_kek in batch.iter() {
                // Generate new KEK (32 bytes)
                let new_kek_bytes = generate_random_bytes(32);

                // Rotate KEK
                let _new_version = self.storage.rotate_kek(
                    &stored_kek.user_id,
                    stored_kek.version,
                    &new_kek_bytes
                ).await?;

                total_rotated += 1;
            }

            // Safety check: prevent infinite loop
            if iteration > 10 {
                eprintln!("[ERROR] Bulk rotation safety limit reached (10 iterations)");
                break;
            }
        }

        Ok(BulkRotationResult {
            keks_marked_retired: marked_count,
            keks_rotated: total_rotated,
        })
    }

    /// API: rotate_user_kek(user_id) - Rotate a specific user's ACTIVE KEK on demand
    ///
    /// This function allows you to rotate a specific user's KEK without doing bulk rotation.
    /// It will:
    /// 1. Get the user's current ACTIVE KEK
    /// 2. Mark it as RETIRED
    /// 3. Generate a new ACTIVE KEK for the user
    ///
    /// Returns: Result with the new KEK version number
    pub async fn rotate_user_kek(&self, user_id: &Uuid) -> Result<UserKekRotationResult> {
        // Get the current ACTIVE KEK
        let active_kek = self.storage.get_active_kek(user_id).await?;

        let old_version = match active_kek {
            Some(kek) => kek.version,
            None => {
                return Err(EnvelopeError::KeyNotFound(format!(
                    "No ACTIVE KEK found for user: {}. Generate a KEK first by calling generate_dek().",
                    user_id
                )));
            }
        };

        // Rotate the KEK
        let rotated_kek = self.rotate_single_kek(user_id, old_version).await?;

        Ok(UserKekRotationResult {
            user_id: *user_id,
            old_version,
            new_version: rotated_kek.version,
        })
    }

    /// API: disable_kek(user_id, version) - Disable a KEK
    ///
    /// Changes KEK status to DISABLED. Only RETIRED KEKs can be disabled.
    /// Returns true if status changed, false if already disabled.
    pub async fn disable_kek(&self, user_id: &Uuid, version: i64) -> Result<bool> {
        self.storage.disable_kek(user_id, version).await
    }

    /// API: delete_kek(user_id, version) - Delete a KEK
    ///
    /// Only deletes if status is DISABLED. Otherwise raises exception.
    /// Returns true if deleted, false if not found.
    pub async fn delete_kek(&self, user_id: &Uuid, version: i64) -> Result<bool> {
        self.storage.delete_kek(user_id, version).await
    }

    /// API: get_kek_stats() - Get KEK statistics by status
    pub async fn get_kek_stats(&self) -> Result<Vec<(String, i64)>> {
        self.storage.get_kek_stats().await
    }

    /// Internal: Get or create user's ACTIVE KEK
    async fn get_or_create_user_kek(&self, user_id: &Uuid) -> Result<KekInfo> {
        // Try to get existing active KEK
        if let Some(stored_kek) = self.storage.get_active_kek(user_id).await? {
            let kek = SecureKey::new(stored_kek.kek_plaintext);

            return Ok(KekInfo {
                version: stored_kek.version,
                kek,
                status: stored_kek.status,
            });
        }

        // Create new KEK for user
        let kek = SecureKey::generate();
        let version = 1;

        // Store KEK in database (plaintext, database encrypts at rest)
        let stored_kek = StoredKek {
            user_id: *user_id,
            version,
            kek_plaintext: kek.as_bytes().to_vec(),
            status: KekStatus::Active,
            created_at: Utc::now(),
            last_accessed_at: None,
            last_rotated_at: None,
        };

        self.storage.store_kek(&stored_kek).await?;

        Ok(KekInfo {
            version,
            kek,
            status: KekStatus::Active,
        })
    }

    /// Internal: Get KEK by version
    async fn get_kek_by_version(&self, user_id: &Uuid, version: i64) -> Result<KekInfo> {
        let stored_kek = self
            .storage
            .get_kek_by_version(user_id, version)
            .await?
            .ok_or_else(|| {
                EnvelopeError::KeyNotFound(format!("KEK for user {} version {}", user_id, version))
            })?;

        let kek = SecureKey::new(stored_kek.kek_plaintext);

        Ok(KekInfo {
            version,
            kek,
            status: stored_kek.status,
        })
    }

    /// Internal: Rotate single KEK (lazy rotation)
    async fn rotate_single_kek(&self, user_id: &Uuid, old_version: i64) -> Result<KekInfo> {
        // Generate new KEK
        let new_kek_bytes = generate_random_bytes(32);
        let new_kek = SecureKey::new(new_kek_bytes.clone());

        // Call SQL function to rotate
        let new_version = self.storage.rotate_kek(user_id, old_version, &new_kek_bytes).await?;

        Ok(KekInfo {
            version: new_version,
            kek: new_kek,
            status: KekStatus::Active,
        })
    }
}

/// Result of generate_dek operation
#[derive(Debug)]
pub struct GeneratedDek {
    pub dek_id: Uuid,
    pub dek: SecureKey,
    pub edek_blob: Vec<u8>,  // AEAD format: nonce(12) || ciphertext(32) || tag(16) = 60 bytes
    pub kek_version: i64,
}

/// Result of bulk rotation
#[derive(Debug)]
pub struct BulkRotationResult {
    pub keks_marked_retired: i64,
    pub keks_rotated: i64,
}

/// Result of single user KEK rotation
#[derive(Debug)]
pub struct UserKekRotationResult {
    pub user_id: Uuid,
    pub old_version: i64,
    pub new_version: i64,
}

/// Internal KEK info (in-memory only)
#[derive(Debug)]
struct KekInfo {
    version: i64,
    kek: SecureKey,
    status: KekStatus,
}
