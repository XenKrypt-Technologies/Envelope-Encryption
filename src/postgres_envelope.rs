use uuid::Uuid;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

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
/// - KEK → DEK (in-memory only)
/// - DEK → Application Data
///
/// Rotation strategy:
/// 1. Mark all ACTIVE KEKs as RETIRED
/// 2. Rotate in batches of 50 using SQL LIMIT
/// 3. Lazy rotation: if RETIRED KEK accessed, rotate immediately
/// 4. Only ACTIVE KEK used for encryption, old KEKs for decryption only
pub struct PostgresEnvelopeService {
    storage: PostgresStorage,
    // In-memory cache for testing: Maps dek_id → (DEK, EDEK, user_id, kek_version)
    dek_cache: Arc<RwLock<HashMap<Uuid, CachedDek>>>,
}

impl PostgresEnvelopeService {
    /// Initialize service
    pub async fn new(storage: PostgresStorage) -> Result<Self> {
        println!("[INIT] Initializing PostgresEnvelopeService...");
        println!("[INIT] ✓ Database encryption handles KEKs at rest");
        println!("[INIT] ✓ KEKs stored as plaintext (32 bytes) in database");
        println!("[INIT] ✓ PostgresEnvelopeService initialized successfully\n");

        Ok(Self {
            storage,
            dek_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// API: generate_dek(user_id) -> (dek, edek, kek_version)
    ///
    /// Crypto flow:
    /// 1. Get or create ACTIVE KEK for user (plaintext from DB, encrypted at rest by database)
    /// 2. Generate fresh DEK (random 32 bytes, in memory)
    /// 3. Encrypt DEK using KEK with AES-GCM (AAD = dek_id) → EDEK (in memory)
    /// 4. Cache DEK + EDEK in memory for testing purposes
    /// 5. Return (dek, edek_blob, kek_version)
    ///
    /// Note: DEK and EDEK are NEVER stored in database, only in memory cache
    pub async fn generate_dek(&self, user_id: &Uuid) -> Result<GeneratedDek> {
        println!("\n[GENERATE_DEK] Starting DEK generation for user: {}", user_id);

        // Step 1: Get or create user's ACTIVE KEK from database
        println!("[GENERATE_DEK] Step 1: Fetching/creating user KEK from database...");
        let kek_info = self.get_or_create_user_kek(user_id).await?;
        println!("[GENERATE_DEK] ✓ KEK retrieved (version: {}, status: {:?})", kek_info.version, kek_info.status);

        // If KEK is RETIRED, perform lazy rotation
        if kek_info.status == KekStatus::Retired {
            println!("[GENERATE_DEK] ⚠ KEK is RETIRED, performing lazy rotation...");
            let rotated_kek = self.rotate_single_kek(user_id, kek_info.version).await?;
            println!("[GENERATE_DEK] ✓ Lazy rotation complete, using new ACTIVE KEK (version: {})", rotated_kek.version);
            return self.generate_dek_with_kek(user_id, rotated_kek).await;
        }

        self.generate_dek_with_kek(user_id, kek_info).await
    }

    /// Internal: Generate DEK with a specific KEK
    async fn generate_dek_with_kek(&self, user_id: &Uuid, kek_info: KekInfo) -> Result<GeneratedDek> {
        // Step 2: Generate fresh DEK (random 32 bytes, in memory only)
        println!("[GENERATE_DEK] Step 2: Generating fresh DEK (32 bytes, in-memory)...");
        let dek = SecureKey::generate();
        let dek_id = Uuid::new_v4();
        println!("[GENERATE_DEK] ✓ DEK generated (ID: {})", dek_id);
        println!("[GENERATE_DEK] ⚠ DEK is in-memory ONLY, NOT stored in database");

        // Step 3: Encrypt DEK with user's KEK (AAD = dek_id for binding)
        println!("[GENERATE_DEK] Step 3: Encrypting DEK with KEK (AAD=dek_id)...");
        let edek = AesGcmCipher::encrypt(&kek_info.kek, dek.as_bytes(), Some(dek_id.as_bytes()))?;

        // Convert to AEAD blob format (nonce || ciphertext || tag)
        let edek_blob = edek.to_aead_blob();
        println!("[GENERATE_DEK] ✓ EDEK created (AEAD blob: {} bytes)", edek_blob.len());

        // Step 4: Cache DEK + EDEK in memory for testing (NOT in database)
        println!("[GENERATE_DEK] Step 4: Caching DEK+EDEK in memory (testing only)...");
        self.dek_cache.write().insert(
            dek_id,
            CachedDek {
                dek: dek.clone(),
                edek_blob: edek_blob.clone(),
                user_id: *user_id,
                kek_version: kek_info.version,
                created_at: Utc::now(),
            },
        );
        let cache_size = self.dek_cache.read().len();
        println!("[GENERATE_DEK] ✓ Cached in memory (total cached DEKs: {})", cache_size);
        println!("[GENERATE_DEK] ⚠ EDEK is in-memory ONLY, NOT stored in database");
        println!("[GENERATE_DEK] ✓ DEK generation complete\n");

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
    /// 1. Try to get from in-memory cache first (for testing)
    /// 2. If not cached, fetch KEK from database by (user_id, kek_version)
    /// 3. If KEK is RETIRED, perform lazy rotation and use new ACTIVE KEK
    /// 4. Decrypt EDEK using KEK (AAD = dek_id) → DEK (in memory)
    /// 5. Return DEK
    pub async fn decrypt_edek(
        &self,
        dek_id: &Uuid,
        edek_blob: &[u8],
        user_id: &Uuid,
        kek_version: i64,
    ) -> Result<SecureKey> {
        println!("\n[DECRYPT_EDEK] Starting EDEK decryption (DEK ID: {})", dek_id);
        println!("[DECRYPT_EDEK] User: {}", user_id);
        println!("[DECRYPT_EDEK] KEK version: {}", kek_version);
        println!("[DECRYPT_EDEK] EDEK blob: {} bytes", edek_blob.len());

        // Step 1: Try to get from cache (for testing)
        println!("[DECRYPT_EDEK] Step 1: Checking in-memory cache...");
        if let Some(cached) = self.dek_cache.read().get(dek_id) {
            println!("[DECRYPT_EDEK] ✓ Found DEK in cache!");
            println!("[DECRYPT_EDEK] ✓ Returning cached DEK (no database access needed)\n");
            return Ok(cached.dek.clone());
        }
        println!("[DECRYPT_EDEK] ✗ Not in cache, will decrypt from EDEK");

        // Step 2: Get user's KEK for this version
        println!("[DECRYPT_EDEK] Step 2: Fetching KEK from database (version: {})...", kek_version);
        let kek_info = self.get_kek_by_version(user_id, kek_version).await?;
        println!("[DECRYPT_EDEK] ✓ KEK retrieved (status: {:?})", kek_info.status);

        // Step 3: If KEK is RETIRED, perform lazy rotation
        let kek_to_use = if kek_info.status == KekStatus::Retired {
            println!("[DECRYPT_EDEK] ⚠ KEK is RETIRED, performing lazy rotation...");
            let rotated_kek = self.rotate_single_kek(user_id, kek_version).await?;
            println!("[DECRYPT_EDEK] ✓ Lazy rotation complete, using new ACTIVE KEK (version: {})", rotated_kek.version);
            rotated_kek
        } else {
            kek_info
        };

        // Step 4: Decrypt EDEK to get DEK
        println!("[DECRYPT_EDEK] Step 3: Decrypting EDEK with KEK (AAD=dek_id)...");
        let edek = EncryptedData::from_aead_blob(edek_blob)?;
        let dek_bytes = AesGcmCipher::decrypt(&kek_to_use.kek, &edek, Some(dek_id.as_bytes()))?;
        println!("[DECRYPT_EDEK] ✓ DEK decrypted successfully (32 bytes, in-memory)");
        println!("[DECRYPT_EDEK] ⚠ DEK is in-memory ONLY, NOT stored in database");
        println!("[DECRYPT_EDEK] ✓ EDEK decryption complete\n");

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
        println!("\n[BULK_ROTATE] Starting bulk KEK rotation");

        // Step 1: Mark all ACTIVE KEKs as RETIRED
        println!("[BULK_ROTATE] Step 1: Marking all ACTIVE KEKs as RETIRED...");
        let marked_count = self.storage.mark_all_active_keks_as_retired().await?;
        println!("[BULK_ROTATE] ✓ Marked {} KEKs as RETIRED", marked_count);

        if marked_count == 0 {
            println!("[BULK_ROTATE] ⚠ No KEKs to rotate");
            return Ok(BulkRotationResult {
                keks_marked_retired: 0,
                keks_rotated: 0,
            });
        }

        // Step 2: Rotate in batches of 50
        println!("[BULK_ROTATE] Step 2: Rotating KEKs in batches of 50...");
        let mut total_rotated = 0i64;
        let batch_size = 50;
        let mut iteration = 0;

        loop {
            iteration += 1;
            println!("[BULK_ROTATE] Fetching batch {}...", iteration);

            let batch = self.storage.get_retired_keks_batch(batch_size).await?;
            if batch.is_empty() {
                println!("[BULK_ROTATE] ✓ No more RETIRED KEKs to rotate");
                break;
            }

            let batch_len = batch.len();
            println!("[BULK_ROTATE] Processing batch {} with {} RETIRED KEKs...", iteration, batch_len);

            for (idx, stored_kek) in batch.iter().enumerate() {
                // Generate new KEK (32 bytes)
                let new_kek_bytes = generate_random_bytes(32);

                // Rotate KEK
                let new_version = self.storage.rotate_kek(
                    &stored_kek.user_id,
                    stored_kek.version,
                    &new_kek_bytes
                ).await?;

                total_rotated += 1;

                if (idx + 1) % 10 == 0 || idx + 1 == batch_len {
                    println!("[BULK_ROTATE]   ✓ Rotated {}/{} KEKs in batch {}", idx + 1, batch_len, iteration);
                }
            }

            // Safety check: prevent infinite loop
            if iteration > 10 {
                println!("[BULK_ROTATE] ⚠ Safety limit reached (10 iterations), stopping");
                println!("[BULK_ROTATE] ⚠ This may indicate an issue with rotation logic");
                break;
            }
        }

        println!("[BULK_ROTATE] ✓ Bulk rotation complete");
        println!("[BULK_ROTATE] ✓ Marked: {}, Rotated: {}\n", marked_count, total_rotated);

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
        println!("[ROTATE_USER_KEK] Starting KEK rotation for user: {}", user_id);

        // Get the current ACTIVE KEK
        let active_kek = self.storage.get_active_kek(user_id).await?;

        let old_version = match active_kek {
            Some(kek) => {
                println!("[ROTATE_USER_KEK] Found ACTIVE KEK (version: {})", kek.version);
                kek.version
            }
            None => {
                return Err(EnvelopeError::KeyNotFound(format!(
                    "No ACTIVE KEK found for user: {}. Generate a KEK first by calling generate_dek().",
                    user_id
                )));
            }
        };

        // Rotate the KEK
        let rotated_kek = self.rotate_single_kek(user_id, old_version).await?;

        println!("[ROTATE_USER_KEK] ✓ KEK rotation complete (v{} → v{})", old_version, rotated_kek.version);

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
        println!("\n[DISABLE_KEK] Disabling KEK (user: {}, version: {})", user_id, version);
        let result = self.storage.disable_kek(user_id, version).await?;
        if result {
            println!("[DISABLE_KEK] ✓ KEK disabled successfully\n");
        } else {
            println!("[DISABLE_KEK] ⚠ KEK was already disabled\n");
        }
        Ok(result)
    }

    /// API: delete_kek(user_id, version) - Delete a KEK
    ///
    /// Only deletes if status is DISABLED. Otherwise raises exception.
    /// Returns true if deleted, false if not found.
    pub async fn delete_kek(&self, user_id: &Uuid, version: i64) -> Result<bool> {
        println!("\n[DELETE_KEK] Deleting KEK (user: {}, version: {})", user_id, version);
        let result = self.storage.delete_kek(user_id, version).await?;
        if result {
            println!("[DELETE_KEK] ✓ KEK deleted successfully\n");
        } else {
            println!("[DELETE_KEK] ⚠ KEK not found\n");
        }
        Ok(result)
    }

    /// API: get_kek_stats() - Get KEK statistics by status
    pub async fn get_kek_stats(&self) -> Result<Vec<(String, i64)>> {
        self.storage.get_kek_stats().await
    }

    /// Get cached DEK count (in-memory only, for testing)
    pub fn get_cached_dek_count(&self) -> usize {
        self.dek_cache.read().len()
    }

    /// Clear DEK cache (for testing)
    pub fn clear_dek_cache(&self) {
        self.dek_cache.write().clear()
    }

    /// Internal: Get or create user's ACTIVE KEK
    async fn get_or_create_user_kek(&self, user_id: &Uuid) -> Result<KekInfo> {
        println!("[GET_OR_CREATE_KEK] Checking database for existing KEK (user: {})...", user_id);

        // Try to get existing active KEK
        if let Some(stored_kek) = self.storage.get_active_kek(user_id).await? {
            println!("[GET_OR_CREATE_KEK] ✓ Found existing KEK in database");
            println!("[GET_OR_CREATE_KEK]   - KEK version: {}", stored_kek.version);
            println!("[GET_OR_CREATE_KEK]   - KEK status: {:?}", stored_kek.status);
            println!("[GET_OR_CREATE_KEK]   - KEK plaintext: {} bytes", stored_kek.kek_plaintext.len());
            println!("[GET_OR_CREATE_KEK] ⚠ KEK stored as plaintext, encrypted at rest by database");

            let kek = SecureKey::new(stored_kek.kek_plaintext);

            return Ok(KekInfo {
                version: stored_kek.version,
                kek,
                status: stored_kek.status,
            });
        }

        // Create new KEK for user
        println!("[GET_OR_CREATE_KEK] ✗ No existing KEK found, creating new one...");
        println!("[GET_OR_CREATE_KEK] Generating new KEK (32 bytes)...");
        let kek = SecureKey::generate();
        let version = 1;
        println!("[GET_OR_CREATE_KEK] ✓ KEK generated (version: {})", version);

        // Store KEK in database (plaintext, database encrypts at rest)
        println!("[GET_OR_CREATE_KEK] Storing KEK in database...");
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
        println!("[GET_OR_CREATE_KEK] ✓ KEK stored in database (user_keks table)");
        println!("[GET_OR_CREATE_KEK] ⚠ KEK stored as plaintext, encrypted at rest by database");

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
        println!("[ROTATE_KEK] Rotating single KEK (user: {}, old_version: {})", user_id, old_version);

        // Generate new KEK
        let new_kek_bytes = generate_random_bytes(32);
        let new_kek = SecureKey::new(new_kek_bytes.clone());

        // Call SQL function to rotate
        let new_version = self.storage.rotate_kek(user_id, old_version, &new_kek_bytes).await?;
        println!("[ROTATE_KEK] ✓ KEK rotated (v{} → v{})", old_version, new_version);

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

/// Cached DEK info (in-memory only, for testing)
#[derive(Debug, Clone)]
struct CachedDek {
    dek: SecureKey,
    #[allow(dead_code)]
    edek_blob: Vec<u8>,  // AEAD format: nonce || ciphertext || tag
    #[allow(dead_code)]
    user_id: Uuid,
    #[allow(dead_code)]
    kek_version: i64,
    #[allow(dead_code)]
    created_at: chrono::DateTime<chrono::Utc>,
}
