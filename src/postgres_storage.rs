use sqlx::{PgPool, Row};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::str::FromStr;

use crate::error::{EnvelopeError, Result};

/// PostgreSQL storage - stores KEKs as plaintext (encrypted at rest by database encryption)
///
/// Architecture:
/// - Database: Stores user KEKs as plaintext (database encryption handles at rest encryption)
/// - Memory: DEKs generated on-demand, never persisted
///
/// Key hierarchy:
/// - Database Encryption → KEK (stored as plaintext in DB, encrypted at rest by database)
/// - KEK → DEK (in-memory only)
/// - DEK → Application Data
pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Get active KEK for a user (calls SQL function)
    pub async fn get_active_kek(&self, user_id: &Uuid) -> Result<Option<StoredKek>> {
        let row = sqlx::query(
            r#"
            SELECT user_id, kek_version, kek_plaintext, status::TEXT as status, created_at, last_accessed_at, last_rotated_at
            FROM get_active_kek($1)
            "#
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to get active KEK: {}", e)))?;

        Ok(row.map(|r| StoredKek {
            user_id: r.get("user_id"),
            version: r.get("kek_version"),
            kek_plaintext: r.get("kek_plaintext"),
            status: KekStatus::from_str(r.get("status")).unwrap_or(KekStatus::Active),
            created_at: r.get("created_at"),
            last_accessed_at: r.get("last_accessed_at"),
            last_rotated_at: r.get("last_rotated_at"),
        }))
    }

    /// Get KEK by version (calls SQL function)
    pub async fn get_kek_by_version(&self, user_id: &Uuid, version: i64) -> Result<Option<StoredKek>> {
        let row = sqlx::query(
            r#"
            SELECT user_id, kek_version, kek_plaintext, status::TEXT as status, created_at, last_accessed_at, last_rotated_at
            FROM get_kek_by_version($1, $2)
            "#
        )
        .bind(user_id)
        .bind(version)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to get KEK by version: {}", e)))?;

        Ok(row.map(|r| StoredKek {
            user_id: r.get("user_id"),
            version: r.get("kek_version"),
            kek_plaintext: r.get("kek_plaintext"),
            status: KekStatus::from_str(r.get("status")).unwrap_or(KekStatus::Active),
            created_at: r.get("created_at"),
            last_accessed_at: r.get("last_accessed_at"),
            last_rotated_at: r.get("last_rotated_at"),
        }))
    }

    /// Store a new KEK (plaintext, will be encrypted at rest by database)
    pub async fn store_kek(&self, kek: &StoredKek) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO user_keks (user_id, kek_version, kek_plaintext, status, created_at)
            VALUES ($1, $2, $3, $4::key_status, $5)
            "#
        )
        .bind(kek.user_id)
        .bind(kek.version)
        .bind(&kek.kek_plaintext)
        .bind(kek.status.to_str())
        .bind(kek.created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to store KEK: {}", e)))?;

        Ok(())
    }

    /// Disable KEK (calls SQL function)
    /// Changes status to DISABLED. Only RETIRED KEKs can be disabled.
    /// Returns true if status changed, false if already disabled.
    pub async fn disable_kek(&self, user_id: &Uuid, version: i64) -> Result<bool> {
        let row = sqlx::query(
            r#"
            SELECT disable_kek($1, $2) as result
            "#
        )
        .bind(user_id)
        .bind(version)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to disable KEK: {}", e)))?;

        Ok(row.get("result"))
    }

    /// Delete KEK (calls SQL function)
    /// Only deletes if status is DISABLED, otherwise raises exception.
    /// Returns true if deleted, false if not found.
    pub async fn delete_kek(&self, user_id: &Uuid, version: i64) -> Result<bool> {
        let row = sqlx::query(
            r#"
            SELECT delete_kek($1, $2) as result
            "#
        )
        .bind(user_id)
        .bind(version)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to delete KEK: {}", e)))?;

        Ok(row.get("result"))
    }

    /// Mark all ACTIVE KEKs as RETIRED (first step of bulk rotation)
    /// Returns count of KEKs marked as RETIRED
    pub async fn mark_all_active_keks_as_retired(&self) -> Result<i64> {
        let row = sqlx::query(
            r#"
            SELECT mark_all_active_keks_as_retired() as count
            "#
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to mark KEKs as retired: {}", e)))?;

        Ok(row.get("count"))
    }

    /// Get batch of RETIRED KEKs for rotation (calls SQL function)
    /// Uses SKIP LOCKED for concurrent rotation workers
    pub async fn get_retired_keks_batch(&self, batch_size: i32) -> Result<Vec<StoredKek>> {
        let rows = sqlx::query(
            r#"
            SELECT user_id, kek_version, kek_plaintext, status::TEXT as status, created_at, last_accessed_at, last_rotated_at
            FROM get_retired_keks_batch($1)
            "#
        )
        .bind(batch_size)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to get retired KEKs batch: {}", e)))?;

        Ok(rows.iter().map(|r| StoredKek {
            user_id: r.get("user_id"),
            version: r.get("kek_version"),
            kek_plaintext: r.get("kek_plaintext"),
            status: KekStatus::from_str(r.get("status")).unwrap_or(KekStatus::Retired),
            created_at: r.get("created_at"),
            last_accessed_at: r.get("last_accessed_at"),
            last_rotated_at: r.get("last_rotated_at"),
        }).collect())
    }

    /// Rotate single KEK (calls SQL function)
    /// Marks old KEK as RETIRED, creates new ACTIVE KEK
    /// Returns new version number
    pub async fn rotate_kek(&self, user_id: &Uuid, old_version: i64, new_kek: &[u8]) -> Result<i64> {
        let row = sqlx::query(
            r#"
            SELECT rotate_kek($1, $2, $3) as new_version
            "#
        )
        .bind(user_id)
        .bind(old_version)
        .bind(new_kek)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to rotate KEK: {}", e)))?;

        Ok(row.get("new_version"))
    }

    /// Get KEK statistics (calls SQL function)
    pub async fn get_kek_stats(&self) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query(
            r#"
            SELECT status::TEXT, count FROM get_kek_stats()
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to get KEK stats: {}", e)))?;

        Ok(rows.iter().map(|r| (r.get("status"), r.get("count"))).collect())
    }
}

/// KEK lifecycle status (matches database ENUM)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KekStatus {
    Active,    // Current KEK for user (encrypt + decrypt)
    Retired,   // Old KEK version (decrypt only)
    Disabled,  // Marked for deletion (no active EDEKs)
}

impl KekStatus {
    pub fn to_str(&self) -> &'static str {
        match self {
            KekStatus::Active => "ACTIVE",
            KekStatus::Retired => "RETIRED",
            KekStatus::Disabled => "DISABLED",
        }
    }
}

impl FromStr for KekStatus {
    type Err = EnvelopeError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "ACTIVE" => Ok(KekStatus::Active),
            "RETIRED" => Ok(KekStatus::Retired),
            "DISABLED" => Ok(KekStatus::Disabled),
            _ => Err(EnvelopeError::Storage(format!("Invalid KEK status: {}", s))),
        }
    }
}

/// Stored KEK (database encrypted at rest)
/// KEK stored as plaintext (32 bytes), encrypted at rest by database encryption
#[derive(Debug, Clone)]
pub struct StoredKek {
    pub user_id: Uuid,
    pub version: i64,
    pub kek_plaintext: Vec<u8>,  // KEK as plaintext (32 bytes), database encrypts at rest
    pub status: KekStatus,
    pub created_at: DateTime<Utc>,
    pub last_accessed_at: Option<DateTime<Utc>>,
    pub last_rotated_at: Option<DateTime<Utc>>,
}

/// Stored DEK (EDEK = Encrypted DEK by KEK)
/// Production AEAD format: edek_blob = nonce || ciphertext || tag (60 bytes total)
#[derive(Debug, Clone)]
pub struct StoredDek {
    pub dek_id: Uuid,
    pub user_id: Uuid,
    pub kek_version: i64,
    pub edek_blob: Vec<u8>,  // AEAD format: nonce(12) || ciphertext(32) || tag(16) = 60 bytes
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}
