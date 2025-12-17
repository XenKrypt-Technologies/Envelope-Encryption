use sqlx::{PgPool, Row};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::error::{EnvelopeError, Result};

/// Simplified PostgreSQL storage - ONLY stores EKEKs (encrypted KEKs)
///
/// Architecture:
/// - Database: Stores ONLY user KEKs encrypted by Server Key (EKEK)
/// - Memory: DEKs and EDEKs are generated on-demand, never persisted
/// - Testing: In-memory cache can hold DEK/EDEK for testing purposes
///
/// Strict requirements:
/// - No plaintext keys stored
/// - Only EKEK (KEK encrypted by Server Key) persisted to database
/// - DEKs generated fresh for each operation
/// - EDEKs created in-memory for testing only
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

    /// Get active KEK (EKEK) for a user
    pub async fn get_active_kek(&self, user_id: &Uuid) -> Result<Option<StoredKek>> {
        let row = sqlx::query(
            r#"
            SELECT user_id, version, ekek_ciphertext, ekek_nonce, created_at, is_active
            FROM user_keks
            WHERE user_id = $1 AND is_active = TRUE
            "#
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to get active KEK: {}", e)))?;

        Ok(row.map(|r| StoredKek {
            user_id: r.get("user_id"),
            version: r.get("version"),
            ekek_ciphertext: r.get("ekek_ciphertext"),
            ekek_nonce: r.get("ekek_nonce"),
            created_at: r.get("created_at"),
            is_active: r.get("is_active"),
        }))
    }

    /// Get specific KEK version for a user
    pub async fn get_kek_by_version(&self, user_id: &Uuid, version: i32) -> Result<Option<StoredKek>> {
        let row = sqlx::query(
            r#"
            SELECT user_id, version, ekek_ciphertext, ekek_nonce, created_at, is_active
            FROM user_keks
            WHERE user_id = $1 AND version = $2
            "#
        )
        .bind(user_id)
        .bind(version)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to get KEK by version: {}", e)))?;

        Ok(row.map(|r| StoredKek {
            user_id: r.get("user_id"),
            version: r.get("version"),
            ekek_ciphertext: r.get("ekek_ciphertext"),
            ekek_nonce: r.get("ekek_nonce"),
            created_at: r.get("created_at"),
            is_active: r.get("is_active"),
        }))
    }

    /// Get all KEKs for a user (all versions)
    pub async fn get_all_user_keks(&self, user_id: &Uuid) -> Result<Vec<StoredKek>> {
        let rows = sqlx::query(
            r#"
            SELECT user_id, version, ekek_ciphertext, ekek_nonce, created_at, is_active
            FROM user_keks
            WHERE user_id = $1
            ORDER BY version DESC
            "#
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to get user KEKs: {}", e)))?;

        Ok(rows.iter().map(|r| StoredKek {
            user_id: r.get("user_id"),
            version: r.get("version"),
            ekek_ciphertext: r.get("ekek_ciphertext"),
            ekek_nonce: r.get("ekek_nonce"),
            created_at: r.get("created_at"),
            is_active: r.get("is_active"),
        }).collect())
    }

    /// Store a new KEK (EKEK)
    pub async fn store_kek(&self, kek: &StoredKek) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO user_keks (user_id, version, ekek_ciphertext, ekek_nonce, created_at, is_active)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#
        )
        .bind(&kek.user_id)
        .bind(kek.version)
        .bind(&kek.ekek_ciphertext)
        .bind(&kek.ekek_nonce)
        .bind(kek.created_at)
        .bind(kek.is_active)
        .execute(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to store KEK: {}", e)))?;

        Ok(())
    }

    /// Disable (deactivate) a KEK
    pub async fn disable_kek(&self, user_id: &Uuid, kek_version: i32) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE user_keks
            SET is_active = FALSE
            WHERE user_id = $1 AND version = $2
            "#
        )
        .bind(user_id)
        .bind(kek_version)
        .execute(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to disable KEK: {}", e)))?;

        Ok(())
    }

    /// Get all active KEKs for server key rotation
    /// When rotating server key, we need to rewrap all EKEKs
    pub async fn get_all_active_keks(&self) -> Result<Vec<StoredKek>> {
        let rows = sqlx::query(
            r#"
            SELECT user_id, version, ekek_ciphertext, ekek_nonce, created_at, is_active
            FROM user_keks
            WHERE is_active = TRUE
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to get all active KEKs: {}", e)))?;

        Ok(rows.iter().map(|r| StoredKek {
            user_id: r.get("user_id"),
            version: r.get("version"),
            ekek_ciphertext: r.get("ekek_ciphertext"),
            ekek_nonce: r.get("ekek_nonce"),
            created_at: r.get("created_at"),
            is_active: r.get("is_active"),
        }).collect())
    }
}

/// Stored KEK (EKEK = Encrypted KEK by Server Key)
/// This is the ONLY encrypted key material stored in the database
#[derive(Debug, Clone)]
pub struct StoredKek {
    pub user_id: Uuid,
    pub version: i32,
    pub ekek_ciphertext: Vec<u8>, // KEK encrypted by Server Key (includes GCM tag)
    pub ekek_nonce: Vec<u8>,      // 12-byte nonce
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}
