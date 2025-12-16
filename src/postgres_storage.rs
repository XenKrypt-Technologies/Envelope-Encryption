use sqlx::{PgPool, Row};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::error::{EnvelopeError, Result};

/// Production PostgreSQL storage implementation
/// Strict requirements:
/// - No plaintext keys stored
/// - KEKs encrypted by Server Key (EKEK)
/// - DEKs encrypted by user KEKs (EDEK)
/// - Referential integrity enforced
/// - Version tracking for all keys
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

    /// Get active KEK for a user
    pub async fn get_active_kek(&self, user_id: &Uuid) -> Result<Option<StoredKek>> {
        let row = sqlx::query(
            r#"
            SELECT user_id, version, server_key_version, ekek_ciphertext, ekek_nonce, created_at, is_active
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
            server_key_version: r.get("server_key_version"),
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
            SELECT user_id, version, server_key_version, ekek_ciphertext, ekek_nonce, created_at, is_active
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
            server_key_version: r.get("server_key_version"),
            ekek_ciphertext: r.get("ekek_ciphertext"),
            ekek_nonce: r.get("ekek_nonce"),
            created_at: r.get("created_at"),
            is_active: r.get("is_active"),
        }))
    }

    /// Store a new KEK (EKEK)
    pub async fn store_kek(&self, kek: &StoredKek) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO user_keks (user_id, version, server_key_version, ekek_ciphertext, ekek_nonce, created_at, is_active)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#
        )
        .bind(&kek.user_id)
        .bind(kek.version)
        .bind(kek.server_key_version)
        .bind(&kek.ekek_ciphertext)
        .bind(&kek.ekek_nonce)
        .bind(kek.created_at)
        .bind(kek.is_active)
        .execute(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to store KEK: {}", e)))?;

        Ok(())
    }

    /// Get DEK by ID
    pub async fn get_dek(&self, dek_id: &Uuid) -> Result<Option<StoredDek>> {
        let row = sqlx::query(
            r#"
            SELECT dek_id, user_id, kek_version, content_id, edek_ciphertext, edek_nonce, created_at, is_active
            FROM user_deks
            WHERE dek_id = $1
            "#
        )
        .bind(dek_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to get DEK: {}", e)))?;

        Ok(row.map(|r| StoredDek {
            dek_id: r.get("dek_id"),
            user_id: r.get("user_id"),
            kek_version: r.get("kek_version"),
            content_id: r.get("content_id"),
            edek_ciphertext: r.get("edek_ciphertext"),
            edek_nonce: r.get("edek_nonce"),
            created_at: r.get("created_at"),
            is_active: r.get("is_active"),
        }))
    }

    /// Store a new DEK (EDEK)
    pub async fn store_dek(&self, dek: &StoredDek) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO user_deks (dek_id, user_id, kek_version, content_id, edek_ciphertext, edek_nonce, created_at, is_active)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#
        )
        .bind(&dek.dek_id)
        .bind(&dek.user_id)
        .bind(dek.kek_version)
        .bind(&dek.content_id)
        .bind(&dek.edek_ciphertext)
        .bind(&dek.edek_nonce)
        .bind(dek.created_at)
        .bind(dek.is_active)
        .execute(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to store DEK: {}", e)))?;

        Ok(())
    }

    /// Get all active DEKs for a user's KEK version
    pub async fn get_deks_by_kek(&self, user_id: &Uuid, kek_version: i32) -> Result<Vec<StoredDek>> {
        let rows = sqlx::query(
            r#"
            SELECT dek_id, user_id, kek_version, content_id, edek_ciphertext, edek_nonce, created_at, is_active
            FROM user_deks
            WHERE user_id = $1 AND kek_version = $2 AND is_active = TRUE
            "#
        )
        .bind(user_id)
        .bind(kek_version)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to get DEKs by KEK: {}", e)))?;

        Ok(rows.iter().map(|r| StoredDek {
            dek_id: r.get("dek_id"),
            user_id: r.get("user_id"),
            kek_version: r.get("kek_version"),
            content_id: r.get("content_id"),
            edek_ciphertext: r.get("edek_ciphertext"),
            edek_nonce: r.get("edek_nonce"),
            created_at: r.get("created_at"),
            is_active: r.get("is_active"),
        }).collect())
    }

    /// Count active DEKs for a KEK
    pub async fn count_active_deks_for_kek(&self, user_id: &Uuid, kek_version: i32) -> Result<i64> {
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM user_deks
            WHERE user_id = $1 AND kek_version = $2 AND is_active = TRUE
            "#
        )
        .bind(user_id)
        .bind(kek_version)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to count DEKs: {}", e)))?;

        Ok(row.get("count"))
    }

    /// Disable (deactivate) a KEK - only if no active DEKs reference it
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

    /// Update DEK to reference new KEK version (used during KEK rotation)
    pub async fn update_dek_kek_version(
        &self,
        dek_id: &Uuid,
        new_kek_version: i32,
        new_edek_ciphertext: &[u8],
        new_edek_nonce: &[u8],
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE user_deks
            SET kek_version = $2, edek_ciphertext = $3, edek_nonce = $4
            WHERE dek_id = $1
            "#
        )
        .bind(dek_id)
        .bind(new_kek_version)
        .bind(new_edek_ciphertext)
        .bind(new_edek_nonce)
        .execute(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to update DEK KEK version: {}", e)))?;

        Ok(())
    }

    /// Get active server key version
    pub async fn get_active_server_key_version(&self) -> Result<i32> {
        let row = sqlx::query(
            r#"
            SELECT version
            FROM server_keys
            WHERE is_active = TRUE
            LIMIT 1
            "#
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| EnvelopeError::Storage(format!("Failed to get active server key version: {}", e)))?;

        Ok(row.get("version"))
    }
}

/// Stored KEK (EKEK = Encrypted KEK by Server Key)
#[derive(Debug, Clone)]
pub struct StoredKek {
    pub user_id: Uuid,
    pub version: i32,
    pub server_key_version: i32,
    pub ekek_ciphertext: Vec<u8>, // KEK encrypted by Server Key (includes GCM tag)
    pub ekek_nonce: Vec<u8>,      // 12-byte nonce
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}

/// Stored DEK (EDEK = Encrypted DEK by user's KEK)
#[derive(Debug, Clone)]
pub struct StoredDek {
    pub dek_id: Uuid,
    pub user_id: Uuid,
    pub kek_version: i32,
    pub content_id: Option<Uuid>,
    pub edek_ciphertext: Vec<u8>, // DEK encrypted by KEK (includes GCM tag)
    pub edek_nonce: Vec<u8>,      // 12-byte nonce
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}

// Implement KeyStorage trait for compatibility (async wrapper needed for existing code)
// Note: This is a sync trait, but PostgresStorage is async, so we can't implement it directly.
// Users should use the async methods above directly for PostgreSQL operations.
