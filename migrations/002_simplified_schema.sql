-- Simplified PostgreSQL Schema for Envelope Encryption
-- Database stores ONLY EKEKs (encrypted KEKs)
-- DEKs and EDEKs are generated and handled entirely in memory

-- ============================================================================
-- Drop old tables if migrating from previous version
-- ============================================================================
DROP TABLE IF EXISTS user_deks;
DROP TRIGGER IF EXISTS prevent_kek_disable_with_deks ON user_keks;
DROP FUNCTION IF EXISTS check_kek_has_no_deks();

-- ============================================================================
-- Table: server_keys (unchanged)
-- Purpose: Track Server Key versions (key itself stored in .env)
-- ============================================================================
-- Already exists from 001_init_schema.sql

-- ============================================================================
-- Table: user_keks (simplified)
-- Purpose: Store per-user KEKs encrypted by Server Key (EKEK)
-- Note: This is the ONLY encrypted key material stored in database
-- ============================================================================
ALTER TABLE user_keks DROP CONSTRAINT IF EXISTS one_active_kek_per_user;

-- Recreate constraint without DEFERRABLE (simpler)
ALTER TABLE user_keks ADD CONSTRAINT one_active_kek_per_user
    UNIQUE (user_id) WHERE (is_active = TRUE);

-- Update comment to reflect new architecture
COMMENT ON TABLE user_keks IS 'Stores per-user KEKs encrypted by Server Key (EKEK). DEKs/EDEKs are in-memory only.';

-- ============================================================================
-- Notes
-- ============================================================================
-- DEKs: Generated in-memory on demand, never stored
-- EDEKs: Created in-memory for testing, never persisted
-- KEKs: Retrieved from database, decrypted in-memory for use
-- EKEK: Only encrypted material in database
