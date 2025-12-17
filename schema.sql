-- PostgreSQL Schema for Envelope Encryption
-- Simplified: No server key versioning, just rewrap all KEKs on rotation

-- ============================================================================
-- Table: user_keks
-- Purpose: Store per-user KEKs encrypted by Server Key (EKEK)
-- Note: Server key itself is in .env, no version tracking needed
-- ============================================================================
CREATE TABLE user_keks (
    user_id UUID NOT NULL,
    version INTEGER NOT NULL,

    -- EKEK = Encrypted KEK (encrypted by Server Key)
    ekek_ciphertext BYTEA NOT NULL, -- KEK encrypted by Server Key (includes GCM tag)
    ekek_nonce BYTEA NOT NULL CHECK (octet_length(ekek_nonce) = 12),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    PRIMARY KEY (user_id, version),

    -- Only one active KEK per user
    CONSTRAINT one_active_kek_per_user UNIQUE (user_id, is_active)
        DEFERRABLE INITIALLY DEFERRED
);

-- Performance-critical index: Find active KEK for user
CREATE UNIQUE INDEX idx_user_keks_active ON user_keks(user_id) WHERE is_active = TRUE;

-- ============================================================================
-- Comments for documentation
-- ============================================================================
COMMENT ON TABLE user_keks IS 'Stores per-user KEKs encrypted by Server Key (EKEK). AAD = user_id.';

COMMENT ON COLUMN user_keks.ekek_ciphertext IS 'KEK encrypted by Server Key using AES-256-GCM (includes 16-byte auth tag)';
COMMENT ON COLUMN user_keks.ekek_nonce IS '12-byte nonce for AES-GCM encryption of KEK';
