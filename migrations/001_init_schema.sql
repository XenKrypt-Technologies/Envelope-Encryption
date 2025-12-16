-- PostgreSQL Schema for Envelope Encryption
-- Strict requirements: Server Key -> KEK -> DEK hierarchy
-- All encrypted keys stored with nonce and tag

-- ============================================================================
-- Table: server_keys
-- Purpose: Track Server Key versions (key itself stored in .env)
-- ============================================================================
CREATE TABLE server_keys (
    version INTEGER PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    -- No plaintext key stored, only version tracking
    CONSTRAINT only_one_active CHECK (
        is_active = FALSE OR
        version = (SELECT version FROM server_keys WHERE is_active = TRUE LIMIT 1)
    )
);

-- Index for finding active server key quickly
CREATE INDEX idx_server_keys_active ON server_keys(is_active) WHERE is_active = TRUE;

-- ============================================================================
-- Table: user_keks
-- Purpose: Store per-user KEKs encrypted by Server Key (EKEK)
-- ============================================================================
CREATE TABLE user_keks (
    user_id UUID NOT NULL,
    version INTEGER NOT NULL,
    server_key_version INTEGER NOT NULL REFERENCES server_keys(version),

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

-- Index for finding KEKs by server key version (needed for server key rotation)
CREATE INDEX idx_user_keks_server_version ON user_keks(server_key_version);

-- ============================================================================
-- Table: user_deks
-- Purpose: Store per-encryption DEKs encrypted by user's KEK (EDEK)
-- ============================================================================
CREATE TABLE user_deks (
    dek_id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    kek_version INTEGER NOT NULL,
    content_id UUID, -- Optional content ID

    -- EDEK = Encrypted DEK (encrypted by user's KEK)
    edek_ciphertext BYTEA NOT NULL, -- DEK encrypted by KEK (includes GCM tag)
    edek_nonce BYTEA NOT NULL CHECK (octet_length(edek_nonce) = 12),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    -- Foreign key to user's KEK
    FOREIGN KEY (user_id, kek_version) REFERENCES user_keks(user_id, version)
        ON DELETE RESTRICT -- Cannot delete KEK while DEKs reference it
);

-- Performance-critical indexes
CREATE INDEX idx_user_deks_user_kek ON user_deks(user_id, kek_version);
CREATE INDEX idx_user_deks_content_id ON user_deks(content_id) WHERE content_id IS NOT NULL;

-- ============================================================================
-- Function: Prevent KEK deletion if DEKs reference it
-- ============================================================================
CREATE OR REPLACE FUNCTION check_kek_has_no_deks()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.is_active = TRUE AND NEW.is_active = FALSE THEN
        IF EXISTS (
            SELECT 1 FROM user_deks
            WHERE user_id = OLD.user_id
              AND kek_version = OLD.version
              AND is_active = TRUE
        ) THEN
            RAISE EXCEPTION 'Cannot disable KEK: active DEKs still reference it (user_id=%, version=%)',
                OLD.user_id, OLD.version;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER prevent_kek_disable_with_deks
    BEFORE UPDATE ON user_keks
    FOR EACH ROW
    EXECUTE FUNCTION check_kek_has_no_deks();

-- ============================================================================
-- Initial Server Key Version
-- ============================================================================
INSERT INTO server_keys (version, is_active) VALUES (1, TRUE);

-- ============================================================================
-- Comments for documentation
-- ============================================================================
COMMENT ON TABLE server_keys IS 'Tracks Server Key versions. Actual key stored in .env as base64.';
COMMENT ON TABLE user_keks IS 'Stores per-user KEKs encrypted by Server Key (EKEK). AAD = user_id.';
COMMENT ON TABLE user_deks IS 'Stores per-encryption DEKs encrypted by user KEK (EDEK). AAD = dek_id.';

COMMENT ON COLUMN user_keks.ekek_ciphertext IS 'KEK encrypted by Server Key using AES-256-GCM (includes 16-byte auth tag)';
COMMENT ON COLUMN user_keks.ekek_nonce IS '12-byte nonce for AES-GCM encryption of KEK';

COMMENT ON COLUMN user_deks.edek_ciphertext IS 'DEK encrypted by user KEK using AES-256-GCM (includes 16-byte auth tag)';
COMMENT ON COLUMN user_deks.edek_nonce IS '12-byte nonce for AES-GCM encryption of DEK';
