-- ============================================================================
-- PostgreSQL Schema for Envelope Encryption
--
-- Self-contained schema that drops and recreates the database with all tables,
-- functions, triggers, and constraints.
--
-- Usage:
--   psql -U postgres -f schema.sql
--
-- Architecture:
--   Server Key → KEK → DEK (in-memory only)
--
-- KEK Rotation Strategy:
--   1. Mark all ACTIVE KEKs as RETIRED
--   2. Rotate in bulk (50 at a time)
--   3. Lazy rotation on access (if RETIRED KEK accessed, rotate immediately)
--   4. Only ACTIVE KEK used for new encryptions
-- ============================================================================

-- Drop and recreate database
DROP DATABASE IF EXISTS envelope_encryption;
CREATE DATABASE envelope_encryption;

-- Connect to the new database
\c envelope_encryption

-- ============================================================================
-- ENUM: key_status
-- Purpose: KEK lifecycle management
-- ============================================================================
CREATE TYPE key_status AS ENUM (
    'ACTIVE',     -- Current KEK for user (encrypt + decrypt)
    'RETIRED',    -- Old KEK version (decrypt only, pending rotation)
    'DISABLED'    -- Marked for deletion (safe to delete)
);

COMMENT ON TYPE key_status IS
    'KEK lifecycle: ACTIVE (current), RETIRED (old, decrypt-only), DISABLED (safe to delete)';

-- ============================================================================
-- Table: user_keks
-- Purpose: Store per-user KEKs (plaintext, encrypted at rest by database encryption)
--
-- Note: No user_deks table - DEKs are in-memory only for testing
-- ============================================================================
CREATE TABLE user_keks (
    user_id UUID NOT NULL,
    kek_version BIGINT NOT NULL,

    -- KEK stored as raw bytes (32 bytes for AES-256)
    -- Database encryption handles encryption at rest
    kek_plaintext BYTEA NOT NULL CHECK (octet_length(kek_plaintext) = 32),

    -- KEK lifecycle status
    status key_status NOT NULL DEFAULT 'ACTIVE',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_accessed_at TIMESTAMPTZ,
    last_rotated_at TIMESTAMPTZ,

    PRIMARY KEY (user_id, kek_version),

    -- Ensure only one ACTIVE KEK per user at any time
    CONSTRAINT one_active_kek_per_user EXCLUDE (user_id WITH =)
        WHERE (status = 'ACTIVE')
);

-- Performance-critical index: Find ACTIVE KEK for user (hot path)
CREATE UNIQUE INDEX idx_user_keks_active
    ON user_keks(user_id)
    WHERE status = 'ACTIVE';

-- Index for bulk rotation: Find RETIRED KEKs
CREATE INDEX idx_user_keks_retired_for_rotation
    ON user_keks(status, last_accessed_at)
    WHERE status = 'RETIRED';

-- Index for finding KEKs by version
CREATE INDEX idx_user_keks_user_version
    ON user_keks(user_id, kek_version);

-- ============================================================================
-- Security Constraints and Triggers
-- ============================================================================

-- Prevent deletion of ACTIVE or RETIRED KEKs
CREATE OR REPLACE FUNCTION prevent_active_retired_kek_deletion()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status IN ('ACTIVE', 'RETIRED') THEN
        RAISE EXCEPTION 'Cannot delete % KEK (user=%, version=%). Must be DISABLED first.',
            OLD.status, OLD.user_id, OLD.kek_version;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_prevent_active_retired_kek_deletion
    BEFORE DELETE ON user_keks
    FOR EACH ROW
    EXECUTE FUNCTION prevent_active_retired_kek_deletion();

-- Update last_accessed_at on KEK read
CREATE OR REPLACE FUNCTION update_kek_last_accessed()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_accessed_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_kek_last_accessed
    BEFORE UPDATE ON user_keks
    FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status OR OLD.kek_plaintext IS DISTINCT FROM NEW.kek_plaintext)
    EXECUTE FUNCTION update_kek_last_accessed();

-- ============================================================================
-- KEK Management Functions
-- ============================================================================

-- Function: Get ACTIVE KEK for user
CREATE OR REPLACE FUNCTION get_active_kek(p_user_id UUID)
RETURNS TABLE (
    user_id UUID,
    kek_version BIGINT,
    kek_plaintext BYTEA,
    status key_status,
    created_at TIMESTAMPTZ,
    last_accessed_at TIMESTAMPTZ,
    last_rotated_at TIMESTAMPTZ
) AS $$
    SELECT user_id, kek_version, kek_plaintext, status, created_at, last_accessed_at, last_rotated_at
    FROM user_keks
    WHERE user_keks.user_id = p_user_id AND status = 'ACTIVE'
    LIMIT 1;
$$ LANGUAGE SQL STABLE;

COMMENT ON FUNCTION get_active_kek IS
    'Returns the active KEK for a user. Uses idx_user_keks_active index for fast lookup.';

-- Function: Get KEK by version (for decrypting old EDEKs)
CREATE OR REPLACE FUNCTION get_kek_by_version(p_user_id UUID, p_version BIGINT)
RETURNS TABLE (
    user_id UUID,
    kek_version BIGINT,
    kek_plaintext BYTEA,
    status key_status,
    created_at TIMESTAMPTZ,
    last_accessed_at TIMESTAMPTZ,
    last_rotated_at TIMESTAMPTZ
) AS $$
    SELECT user_id, kek_version, kek_plaintext, status, created_at, last_accessed_at, last_rotated_at
    FROM user_keks
    WHERE user_keks.user_id = p_user_id AND user_keks.kek_version = p_version
    LIMIT 1;
$$ LANGUAGE SQL STABLE;

COMMENT ON FUNCTION get_kek_by_version IS
    'Returns a specific KEK version for a user. Used for decrypting EDEKs with older KEKs.';

-- Function: Disable KEK (mark as DISABLED)
CREATE OR REPLACE FUNCTION disable_kek(p_user_id UUID, p_version BIGINT)
RETURNS BOOLEAN AS $$
DECLARE
    v_current_status key_status;
BEGIN
    -- Get current status
    SELECT status INTO v_current_status
    FROM user_keks
    WHERE user_id = p_user_id AND kek_version = p_version;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'KEK not found: user_id=%, version=%', p_user_id, p_version;
    END IF;

    IF v_current_status = 'ACTIVE' THEN
        RAISE EXCEPTION 'Cannot disable ACTIVE KEK. Rotate to a new version first.';
    END IF;

    IF v_current_status = 'DISABLED' THEN
        RETURN FALSE; -- Already disabled
    END IF;

    -- Mark as DISABLED
    UPDATE user_keks
    SET status = 'DISABLED',
        last_accessed_at = NOW()
    WHERE user_id = p_user_id AND kek_version = p_version;

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION disable_kek IS
    'Marks a KEK as DISABLED. Only RETIRED KEKs can be disabled. Returns TRUE if status changed, FALSE if already disabled.';

-- Function: Delete KEK (only if DISABLED)
CREATE OR REPLACE FUNCTION delete_kek(p_user_id UUID, p_version BIGINT)
RETURNS BOOLEAN AS $$
DECLARE
    v_status key_status;
BEGIN
    -- Get current status
    SELECT status INTO v_status
    FROM user_keks
    WHERE user_id = p_user_id AND kek_version = p_version;

    IF NOT FOUND THEN
        RETURN FALSE; -- KEK doesn't exist
    END IF;

    IF v_status != 'DISABLED' THEN
        RAISE EXCEPTION 'Cannot delete KEK with status %. Must be DISABLED first. (user_id=%, version=%)',
            v_status, p_user_id, p_version;
    END IF;

    -- Delete the KEK
    DELETE FROM user_keks
    WHERE user_id = p_user_id AND kek_version = p_version;

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION delete_kek IS
    'Deletes a KEK only if status is DISABLED. Returns TRUE if deleted, FALSE if not found. Raises exception if not DISABLED.';

-- Function: Mark all ACTIVE KEKs as RETIRED (preparation for rotation)
CREATE OR REPLACE FUNCTION mark_all_active_keks_as_retired()
RETURNS BIGINT AS $$
DECLARE
    v_count BIGINT;
BEGIN
    UPDATE user_keks
    SET status = 'RETIRED',
        last_accessed_at = NOW()
    WHERE status = 'ACTIVE';

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION mark_all_active_keks_as_retired IS
    'Marks ALL active KEKs as RETIRED. Used as first step in bulk rotation. Returns count of KEKs marked.';

-- Function: Get batch of RETIRED KEKs for rotation
-- IMPORTANT: Only returns the LATEST (max version) RETIRED KEK per user
-- AND only for users who don't already have an ACTIVE KEK (need rotation)
-- This prevents infinite loops when rotating
CREATE OR REPLACE FUNCTION get_retired_keks_batch(p_batch_size INTEGER DEFAULT 50)
RETURNS TABLE (
    user_id UUID,
    kek_version BIGINT,
    kek_plaintext BYTEA,
    status key_status,
    created_at TIMESTAMPTZ,
    last_accessed_at TIMESTAMPTZ,
    last_rotated_at TIMESTAMPTZ
) AS $$
    WITH latest_retired AS (
        SELECT
            user_keks.user_id,
            MAX(user_keks.kek_version) as max_version
        FROM user_keks
        WHERE user_keks.status = 'RETIRED'
        -- Only include users who don't have an ACTIVE KEK (need rotation)
        AND NOT EXISTS (
            SELECT 1 FROM user_keks active
            WHERE active.user_id = user_keks.user_id
            AND active.status = 'ACTIVE'
        )
        GROUP BY user_keks.user_id
    )
    SELECT k.user_id, k.kek_version, k.kek_plaintext, k.status, k.created_at, k.last_accessed_at, k.last_rotated_at
    FROM user_keks k
    INNER JOIN latest_retired lr ON k.user_id = lr.user_id AND k.kek_version = lr.max_version
    WHERE k.status = 'RETIRED'
    ORDER BY k.last_accessed_at ASC NULLS FIRST
    LIMIT p_batch_size
    FOR UPDATE OF k SKIP LOCKED;  -- Lock for update, skip if already locked
$$ LANGUAGE SQL;

COMMENT ON FUNCTION get_retired_keks_batch IS
    'Returns a batch of RETIRED KEKs for rotation. Only returns the LATEST (max version) RETIRED KEK per user to avoid conflicts. Uses SKIP LOCKED for concurrent rotation workers. Default batch size: 50.';

-- Function: Rotate single KEK (create new ACTIVE version)
CREATE OR REPLACE FUNCTION rotate_kek(p_user_id UUID, p_old_version BIGINT, p_new_kek BYTEA)
RETURNS BIGINT AS $$
DECLARE
    v_new_version BIGINT;
    v_current_status key_status;
BEGIN
    -- Validate new KEK size
    IF octet_length(p_new_kek) != 32 THEN
        RAISE EXCEPTION 'Invalid KEK size: expected 32 bytes, got %', octet_length(p_new_kek);
    END IF;

    -- Check old KEK status
    SELECT status INTO v_current_status
    FROM user_keks
    WHERE user_id = p_user_id AND kek_version = p_old_version;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Old KEK not found: user_id=%, version=%', p_user_id, p_old_version;
    END IF;

    IF v_current_status = 'DISABLED' THEN
        RAISE EXCEPTION 'Cannot rotate from DISABLED KEK';
    END IF;

    -- Calculate new version
    v_new_version := p_old_version + 1;

    -- Mark old KEK as RETIRED (if not already)
    UPDATE user_keks
    SET status = 'RETIRED',
        last_accessed_at = NOW()
    WHERE user_id = p_user_id AND kek_version = p_old_version AND status != 'RETIRED';

    -- Insert new ACTIVE KEK
    INSERT INTO user_keks (user_id, kek_version, kek_plaintext, status, created_at, last_rotated_at)
    VALUES (p_user_id, v_new_version, p_new_kek, 'ACTIVE', NOW(), NOW())
    ON CONFLICT (user_id, kek_version) DO UPDATE
    SET kek_plaintext = EXCLUDED.kek_plaintext,
        status = 'ACTIVE',
        last_rotated_at = NOW();

    RETURN v_new_version;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION rotate_kek IS
    'Rotates a single KEK: marks old as RETIRED, creates new ACTIVE version. Returns new version number.';

-- ============================================================================
-- Statistics and Monitoring
-- ============================================================================

-- Function: Get KEK statistics
CREATE OR REPLACE FUNCTION get_kek_stats()
RETURNS TABLE (
    status key_status,
    count BIGINT
) AS $$
    SELECT status, COUNT(*)
    FROM user_keks
    GROUP BY status
    ORDER BY status;
$$ LANGUAGE SQL STABLE;

COMMENT ON FUNCTION get_kek_stats IS
    'Returns count of KEKs by status. Useful for monitoring rotation progress.';

-- ============================================================================
-- Comments for documentation
-- ============================================================================

COMMENT ON TABLE user_keks IS
    'Stores per-user KEKs as plaintext (32 bytes). Database encryption handles encryption at rest. No user_deks table - DEKs are in-memory only.';

COMMENT ON COLUMN user_keks.kek_plaintext IS
    'KEK stored as plaintext (32 bytes for AES-256). Encrypted at rest by database encryption.';

COMMENT ON COLUMN user_keks.status IS
    'KEK lifecycle: ACTIVE (current, encrypt+decrypt), RETIRED (old, decrypt-only), DISABLED (safe to delete).';

COMMENT ON COLUMN user_keks.last_rotated_at IS
    'Timestamp when this KEK was last rotated (when new version was created from this one).';

-- ============================================================================
-- Example Rotation Workflow
-- ============================================================================

COMMENT ON SCHEMA public IS
    'KEK Rotation Workflow:

1. Mark all ACTIVE KEKs as RETIRED:
   SELECT mark_all_active_keks_as_retired();

2. Rotate in batches of 50:
   LOOP
     -- Get batch
     batch = SELECT * FROM get_retired_keks_batch(50);
     IF batch IS EMPTY THEN EXIT;

     -- For each KEK in batch
     FOR kek IN batch LOOP
       new_kek = generate_random_32_bytes();
       SELECT rotate_kek(kek.user_id, kek.kek_version, new_kek);
     END LOOP;
   END LOOP;

3. Lazy rotation on access:
   kek = get_kek_by_version(user_id, version);
   IF kek.status = RETIRED THEN
     new_kek = generate_random_32_bytes();
     new_version = rotate_kek(user_id, version, new_kek);
     -- Use new_version for subsequent operations
   END IF;

4. Cleanup old KEKs:
   -- After all EDEKs migrated
   SELECT disable_kek(user_id, old_version);  -- Mark as DISABLED
   SELECT delete_kek(user_id, old_version);    -- Delete if DISABLED
';

-- ============================================================================
-- Schema setup complete
-- ============================================================================
