# Quick Start Guide

## Setup PostgreSQL (Linux)

```bash
# 1. Create database
psql -U postgres -c "CREATE DATABASE envelope_encryption;"

# 2. Run migration
psql -U postgres -d envelope_encryption -f migrations/001_init_schema.sql

# 3. Verify
psql -U postgres -d envelope_encryption -c "\dt"
```

Expected output:
```
 Schema |   Name    | Type  |  Owner
--------+-----------+-------+----------
 public | user_keks | table | postgres
```

## Configure

Update `.env` with your database password:
```bash
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/envelope_encryption
SERVER_KEY_BASE64=JEVim9SuHAvJQ/6++itTa/2PIUylMtpbhZ/E41cJc+o=
```

## Run

```bash
cargo run
```

## What's Stored Where

| Item | Location | Purpose |
|------|----------|---------|
| **EKEK** | PostgreSQL `user_keks` | Encrypted KEKs |
| **KEK** | Memory only | Decrypt/encrypt DEKs |
| **DEK** | Memory only | Encrypt data |
| **EDEK** | Memory cache | Testing only |

## Database Schema

```sql
CREATE TABLE user_keks (
    user_id UUID NOT NULL,
    version INTEGER NOT NULL,
    ekek_ciphertext BYTEA NOT NULL,  -- KEK + GCM tag
    ekek_nonce BYTEA NOT NULL,       -- 12 bytes
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (user_id, version)
);
```

That's it! Simple and clean.
