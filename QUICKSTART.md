# Quick Start Guide

## Setup PostgreSQL (Linux)

```bash
# Run schema (this will drop and recreate the database)
psql -U postgres -f schema.sql
```

Expected output:
```
DROP DATABASE
CREATE DATABASE
You are now connected to database "envelope_encryption" as user "postgres".
CREATE TYPE
CREATE TABLE
...
```

## Configure

Update `.env` with your database password:
```bash
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/envelope_encryption
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
