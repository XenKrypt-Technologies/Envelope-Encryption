# Quick Start - PostgreSQL Envelope Encryption

## 🚀 Setup (5 minutes)

### 1. Start PostgreSQL

```bash
docker run -d \
  --name envelope-pg \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 \
  postgres:15
```

### 2. Create Database

```bash
psql -U postgres -c "CREATE DATABASE envelope_encryption;"
```

### 3. Run Migrations

```bash
psql -U postgres -d envelope_encryption -f migrations/001_init_schema.sql
```

### 4. Configure Environment

```bash
# Generate Server Key (KEEP SECRET!)
SERVER_KEY=$(openssl rand -base64 32)

# Create .env file
cat > .env << EOF
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/envelope_encryption
SERVER_KEY_BASE64=$SERVER_KEY
SERVER_KEY_VERSION=1
EOF
```

### 5. Run Demo

```bash
# In-memory demo
cargo run

# PostgreSQL demo
cargo run -- --postgres
```

## 📝 Basic Usage

```rust
use envelope_encryption::{PostgresStorage, PostgresEnvelopeService};
use sqlx::PgPool;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv()?;

    // Connect
    let pool = PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
    let storage = PostgresStorage::new(pool);
    let service = PostgresEnvelopeService::new(storage).await?;

    // Generate DEK for user
    let user_id = Uuid::new_v4();
    let generated = service.generate_dek(&user_id).await?;

    println!("✓ Generated DEK: {}", generated.dek_id);
    println!("✓ KEK Version: {}", generated.kek_version);

    // Use DEK to encrypt data
    let plaintext = b"Sensitive data";
    let encrypted = AesGcmCipher::encrypt(
        &generated.dek,
        plaintext,
        Some(content_id.as_bytes())
    )?;

    // Later: Decrypt EDEK to recover DEK
    let recovered_dek = service.decrypt_edek(&generated.dek_id).await?;
    let decrypted = AesGcmCipher::decrypt(
        &recovered_dek,
        &encrypted,
        Some(content_id.as_bytes())
    )?;

    println!("✓ Decrypted: {:?}", String::from_utf8_lossy(&decrypted));

    Ok(())
}
```

## 🔑 Key Operations

### Generate DEK
```rust
let result = service.generate_dek(&user_id).await?;
// Returns: dek, edek_ciphertext, edek_nonce, tag, kek_version
```

### Decrypt EDEK
```rust
let dek = service.decrypt_edek(&dek_id).await?;
```

### Rotate User's KEK
```rust
let result = service.rotate_user_kek(&user_id).await?;
println!("Re-wrapped {} DEKs", result.deks_rewrapped);
```

### Disable Unused KEK
```rust
let disabled = service.disable_kek_if_unused(&user_id, kek_version).await?;
```

## 🗄️ Database Tables

| Table | Purpose |
|-------|---------|
| `server_keys` | Track Server Key versions |
| `user_keks` | Store EKEKs (KEK encrypted by Server Key) |
| `user_deks` | Store EDEKs (DEK encrypted by KEK) |

## 🔐 Security

**CRITICAL - Server Key:**
```bash
# Generate ONCE and KEEP SECRET
openssl rand -base64 32

# In production: Store in AWS KMS, Azure Key Vault, or HashiCorp Vault
# NEVER commit .env to version control
```

**Key Hierarchy:**
```
.env → Server Key (32B base64)
  ↓
PostgreSQL → EKEK (encrypted KEK)
  ↓
PostgreSQL → EDEK (encrypted DEK)
  ↓
Your App → Encrypted Data
```

## 📊 Monitoring Queries

```sql
-- Active KEKs per user
SELECT user_id, version, created_at
FROM user_keks
WHERE is_active = TRUE;

-- DEK count per KEK
SELECT user_id, kek_version, COUNT(*) as dek_count
FROM user_deks
WHERE is_active = TRUE
GROUP BY user_id, kek_version;

-- Server Key version
SELECT version, is_active
FROM server_keys
ORDER BY version DESC;
```

## ⚠️ Common Errors

**"SERVER_KEY_BASE64 not set"**
```bash
# Missing .env file
cp .env.example .env
# Then edit .env with your key
```

**"Cannot disable KEK: active DEKs still reference it"**
```bash
# This is correct behavior! KEKs cannot be disabled while DEKs use them.
# This prevents orphaning encrypted data.
```

**"Connection refused"**
```bash
# PostgreSQL not running
docker start envelope-pg
# Or check DATABASE_URL in .env
```

## 🧪 Testing

```bash
# Unit tests
cargo test

# Run both demos
cargo run                    # In-memory
cargo run -- --postgres      # PostgreSQL
```

## 📚 Documentation

- Full docs: `POSTGRES_README.md`
- Implementation: `IMPLEMENTATION_SUMMARY.md`
- Schema: `migrations/001_init_schema.sql`

## 🆘 Troubleshooting

1. **Build errors:** `cargo clean && cargo build`
2. **DB connection issues:** Check `DATABASE_URL` in `.env`
3. **Server key errors:** Ensure 32-byte base64 in `.env`
4. **Permission denied:** Check PostgreSQL user permissions

## ✅ Production Checklist

- [ ] Server Key in KMS/Vault (not `.env`)
- [ ] PostgreSQL over TLS
- [ ] Database backups enabled
- [ ] Monitoring and alerting configured
- [ ] Key rotation schedule established
- [ ] Audit logging enabled
- [ ] Security review completed

---

**Need help?** Check `POSTGRES_README.md` for detailed documentation.
