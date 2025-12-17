/// Envelope Encryption Demo - PostgreSQL Backend Only
///
/// Usage:
///   cargo run                    # PostgreSQL demo
///
/// PostgreSQL setup:
///   1. Run automated setup: .\setup_windows_db.ps1
///   OR
///   2. Manual setup:
///      - Create database: psql -U postgres -c "CREATE DATABASE envelope_encryption;"
///      - Run migrations: psql -U postgres -d envelope_encryption -f migrations/001_init_schema.sql
///      - Run migrations: psql -U postgres -d envelope_encryption -f migrations/002_simplified_schema.sql
///   3. Ensure .env has DATABASE_URL and SERVER_KEY_BASE64

use envelope_encryption::{PostgresStorage, PostgresEnvelopeService, AesGcmCipher};
use sqlx::PgPool;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== PostgreSQL Envelope Encryption Demo ===\n");

    // Load environment variables
    println!("[STARTUP] Loading .env file...");
    dotenvy::dotenv().ok();

    // Get database URL
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env");

    println!("[STARTUP] Database URL: {}", database_url.split('@').next().unwrap_or("***"));
    println!("[STARTUP] Connecting to PostgreSQL...\n");

    // Connect to PostgreSQL
    let pool = PgPool::connect(&database_url).await?;
    println!("[STARTUP] ✓ PostgreSQL connection established\n");

    // Initialize storage and service
    println!("[STARTUP] Initializing PostgresEnvelopeService...");
    let storage = PostgresStorage::new(pool);
    let service = PostgresEnvelopeService::new(storage).await?;

    println!("\n{}", "=".repeat(70));
    println!("                    DEMO START");
    println!("{}\n", "=".repeat(70));

    // Demo: Two users
    let user1_id = Uuid::new_v4();
    let user2_id = Uuid::new_v4();

    println!("[USERS] User 1 ID: {}", user1_id);
    println!("[USERS] User 2 ID: {}\n", user2_id);

    // ========================================================================
    // Demo 1: Generate DEK for User 1
    // ========================================================================
    println!("┌{}┐", "─".repeat(68));
    println!("│  Demo 1: Generate DEK for User 1                                  │");
    println!("└{}┘", "─".repeat(68));

    let user1_dek = service.generate_dek(&user1_id).await?;

    println!("\n[RESULT] User: {}", user1_id);
    println!("[RESULT] DEK ID: {}", user1_dek.dek_id);
    println!("[RESULT] KEK Version: {}", user1_dek.kek_version);
    println!("[RESULT] EDEK Nonce: {} bytes", user1_dek.edek_nonce.len());
    println!("[RESULT] EDEK Ciphertext: {} bytes", user1_dek.edek_ciphertext.len());
    println!("[RESULT] GCM Tag: {} bytes", user1_dek.tag.len());
    println!("[RESULT] ⚠ DEK/EDEK stored in MEMORY only, NOT in PostgreSQL");

    // ========================================================================
    // Demo 2: Encrypt data with DEK
    // ========================================================================
    println!("\n┌{}┐", "─".repeat(68));
    println!("│  Demo 2: Encrypt Data with DEK                                    │");
    println!("└{}┘", "─".repeat(68));

    let plaintext = b"Sensitive user data protected by envelope encryption";
    let content_id = Uuid::new_v4();

    println!("\n[ENCRYPT] Plaintext: {:?}", String::from_utf8_lossy(plaintext));
    println!("[ENCRYPT] Content ID: {}", content_id);
    println!("[ENCRYPT] Encrypting with DEK (AAD=content_id)...");

    let encrypted = AesGcmCipher::encrypt(&user1_dek.dek, plaintext, Some(content_id.as_bytes()))?;

    println!("[ENCRYPT] ✓ Ciphertext: {} bytes", encrypted.ciphertext.len());
    println!("[ENCRYPT] ✓ Nonce: {} bytes", encrypted.nonce.len());

    // ========================================================================
    // Demo 3: Decrypt EDEK to recover DEK (from in-memory cache)
    // ========================================================================
    println!("\n┌{}┐", "─".repeat(68));
    println!("│  Demo 3: Decrypt EDEK to Recover DEK                              │");
    println!("└{}┘", "─".repeat(68));

    // Reconstruct full EDEK ciphertext (edek + tag)
    let mut full_edek_ciphertext = user1_dek.edek_ciphertext.clone();
    full_edek_ciphertext.extend_from_slice(&user1_dek.tag);

    let recovered_dek = service.decrypt_edek(
        &user1_dek.dek_id,
        &full_edek_ciphertext,
        &user1_dek.edek_nonce,
        &user1_id,
        user1_dek.kek_version
    ).await?;

    println!("\n[RESULT] DEK ID: {}", user1_dek.dek_id);
    println!("[RESULT] ✓ DEK recovered successfully");

    // Decrypt data with recovered DEK
    println!("[DECRYPT] Decrypting ciphertext with recovered DEK...");
    let decrypted = AesGcmCipher::decrypt(&recovered_dek, &encrypted, Some(content_id.as_bytes()))?;
    println!("[DECRYPT] ✓ Plaintext: {:?}", String::from_utf8_lossy(&decrypted));

    // ========================================================================
    // Demo 4: Generate DEK for User 2 (gets different KEK)
    // ========================================================================
    println!("\n┌{}┐", "─".repeat(68));
    println!("│  Demo 4: Per-User KEK Isolation                                   │");
    println!("└{}┘", "─".repeat(68));

    let user2_dek = service.generate_dek(&user2_id).await?;

    println!("\n[USER_2] User 2 ID: {}", user2_id);
    println!("[USER_2] DEK ID: {}", user2_dek.dek_id);
    println!("[USER_2] KEK Version: {}", user2_dek.kek_version);
    println!("[USER_2] ✓ Each user has their own KEK in PostgreSQL");

    // ========================================================================
    // Demo 5: Server Key Rotation (Test by changing .env)
    // ========================================================================
    println!("\n┌{}┐", "─".repeat(68));
    println!("│  Demo 5: Server Key Rotation Test                                 │");
    println!("└{}┘", "─".repeat(68));

    println!("\n[INFO] Testing server key rotation mechanism");
    println!("[INFO] To test with actual rotation:");
    println!("[INFO]   1. Stop the program");
    println!("[INFO]   2. Edit .env and change SERVER_KEY_BASE64");
    println!("[INFO]   3. Restart and call service.rotate_server_key()");
    println!("[INFO] For now, calling rotate_server_key() with unchanged key...");

    let server_rotation_result = service.rotate_server_key().await?;

    println!("\n[ROTATE_SERVER_KEY] KEKs Re-wrapped: {}", server_rotation_result.keks_rewrapped);
    println!("[ROTATE_SERVER_KEY] Users Affected: {}", server_rotation_result.users_affected);
    if server_rotation_result.keks_rewrapped == 0 {
        println!("[ROTATE_SERVER_KEY] ✓ Server key unchanged, no rotation performed");
    } else {
        println!("[ROTATE_SERVER_KEY] ✓ All KEKs re-wrapped with new server key");
    }

    // ========================================================================
    // Demo 5b: Rotate User 1's KEK
    // ========================================================================
    println!("\n┌{}┐", "─".repeat(68));
    println!("│  Demo 5b: User KEK Rotation                                       │");
    println!("└{}┘", "─".repeat(68));

    let rotation_result = service.rotate_user_kek(&user1_id).await?;

    println!("\n[ROTATE_KEK] User: {}", rotation_result.user_id);
    println!("[ROTATE_KEK] Old KEK Version: {}", rotation_result.old_version);
    println!("[ROTATE_KEK] New KEK Version: {}", rotation_result.new_version);
    println!("[ROTATE_KEK] DEKs Re-wrapped: {}", rotation_result.deks_rewrapped);
    println!("[ROTATE_KEK] ✓ New EKEK stored in PostgreSQL");
    println!("[ROTATE_KEK] ✓ All cached DEKs re-wrapped with new KEK");

    // Verify: Decrypt EDEK still works after KEK rotation
    println!("\n┌{}┐", "─".repeat(68));
    println!("│  Demo 6: Verify Decryption After KEK Rotation                     │");
    println!("└{}┘", "─".repeat(68));

    let recovered_dek_after_rotation = service.decrypt_edek(
        &user1_dek.dek_id,
        &full_edek_ciphertext,
        &user1_dek.edek_nonce,
        &user1_id,
        rotation_result.new_version  // Now using new KEK version
    ).await?;
    let decrypted_after = AesGcmCipher::decrypt(
        &recovered_dek_after_rotation,
        &encrypted,
        Some(content_id.as_bytes()),
    )?;

    println!("\n[VERIFY] ✓ DEK decrypted successfully after KEK rotation");
    println!("[VERIFY] ✓ Plaintext: {:?}", String::from_utf8_lossy(&decrypted_after));
    println!("[VERIFY] ✓ KEK rotation is transparent to application");

    // ========================================================================
    // Demo 7: Show Database vs Memory Status
    // ========================================================================
    println!("\n┌{}┐", "─".repeat(68));
    println!("│  Demo 7: Database vs Memory Status                                │");
    println!("└{}┘", "─".repeat(68));

    let cached_dek_count = service.get_cached_dek_count();
    let user1_kek_count = service.get_user_kek_count(&user1_id).await?;
    let user2_kek_count = service.get_user_kek_count(&user2_id).await?;

    println!("\n[MEMORY CACHE]");
    println!("  - DEKs cached: {}", cached_dek_count);
    println!("  - Purpose: Testing and performance optimization");
    println!("  - Lifetime: Process runtime only");

    println!("\n[POSTGRESQL DATABASE]");
    println!("  - User 1 KEKs (EKEK): {}", user1_kek_count);
    println!("  - User 2 KEKs (EKEK): {}", user2_kek_count);
    println!("  - Storage: ONLY encrypted KEKs (EKEK)");
    println!("  - Lifetime: Persistent");

    println!("\n[IMPORTANT]");
    println!("  ⚠ DEKs are NEVER stored in PostgreSQL");
    println!("  ⚠ EDEKs are NEVER stored in PostgreSQL");
    println!("  ✓ Only EKEKs are persisted to database");
    println!("  ✓ All plaintext keys stay in memory only");

    // ========================================================================
    // Summary
    // ========================================================================
    println!("\n{}", "=".repeat(70));
    println!("                         SUMMARY");
    println!("{}\n", "=".repeat(70));

    println!("┌─ Crypto Architecture ─────────────────────────────────────────────┐");
    println!("│                                                                    │");
    println!("│  .env (SERVER_KEY_BASE64)                                          │");
    println!("│    ↓ encrypts (AAD=user_id)                                        │");
    println!("│  PostgreSQL (user_keks table)                                      │");
    println!("│    ↓ stores EKEK                                                   │");
    println!("│    ↓ decrypts in-memory                                            │");
    println!("│  KEK (in-memory only)                                              │");
    println!("│    ↓ encrypts (AAD=dek_id)                                         │");
    println!("│  EDEK (in-memory cache, testing only)                              │");
    println!("│    ↓ decrypts in-memory                                            │");
    println!("│  DEK (in-memory only)                                              │");
    println!("│    ↓ encrypts (AAD=content_id)                                     │");
    println!("│  Application Data                                                  │");
    println!("│                                                                    │");
    println!("└────────────────────────────────────────────────────────────────────┘");

    println!("\n✓ Server Key: Loaded from .env (32-byte base64)");
    println!("✓ KEKs (EKEK): Per-user, encrypted by Server Key, stored in PostgreSQL");
    println!("✓ DEKs: Generated in-memory, NEVER stored in database");
    println!("✓ EDEKs: Created in-memory for testing, NEVER stored in database");
    println!("✓ Versioning: Explicit version tracking for KEKs");
    println!("✓ Nonces: Fresh random nonce for each encryption");
    println!("✓ AAD Binding:");
    println!("  - EKEK: AAD = user_id");
    println!("  - EDEK: AAD = dek_id");
    println!("  - Data: AAD = content_id");
    println!("✓ Crypto: AES-256-GCM only, no HKDF/KDFs");
    println!("✓ Database: Stores ONLY EKEKs, no DEKs/EDEKs");
    println!("✓ KEK Rotation: Automatic re-wrapping of cached EDEKs in memory");

    println!("\n{}", "=".repeat(70));
    println!("                      DEMO COMPLETE");
    println!("{}\n", "=".repeat(70));

    Ok(())
}
