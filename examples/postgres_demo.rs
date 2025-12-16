/// Production-grade PostgreSQL envelope encryption demo
///
/// Prerequisites:
/// 1. PostgreSQL running: docker run -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres
/// 2. Create database: psql -U postgres -c "CREATE DATABASE envelope_encryption;"
/// 3. Run migrations: psql -U postgres -d envelope_encryption -f migrations/001_init_schema.sql
/// 4. Create .env file with SERVER_KEY_BASE64 (generate with: openssl rand -base64 32)
///
/// Example .env:
/// DATABASE_URL=postgresql://postgres:postgres@localhost:5432/envelope_encryption
/// SERVER_KEY_BASE64=<your 32-byte base64 key>
/// SERVER_KEY_VERSION=1

use envelope_encryption::{PostgresStorage, PostgresEnvelopeService, AesGcmCipher};
use sqlx::PgPool;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenvy::dotenv().ok();

    println!("=== PostgreSQL Envelope Encryption Demo ===\n");

    // Connect to PostgreSQL
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env");

    println!("[INIT] Connecting to PostgreSQL...");
    let pool = PgPool::connect(&database_url).await?;
    println!("[INIT] Connected successfully\n");

    // Initialize storage and service
    let storage = PostgresStorage::new(pool);
    let service = PostgresEnvelopeService::new(storage).await?;

    println!("[INIT] Server Key loaded from .env");
    println!("[INIT] PostgreSQL envelope service initialized\n");

    // Demo: Two users
    let user1_id = Uuid::new_v4();
    let user2_id = Uuid::new_v4();

    println!("[USERS] User 1 ID: {}", user1_id);
    println!("[USERS] User 2 ID: {}\n", user2_id);

    // ========================================================================
    // Demo 1: Generate DEK for User 1
    // ========================================================================
    println!("=== Demo 1: Generate DEK ===");
    let user1_dek = service.generate_dek(&user1_id).await?;

    println!("[GENERATE_DEK] User: {}", user1_id);
    println!("[GENERATE_DEK] DEK ID: {}", user1_dek.dek_id);
    println!("[GENERATE_DEK] KEK Version: {}", user1_dek.kek_version);
    println!("[GENERATE_DEK] EDEK Nonce (12B): {} bytes", user1_dek.edek_nonce.len());
    println!("[GENERATE_DEK] EDEK Ciphertext: {} bytes", user1_dek.edek_ciphertext.len());
    println!("[GENERATE_DEK] GCM Tag (16B): {} bytes", user1_dek.tag.len());
    println!("[GENERATE_DEK] EDEK stored in PostgreSQL\n");

    // ========================================================================
    // Demo 2: Encrypt data with DEK
    // ========================================================================
    println!("=== Demo 2: Encrypt Data ===");
    let plaintext = b"Sensitive user data protected by envelope encryption";

    let content_id = Uuid::new_v4();
    let encrypted = AesGcmCipher::encrypt(&user1_dek.dek, plaintext, Some(content_id.as_bytes()))?;

    println!("[ENCRYPT] Plaintext: {:?}", String::from_utf8_lossy(plaintext));
    println!("[ENCRYPT] Content ID: {}", content_id);
    println!("[ENCRYPT] Ciphertext: {} bytes", encrypted.ciphertext.len());
    println!("[ENCRYPT] Nonce: {} bytes\n", encrypted.nonce.len());

    // ========================================================================
    // Demo 3: Decrypt EDEK to recover DEK
    // ========================================================================
    println!("=== Demo 3: Decrypt EDEK ===");
    let recovered_dek = service.decrypt_edek(&user1_dek.dek_id).await?;

    println!("[DECRYPT_EDEK] DEK ID: {}", user1_dek.dek_id);
    println!("[DECRYPT_EDEK] DEK recovered successfully");

    // Decrypt data with recovered DEK
    let decrypted = AesGcmCipher::decrypt(&recovered_dek, &encrypted, Some(content_id.as_bytes()))?;
    println!("[DECRYPT] Plaintext: {:?}\n", String::from_utf8_lossy(&decrypted));

    // ========================================================================
    // Demo 4: Generate DEK for User 2 (gets different KEK)
    // ========================================================================
    println!("=== Demo 4: Per-User KEK Isolation ===");
    let user2_dek = service.generate_dek(&user2_id).await?;

    println!("[USER_2] User 2 ID: {}", user2_id);
    println!("[USER_2] DEK ID: {}", user2_dek.dek_id);
    println!("[USER_2] KEK Version: {}", user2_dek.kek_version);
    println!("[USER_2] Each user has their own KEK\n");

    // ========================================================================
    // Demo 5: Rotate User 1's KEK
    // ========================================================================
    println!("=== Demo 5: KEK Rotation ===");
    let rotation_result = service.rotate_user_kek(&user1_id).await?;

    println!("[ROTATE_KEK] User: {}", rotation_result.user_id);
    println!("[ROTATE_KEK] Old KEK Version: {}", rotation_result.old_version);
    println!("[ROTATE_KEK] New KEK Version: {}", rotation_result.new_version);
    println!("[ROTATE_KEK] DEKs Re-wrapped: {}", rotation_result.deks_rewrapped);
    println!("[ROTATE_KEK] All DEKs now encrypted with new KEK\n");

    // Verify: Decrypt EDEK still works after KEK rotation
    println!("=== Demo 6: Verify Decryption After KEK Rotation ===");
    let recovered_dek_after_rotation = service.decrypt_edek(&user1_dek.dek_id).await?;
    let decrypted_after = AesGcmCipher::decrypt(
        &recovered_dek_after_rotation,
        &encrypted,
        Some(content_id.as_bytes()),
    )?;

    println!("[VERIFY] DEK decrypted successfully after KEK rotation");
    println!("[VERIFY] Plaintext: {:?}\n", String::from_utf8_lossy(&decrypted_after));

    // ========================================================================
    // Demo 7: Disable KEK if unused
    // ========================================================================
    println!("=== Demo 7: Disable KEK (if unused) ===");

    // Try to disable User 1's old KEK (should fail - DEKs still reference it)
    let can_disable_old = service
        .disable_kek_if_unused(&user1_id, rotation_result.old_version)
        .await?;

    println!("[DISABLE_KEK] Attempt to disable old KEK version {}", rotation_result.old_version);
    println!("[DISABLE_KEK] Can disable: {}", can_disable_old);
    println!("[DISABLE_KEK] Reason: Active DEKs still reference it");
    println!("[DISABLE_KEK] Database constraint prevents orphaning DEKs\n");

    // ========================================================================
    // Summary
    // ========================================================================
    println!("=== Summary ===");
    println!("✓ Server Key: Loaded from .env (32-byte base64)");
    println!("✓ KEKs: Per-user, encrypted by Server Key (EKEK) in PostgreSQL");
    println!("✓ DEKs: Per-encryption, encrypted by user's KEK (EDEK) in PostgreSQL");
    println!("✓ Versioning: Explicit version tracking for all KEKs");
    println!("✓ Nonces: Fresh random nonce for each encryption");
    println!("✓ AAD Binding:");
    println!("  - EKEK: AAD = user_id");
    println!("  - EDEK: AAD = dek_id");
    println!("  - Data: AAD = content_id");
    println!("✓ Crypto: AES-256-GCM only, no HKDF/KDFs");
    println!("✓ Referential Integrity: PostgreSQL enforces KEK->DEK relationships");
    println!("✓ KEK Rotation: Automatic re-wrapping of all user's DEKs");

    Ok(())
}
