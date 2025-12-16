/// Envelope Encryption Demo - Supports both In-Memory and PostgreSQL backends
///
/// Usage:
///   cargo run                    # In-memory demo
///   cargo run -- --postgres      # PostgreSQL demo (requires setup)
///
/// PostgreSQL setup:
///   1. docker run -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres
///   2. psql -U postgres -c "CREATE DATABASE envelope_encryption;"
///   3. psql -U postgres -d envelope_encryption -f migrations/001_init_schema.sql
///   4. Create .env with DATABASE_URL and SERVER_KEY_BASE64 (openssl rand -base64 32)

use envelope_encryption::{EnvelopeEncryption, InMemoryStorage};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::sync::Arc;
use uuid::Uuid;
use std::env;

#[cfg(feature = "postgres")]
use envelope_encryption::{PostgresStorage, PostgresEnvelopeService, AesGcmCipher};
#[cfg(feature = "postgres")]
use sqlx::PgPool;

fn b64(data: &[u8]) -> String {
    let encoded = STANDARD.encode(data);
    if encoded.len() > 16 {
        format!("{}...{}", &encoded[..8], &encoded[encoded.len()-4..])
    } else {
        encoded
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let use_postgres = args.iter().any(|arg| arg == "--postgres");

    if use_postgres {
        println!("=== PostgreSQL Envelope Encryption Demo ===\n");
        #[cfg(feature = "postgres")]
        run_postgres_demo().await?;
        #[cfg(not(feature = "postgres"))]
        {
            println!("ERROR: PostgreSQL support not enabled.");
            println!("Build with: cargo build --features postgres");
        }
    } else {
        run_inmemory_demo().await?;
    }

    Ok(())
}

/// In-Memory Demo (original implementation)
async fn run_inmemory_demo() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Envelope Encryption with Per-User KEKs (In-Memory) ===\n");

    let storage = Arc::new(InMemoryStorage::new());
    let mut service = EnvelopeEncryption::new(storage)?;

    println!("[INIT] ServerKey ID: {}", service.server_key_id());
    println!("[INIT] ServerKey (32B): {}", b64(&service.export_server_key()));
    println!("[INIT] ServerKey Version: v{}\n", service.server_key_version());

    // Create two users
    let user1_id = Uuid::new_v4();
    let user2_id = Uuid::new_v4();

    println!("[USERS] User 1 ID: {}", user1_id);
    println!("[USERS] User 2 ID: {}\n", user2_id);

    // Encrypt data for User 1
    let user1_data = b"User 1's sensitive data";
    let envelope1 = service.encrypt(user1_data, &user1_id, None)?;

    println!("[ENCRYPT USER 1] CID: {}", envelope1.cid);
    println!("[ENCRYPT USER 1] DEK ID: {}", envelope1.dek_id);
    println!("[ENCRYPT USER 1] KEK ID: {}", envelope1.kek_id);
    println!("[ENCRYPT USER 1] Nonce (12B): {}", b64(&envelope1.encrypted_data.nonce));
    println!("[ENCRYPT USER 1] Ciphertext: {}\n", b64(&envelope1.encrypted_data.ciphertext));

    // Encrypt data for User 2
    let user2_data = b"User 2's different sensitive data";
    let envelope2 = service.encrypt(user2_data, &user2_id, None)?;

    println!("[ENCRYPT USER 2] CID: {}", envelope2.cid);
    println!("[ENCRYPT USER 2] DEK ID: {}", envelope2.dek_id);
    println!("[ENCRYPT USER 2] KEK ID: {}", envelope2.kek_id);
    println!("[ENCRYPT USER 2] Nonce (12B): {}", b64(&envelope2.encrypted_data.nonce));
    println!("[ENCRYPT USER 2] Ciphertext: {}\n", b64(&envelope2.encrypted_data.ciphertext));

    // Note: Each user has a different KEK
    println!("[NOTE] User 1 KEK ID: {}", envelope1.kek_id);
    println!("[NOTE] User 2 KEK ID: {}", envelope2.kek_id);
    println!("[NOTE] KEKs are different: {}\n", envelope1.kek_id != envelope2.kek_id);

    // Decrypt User 1's data
    let decrypted1 = service.decrypt(&envelope1)?;
    println!("[DECRYPT USER 1] Plaintext: {}\n", String::from_utf8_lossy(&decrypted1));

    // Decrypt User 2's data
    let decrypted2 = service.decrypt(&envelope2)?;
    println!("[DECRYPT USER 2] Plaintext: {}\n", String::from_utf8_lossy(&decrypted2));

    // Rotate Server Key
    println!("=== Server Key Rotation ===\n");
    let old_server_key = service.export_server_key();
    let rotation = service.rotate_server_key()?;
    let new_server_key = service.export_server_key();

    println!("[ROTATE SERVER] {}", rotation);
    println!("[ROTATE SERVER] Old ServerKey: {}", b64(&old_server_key));
    println!("[ROTATE SERVER] New ServerKey: {}", b64(&new_server_key));
    println!("[ROTATE SERVER] New ServerKey ID: {}\n", service.server_key_id());

    // Verify decryption still works after server key rotation
    let decrypted1_after = service.decrypt(&envelope1)?;
    println!("[VERIFY AFTER SERVER ROTATION] User 1 data: {}\n", String::from_utf8_lossy(&decrypted1_after));

    // Rotate User 1's KEK
    println!("=== User KEK Rotation ===\n");
    let old_kek_id = envelope1.kek_id;
    let kek_rotation = service.rotate_user_kek(&user1_id)?;

    println!("[ROTATE USER KEK] {}", kek_rotation);
    println!("[ROTATE USER KEK] Old KEK ID: {}", old_kek_id);
    println!("[ROTATE USER KEK] New KEK ID: {}\n", kek_rotation.new_key_id);

    // Verify User 1's data can still be decrypted after KEK rotation
    let decrypted1_after_kek = service.decrypt(&envelope1)?;
    println!("[VERIFY AFTER KEK ROTATION] User 1 data: {}\n", String::from_utf8_lossy(&decrypted1_after_kek));

    // Stats
    let stats = service.get_stats()?;
    println!("=== Key Statistics ===\n");
    println!("[STATS] ServerKey: {} total, {} active (v{})",
             stats.total_server_keys, stats.active_server_keys, stats.server_key_version);
    println!("[STATS] KEK: {} total, {} active", stats.total_keks, stats.active_keks);
    println!("[STATS] DEK: {} total, {} active", stats.total_deks, stats.active_deks);

    println!("\n=== Architecture Summary ===");
    println!("- ServerKey: Per-server key for DB and system security");
    println!("- KEK: Per-user Key Encryption Key (actual master key)");
    println!("- DEK: One-time Data Encryption Key (no rotation needed)");
    println!("- Hierarchy: ServerKey -> EKEK -> EDEK -> Encrypted Data");
    println!("- No HKDF: Standard AES-256-GCM envelope encryption");

    Ok(())
}

/// PostgreSQL Demo (production-grade)
#[cfg(feature = "postgres")]
async fn run_postgres_demo() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenvy::dotenv().ok();

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
    println!("[GENERATE_DEK] DEK/EDEK stored in MEMORY only (not in PostgreSQL)\n");

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
    // Demo 3: Decrypt EDEK to recover DEK (from in-memory cache)
    // ========================================================================
    println!("=== Demo 3: Decrypt EDEK ===");

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

    println!("[DECRYPT_EDEK] DEK ID: {}", user1_dek.dek_id);
    println!("[DECRYPT_EDEK] DEK recovered from in-memory cache");

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

    println!("[VERIFY] DEK decrypted successfully after KEK rotation");
    println!("[VERIFY] Plaintext: {:?}\n", String::from_utf8_lossy(&decrypted_after));

    // ========================================================================
    // Demo 7: Show In-Memory Cache Status
    // ========================================================================
    println!("=== Demo 7: In-Memory Cache Status ===");

    let cached_dek_count = service.get_cached_dek_count();
    let user1_kek_count = service.get_user_kek_count(&user1_id).await?;
    let user2_kek_count = service.get_user_kek_count(&user2_id).await?;

    println!("[CACHE] DEKs cached in memory: {}", cached_dek_count);
    println!("[DATABASE] User 1 KEKs (EKEK) in PostgreSQL: {}", user1_kek_count);
    println!("[DATABASE] User 2 KEKs (EKEK) in PostgreSQL: {}", user2_kek_count);
    println!("[NOTE] DEKs/EDEKs are NEVER stored in database, only in memory\n");

    // ========================================================================
    // Summary
    // ========================================================================
    println!("=== Summary ===");
    println!("✓ Server Key: Loaded from .env (32-byte base64)");
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

    Ok(())
}

#[cfg(not(feature = "postgres"))]
async fn run_postgres_demo() -> Result<(), Box<dyn std::error::Error>> {
    unreachable!()
}
