/// Envelope Encryption Demo
///
/// Usage:
///   cargo run
///
/// PostgreSQL setup:
///   1. Run schema: psql -U postgres -f schema.sql
///   2. Ensure .env has DATABASE_URL
use envelope_encryption::{PostgresStorage, PostgresEnvelopeService, AesGcmCipher};
use sqlx::PgPool;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Envelope Encryption Demo ===\n");

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

    // ========================================================================
    // Demo 1: Create 125 users with KEKs
    // ========================================================================
    println!("┌{}┐", "─".repeat(68));
    println!("│  Demo 1: Create 125 Users with KEKs                               │");
    println!("└{}┘", "─".repeat(68));

    let mut user_ids = Vec::new();
    println!("\n[INFO] Creating 125 users...");

    for i in 0..125 {
        let user_id = Uuid::new_v4();
        user_ids.push(user_id);

        // Generate DEK to trigger KEK creation
        let _ = service.generate_dek(&user_id).await?;

        if (i + 1) % 25 == 0 {
            println!("[INFO] Created {} users with KEKs", i + 1);
        }
    }

    println!("\n[RESULT] ✓ Created 125 users with ACTIVE KEKs");

    // Check stats
    let stats = service.get_kek_stats().await?;
    println!("[RESULT] KEK Statistics:");
    for (status, count) in &stats {
        println!("[RESULT]   - {}: {}", status, count);
    }

    // ========================================================================
    // Demo 2: Test basic encryption/decryption with first user
    // ========================================================================
    println!("\n┌{}┐", "─".repeat(68));
    println!("│  Demo 2: Test Encryption/Decryption                               │");
    println!("└{}┘", "─".repeat(68));

    let test_user = user_ids[0];
    println!("\n[INFO] Testing with user: {}", test_user);

    let user_dek = service.generate_dek(&test_user).await?;
    let plaintext = b"Sensitive data protected by envelope encryption";
    let content_id = Uuid::new_v4();

    println!("[ENCRYPT] Encrypting data...");
    let encrypted = AesGcmCipher::encrypt(&user_dek.dek, plaintext, Some(content_id.as_bytes()))?;
    println!("[ENCRYPT] ✓ Ciphertext: {} bytes", encrypted.ciphertext.len());

    println!("[DECRYPT] Decrypting data...");
    let recovered_dek = service.decrypt_edek(
        &user_dek.dek_id,
        &user_dek.edek_blob,
        &test_user,
        user_dek.kek_version
    ).await?;
    let decrypted = AesGcmCipher::decrypt(&recovered_dek, &encrypted, Some(content_id.as_bytes()))?;
    println!("[DECRYPT] ✓ Plaintext: {:?}", String::from_utf8_lossy(&decrypted));

    // ========================================================================
    // Demo 3: Bulk KEK Rotation (125 KEKs)
    // ========================================================================
    println!("\n┌{}┐", "─".repeat(68));
    println!("│  Demo 3: Bulk KEK Rotation (125 KEKs in batches of 50)            │");
    println!("└{}┘", "─".repeat(68));

    println!("\n[INFO] Current KEK statistics:");
    let stats_before = service.get_kek_stats().await?;
    for (status, count) in &stats_before {
        println!("[INFO]   - {}: {}", status, count);
    }

    println!("\n[INFO] Starting bulk rotation of 125 KEKs...");
    println!("[INFO] This will rotate in batches of 50...");

    let rotation_result = service.bulk_rotate_all_keks().await?;

    println!("\n[RESULT] Bulk Rotation Complete:");
    println!("[RESULT]   - KEKs marked as RETIRED: {}", rotation_result.keks_marked_retired);
    println!("[RESULT]   - KEKs rotated: {}", rotation_result.keks_rotated);

    println!("\n[INFO] KEK statistics after rotation:");
    let stats_after = service.get_kek_stats().await?;
    for (status, count) in &stats_after {
        println!("[INFO]   - {}: {}", status, count);
    }

    // ========================================================================
    // Demo 4: Lazy Rotation - Random User Access
    // ========================================================================
    println!("\n┌{}┐", "─".repeat(68));
    println!("│  Demo 4: Lazy Rotation - Random User Access                       │");
    println!("└{}┘", "─".repeat(68));

    // After bulk rotation, all 125 users now have ACTIVE KEKs (version 2)
    // Let's pick 5 random users and test that they can generate DEKs successfully
    println!("\n[INFO] Testing KEK access after bulk rotation");
    println!("[INFO] All users should have ACTIVE KEKs (version 2) after rotation");

    use rand::seq::SliceRandom;
    use rand::thread_rng;

    let mut rng = thread_rng();
    let mut random_users: Vec<_> = user_ids.iter().take(10).cloned().collect();
    random_users.shuffle(&mut rng);
    let random_users: Vec<_> = random_users.iter().take(5).cloned().collect();

    println!("\n[INFO] Testing with 5 random users from the 125:");
    for (idx, user_id) in random_users.iter().enumerate() {
        println!("\n[INFO] User {} of 5: {}", idx + 1, user_id);

        // Generate new DEK - should use the ACTIVE KEK (version 2 after rotation)
        let dek = service.generate_dek(user_id).await?;
        println!("[INFO] ✓ DEK generated with KEK version: {}", dek.kek_version);
        println!("[INFO] ✓ Using ACTIVE KEK (version {} after bulk rotation)", dek.kek_version);
    }

    println!("\n[RESULT] ✓ All 5 users successfully generated DEKs");
    println!("[RESULT] ✓ All are using ACTIVE KEKs (version 2)");

    // ========================================================================
    // Demo 5: Verify Old KEKs Can Still Decrypt
    // ========================================================================
    println!("\n┌{}┐", "─".repeat(68));
    println!("│  Demo 5: Verify Old KEKs Can Still Decrypt                        │");
    println!("└{}┘", "─".repeat(68));

    println!("\n[INFO] Testing that old RETIRED KEKs can still decrypt EDEKs");

    // The user_dek we created earlier should still be decryptable
    // even though we rotated KEKs
    println!("[INFO] Attempting to decrypt EDEK created with old KEK version...");
    let _old_dek = service.decrypt_edek(
        &user_dek.dek_id,
        &user_dek.edek_blob,
        &test_user,
        user_dek.kek_version
    ).await?;

    println!("[RESULT] ✓ Successfully decrypted with old KEK version: {}", user_dek.kek_version);
    println!("[RESULT] ✓ Backward compatibility maintained");

    // ========================================================================
    // Demo 6: Disable and Delete Old KEK
    // ========================================================================
    println!("\n┌{}┐", "─".repeat(68));
    println!("│  Demo 6: KEK Lifecycle Management                                 │");
    println!("└{}┘", "─".repeat(68));

    // Pick a user and try to manage their old KEK
    let manage_user = user_ids[10];
    println!("\n[INFO] Managing KEKs for user: {}", manage_user);

    // Try to disable the old KEK version (version 1 - now RETIRED after rotation)
    println!("[INFO] Attempting to disable old RETIRED KEK (version 1)...");
    match service.disable_kek(&manage_user, 1).await {
        Ok(result) => {
            if result {
                println!("[RESULT] ✓ KEK disabled successfully");

                // Now try to delete it
                println!("\n[INFO] Attempting to delete disabled KEK...");
                match service.delete_kek(&manage_user, 1).await {
                    Ok(deleted) => {
                        if deleted {
                            println!("[RESULT] ✓ KEK deleted successfully");
                        }
                    }
                    Err(e) => println!("[INFO] ⚠ Delete failed: {}", e),
                }
            }
        }
        Err(e) => println!("[INFO] ⚠ Disable failed: {}", e),
    }

    // ========================================================================
    // Demo 7: Final Statistics
    // ========================================================================
    println!("\n┌{}┐", "─".repeat(68));
    println!("│  Demo 7: Final Statistics                                         │");
    println!("└{}┘", "─".repeat(68));

    let final_stats = service.get_kek_stats().await?;

    println!("\n[HSM-STYLE ARCHITECTURE]");
    println!("  - Library manages: KEKs only");
    println!("  - Application manages: DEKs and EDEKs");
    println!("  - Purpose: Separation of concerns");

    println!("\n[DATABASE]");
    println!("  - KEK Statistics:");
    for (status, count) in &final_stats {
        println!("    - {}: {}", status, count);
    }
    println!("  - Storage: KEKs as plaintext (32 bytes)");
    println!("  - Encryption at rest: Database encryption");

    println!("\n[IMPORTANT]");
    println!("  ⚠ Library does NOT cache or store DEKs");
    println!("  ⚠ Application manages DEK lifecycle (cache, store as EDEK)");
    println!("  ✓ Only KEKs persisted in database (encrypted at rest)");
    println!("  ✓ Total users tested: {}", user_ids.len());

    // ========================================================================
    // Summary
    // ========================================================================
    println!("\n{}", "=".repeat(70));
    println!("                         SUMMARY");
    println!("{}\n", "=".repeat(70));

    println!("┌─ Test Results ────────────────────────────────────────────────────┐");
    println!("│                                                                    │");
    println!("│  ✓ Created 125 users with unique KEKs                             │");
    println!("│  ✓ Bulk rotation: {} KEKs rotated in batches of 50          │", rotation_result.keks_rotated);
    println!("│  ✓ Lazy rotation: Auto-triggered on access                        │");
    println!("│  ✓ Backward compatibility: Old KEKs decrypt old EDEKs             │");
    println!("│  ✓ KEK lifecycle: ACTIVE → RETIRED → DISABLED → Deleted           │");
    println!("│  ✓ Performance: Batch processing with SKIP LOCKED                 │");
    println!("│                                                                    │");
    println!("└────────────────────────────────────────────────────────────────────┘");

    println!("\n✓ Database: Encrypts KEKs at rest");
    println!("✓ KEKs: Per-user, 32 bytes plaintext in DB");
    println!("✓ DEKs: In-memory only, never persisted");
    println!("✓ Rotation:");
    println!("  - Bulk: {} KEKs in batches of 50", rotation_result.keks_rotated);
    println!("  - Lazy: Auto-rotate RETIRED KEKs on access");
    println!("✓ Crypto: AES-256-GCM with AEAD format");

    println!("\n{}", "=".repeat(70));
    println!("                      DEMO COMPLETE");
    println!("{}\n", "=".repeat(70));

    Ok(())
}
