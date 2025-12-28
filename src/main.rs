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
use std::time::Instant;
use std::io::{self, Write};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Envelope Encryption Benchmark ===\n");

    // Load environment variables
    dotenvy::dotenv().ok();
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env");

    // Connect to PostgreSQL
    let pool = PgPool::connect(&database_url).await?;

    // Truncate tables on startup (if they exist)
    let truncate_start = Instant::now();
    match sqlx::query("TRUNCATE TABLE user_keks CASCADE").execute(&pool).await {
        Ok(_) => {
            let truncate_duration = truncate_start.elapsed();
            println!("[STARTUP] Tables truncated in {:.3}ms", truncate_duration.as_secs_f64() * 1000.0);
        }
        Err(_) => {
            println!("[STARTUP] Tables will be created automatically");
        }
    }

    // Get test quantity from user
    print!("Enter number of users to test (default: 125): ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let test_quantity: usize = input.trim().parse().unwrap_or(125);
    println!("Testing with {} users\n", test_quantity);

    // Initialize storage and service
    let storage = PostgresStorage::new(pool);
    let service = PostgresEnvelopeService::new(storage).await?;

    println!("{}", "=".repeat(70));
    println!("                    BENCHMARK START");
    println!("{}\n", "=".repeat(70));

    // ========================================================================
    // Demo 1: Create users with KEKs
    // ========================================================================
    println!("┌{}┐", "─".repeat(68));
    println!("│  Demo 1: Create {} Users with KEKs{:>width$}│", test_quantity, "", width = 35 - test_quantity.to_string().len());
    println!("└{}┘", "─".repeat(68));

    let mut user_ids = Vec::new();

    let demo1_start = Instant::now();
    for i in 0..test_quantity {
        let user_id = Uuid::new_v4();
        user_ids.push(user_id);
        let _ = service.generate_dek(&user_id).await?;

        if (i + 1) % 25 == 0 || (i + 1) == test_quantity {
            println!("  Progress: {}/{}", i + 1, test_quantity);
        }
    }
    let demo1_duration = demo1_start.elapsed();

    println!("✓ Created {} users with ACTIVE KEKs", test_quantity);
    println!("[PERF] Time: {:.3}ms | Rate: {:.2} ops/sec\n",
        demo1_duration.as_secs_f64() * 1000.0,
        test_quantity as f64 / demo1_duration.as_secs_f64());

    // ========================================================================
    // Demo 2: Test basic encryption/decryption
    // ========================================================================
    println!("┌{}┐", "─".repeat(68));
    println!("│  Demo 2: Encryption/Decryption Benchmark                          │");
    println!("└{}┘", "─".repeat(68));

    let test_user = user_ids[0];
    let user_dek = service.generate_dek(&test_user).await?;
    let plaintext = b"Sensitive data protected by envelope encryption";
    let content_id = Uuid::new_v4();

    let encrypt_start = Instant::now();
    let encrypted = AesGcmCipher::encrypt(&user_dek.dek, plaintext, Some(content_id.as_bytes()))?;
    let encrypt_time = encrypt_start.elapsed();

    let decrypt_start = Instant::now();
    let recovered_dek = service.decrypt_edek(
        &user_dek.dek_id,
        &user_dek.edek_blob,
        &test_user,
        user_dek.kek_version
    ).await?;
    let edek_decrypt_time = decrypt_start.elapsed();

    let decrypt_data_start = Instant::now();
    let _decrypted = AesGcmCipher::decrypt(&recovered_dek, &encrypted, Some(content_id.as_bytes()))?;
    let data_decrypt_time = decrypt_data_start.elapsed();

    println!("✓ Data encrypted/decrypted successfully");
    println!("[PERF] Encryption:      {:.3}ms ({:.2} ops/sec)",
        encrypt_time.as_secs_f64() * 1000.0, 1.0 / encrypt_time.as_secs_f64());
    println!("[PERF] EDEK Decryption: {:.3}ms ({:.2} ops/sec)",
        edek_decrypt_time.as_secs_f64() * 1000.0, 1.0 / edek_decrypt_time.as_secs_f64());
    println!("[PERF] Data Decryption: {:.3}ms ({:.2} ops/sec)\n",
        data_decrypt_time.as_secs_f64() * 1000.0, 1.0 / data_decrypt_time.as_secs_f64());

    // ========================================================================
    // Demo 3: Bulk KEK Rotation
    // ========================================================================
    println!("┌{}┐", "─".repeat(68));
    println!("│  Demo 3: Bulk KEK Rotation ({} KEKs){:>width$}│",
        test_quantity, "", width = 40 - test_quantity.to_string().len());
    println!("└{}┘", "─".repeat(68));

    let demo3_start = Instant::now();
    let rotation_result = service.bulk_rotate_all_keks().await?;
    let demo3_duration = demo3_start.elapsed();

    println!("✓ Bulk rotation complete");
    println!("[PERF] Time: {:.3}ms | Rate: {:.2} ops/sec",
        demo3_duration.as_secs_f64() * 1000.0,
        rotation_result.keks_rotated as f64 / demo3_duration.as_secs_f64());
    println!("[DEBUG] KEKs marked RETIRED: {}", rotation_result.keks_marked_retired);
    println!("[DEBUG] KEKs rotated: {}\n", rotation_result.keks_rotated);

    // ========================================================================
    // Demo 4: Lazy Rotation - Random User Access
    // ========================================================================
    println!("┌{}┐", "─".repeat(68));
    println!("│  Demo 4: Lazy Rotation Test                                       │");
    println!("└{}┘", "─".repeat(68));

    use rand::seq::SliceRandom;
    use rand::thread_rng;

    let mut rng = thread_rng();
    let sample_size = std::cmp::min(10, test_quantity);
    let mut random_users: Vec<_> = user_ids.iter().take(sample_size).cloned().collect();
    random_users.shuffle(&mut rng);
    let test_sample = std::cmp::min(5, random_users.len());
    let random_users: Vec<_> = random_users.iter().take(test_sample).cloned().collect();

    let demo4_start = Instant::now();
    for (idx, user_id) in random_users.iter().enumerate() {
        let user_start = Instant::now();
        let dek = service.generate_dek(user_id).await?;
        let user_time = user_start.elapsed();

        println!("  User {}/{}: KEK v{} | {:.3}ms ({:.2} ops/sec)",
            idx + 1, test_sample, dek.kek_version,
            user_time.as_secs_f64() * 1000.0,
            1.0 / user_time.as_secs_f64());
    }
    let demo4_duration = demo4_start.elapsed();

    println!("✓ All {} users successfully generated DEKs", test_sample);
    println!("[PERF] Average: {:.3}ms per user\n",
        demo4_duration.as_secs_f64() * 1000.0 / test_sample as f64);

    // ========================================================================
    // Demo 5: Verify Old KEKs Can Still Decrypt
    // ========================================================================
    println!("┌{}┐", "─".repeat(68));
    println!("│  Demo 5: Backward Compatibility Test                              │");
    println!("└{}┘", "─".repeat(68));

    let demo5_start = Instant::now();
    let _old_dek = service.decrypt_edek(
        &user_dek.dek_id,
        &user_dek.edek_blob,
        &test_user,
        user_dek.kek_version
    ).await?;
    let demo5_duration = demo5_start.elapsed();

    println!("✓ Old KEK (v{}) can still decrypt EDEKs", user_dek.kek_version);
    println!("[PERF] EDEK Decryption (old KEK): {:.3}ms ({:.2} ops/sec)\n",
        demo5_duration.as_secs_f64() * 1000.0,
        1.0 / demo5_duration.as_secs_f64());

    // ========================================================================
    // Demo 6: KEK Lifecycle Management
    // ========================================================================
    println!("┌{}┐", "─".repeat(68));
    println!("│  Demo 6: KEK Lifecycle (Disable/Delete)                           │");
    println!("└{}┘", "─".repeat(68));

    let manage_user_idx = std::cmp::min(10, test_quantity - 1);
    let manage_user = user_ids[manage_user_idx];

    let demo6_start = Instant::now();
    match service.disable_kek(&manage_user, 1).await {
        Ok(result) => {
            let disable_time = demo6_start.elapsed().as_secs_f64() * 1000.0;
            if result {
                println!("✓ KEK disabled");
                println!("[PERF] Disable: {:.3}ms ({:.2} ops/sec)",
                    disable_time, 1000.0 / disable_time);

                let delete_start = Instant::now();
                match service.delete_kek(&manage_user, 1).await {
                    Ok(deleted) => {
                        let delete_time = delete_start.elapsed().as_secs_f64() * 1000.0;
                        if deleted {
                            println!("✓ KEK deleted");
                            println!("[PERF] Delete: {:.3}ms ({:.2} ops/sec)\n",
                                delete_time, 1000.0 / delete_time);
                        }
                    }
                    Err(e) => println!("[ERROR] Delete failed: {}\n", e),
                }
            }
        }
        Err(e) => println!("[ERROR] Disable failed: {}\n", e),
    }

    // ========================================================================
    // Summary
    // ========================================================================
    println!("{}", "=".repeat(70));
    println!("                    BENCHMARK SUMMARY");
    println!("{}\n", "=".repeat(70));

    let final_stats = service.get_kek_stats().await?;
    println!("KEK Statistics:");
    for (status, count) in &final_stats {
        println!("  - {}: {}", status, count);
    }

    println!("\n┌─ Performance Summary (HSM-Style) ─────────────────────────────────┐");
    println!("│                                                                    │");
    println!("│  KEK Creation:      {:.2} ops/sec{:>width$}│",
        test_quantity as f64 / demo1_duration.as_secs_f64(), "",
        width = 33 - format!("{:.2}", test_quantity as f64 / demo1_duration.as_secs_f64()).len());
    println!("│  Encryption:        {:.2} ops/sec{:>width$}│",
        1.0 / encrypt_time.as_secs_f64(), "",
        width = 33 - format!("{:.2}", 1.0 / encrypt_time.as_secs_f64()).len());
    println!("│  Decryption:        {:.2} ops/sec{:>width$}│",
        1.0 / data_decrypt_time.as_secs_f64(), "",
        width = 33 - format!("{:.2}", 1.0 / data_decrypt_time.as_secs_f64()).len());
    println!("│  KEK Rotation:      {:.2} ops/sec{:>width$}│",
        rotation_result.keks_rotated as f64 / demo3_duration.as_secs_f64(), "",
        width = 33 - format!("{:.2}", rotation_result.keks_rotated as f64 / demo3_duration.as_secs_f64()).len());
    println!("│                                                                    │");
    println!("└────────────────────────────────────────────────────────────────────┘");

    println!("\nTest Configuration:");
    println!("  • Total users tested: {}", test_quantity);
    println!("  • Crypto: AES-256-GCM with AEAD");
    println!("  • KEK lifecycle: ACTIVE → RETIRED → DISABLED → Deleted");
    println!("  • Rotation: Bulk (batches of 50) + Lazy (on-access)");

    println!("\n{}", "=".repeat(70));
    println!("                    BENCHMARK COMPLETE");
    println!("{}\n", "=".repeat(70));

    Ok(())
}
