use envelope_encryption::{EnvelopeEncryption, InMemoryStorage};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::sync::Arc;

fn b64(data: &[u8]) -> String {
    let encoded = STANDARD.encode(data);
    if encoded.len() > 16 {
        format!("{}...{}", &encoded[..8], &encoded[encoded.len()-4..])
    } else {
        encoded
    }
}

fn main() {
    println!("=== HSM Envelope Encryption ===\n");

    let storage = Arc::new(InMemoryStorage::new());
    let mut hsm = EnvelopeEncryption::new(storage).expect("Failed to create HSM");

    println!("[INIT] KEK ID: {}", hsm.kek_id());
    println!("[INIT] KEK (32B): {}", b64(&hsm.export_kek()));
    println!("[INIT] Version: v{}\n", hsm.kek_version());

    // Encrypt
    let plaintext = b"Sensitive data protected by HSM";
    let envelope = hsm.encrypt(plaintext, None).expect("Encryption failed");

    println!("[ENCRYPT] CID: {}", envelope.cid);
    println!("[ENCRYPT] DEK ID: {}", envelope.dek_id);
    println!("[ENCRYPT] Nonce (12B): {}", b64(&envelope.encrypted_data.nonce));
    println!("[ENCRYPT] Ciphertext: {}", b64(&envelope.encrypted_data.ciphertext));
    println!("[ENCRYPT] Tag (last 16B of ciphertext)\n");

    // Decrypt
    let decrypted = hsm.decrypt(&envelope).expect("Decryption failed");
    println!("[DECRYPT] Plaintext: {}\n", String::from_utf8_lossy(&decrypted));

    // Rotate KEK
    let old_kek = hsm.export_kek();
    let rotation = hsm.rotate_kek().expect("KEK rotation failed");
    let new_kek = hsm.export_kek();

    println!("[ROTATE] {}", rotation);
    println!("[ROTATE] Old KEK: {}", b64(&old_kek));
    println!("[ROTATE] New KEK: {}", b64(&new_kek));
    println!("[ROTATE] New KEK ID: {}\n", hsm.kek_id());

    // Verify post-rotation
    let decrypted = hsm.decrypt(&envelope).expect("Post-rotation decrypt failed");
    println!("[VERIFY] Decrypted: {}\n", String::from_utf8_lossy(&decrypted));

    // Stats
    let stats = hsm.get_stats().expect("Failed to get stats");
    println!("[STATS] KEK: {} total, {} active (v{})", stats.total_keks, stats.active_keks, stats.kek_version);
    println!("[STATS] DEK: {} total, {} active", stats.total_deks, stats.active_deks);
}

