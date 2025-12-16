use envelope_encryption::{EnvelopeEncryption, InMemoryStorage};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::sync::Arc;
use uuid::Uuid;

fn b64(data: &[u8]) -> String {
    let encoded = STANDARD.encode(data);
    if encoded.len() > 16 {
        format!("{}...{}", &encoded[..8], &encoded[encoded.len()-4..])
    } else {
        encoded
    }
}

fn main() {
    println!("=== Envelope Encryption with Per-User KEKs ===\n");

    let storage = Arc::new(InMemoryStorage::new());
    let mut service = EnvelopeEncryption::new(storage).expect("Failed to create service");

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
    let envelope1 = service.encrypt(user1_data, &user1_id, None).expect("Encryption failed");

    println!("[ENCRYPT USER 1] CID: {}", envelope1.cid);
    println!("[ENCRYPT USER 1] DEK ID: {}", envelope1.dek_id);
    println!("[ENCRYPT USER 1] KEK ID: {}", envelope1.kek_id);
    println!("[ENCRYPT USER 1] Nonce (12B): {}", b64(&envelope1.encrypted_data.nonce));
    println!("[ENCRYPT USER 1] Ciphertext: {}\n", b64(&envelope1.encrypted_data.ciphertext));

    // Encrypt data for User 2
    let user2_data = b"User 2's different sensitive data";
    let envelope2 = service.encrypt(user2_data, &user2_id, None).expect("Encryption failed");

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
    let decrypted1 = service.decrypt(&envelope1).expect("Decryption failed");
    println!("[DECRYPT USER 1] Plaintext: {}\n", String::from_utf8_lossy(&decrypted1));

    // Decrypt User 2's data
    let decrypted2 = service.decrypt(&envelope2).expect("Decryption failed");
    println!("[DECRYPT USER 2] Plaintext: {}\n", String::from_utf8_lossy(&decrypted2));

    // Rotate Server Key
    println!("=== Server Key Rotation ===\n");
    let old_server_key = service.export_server_key();
    let rotation = service.rotate_server_key().expect("Server key rotation failed");
    let new_server_key = service.export_server_key();

    println!("[ROTATE SERVER] {}", rotation);
    println!("[ROTATE SERVER] Old ServerKey: {}", b64(&old_server_key));
    println!("[ROTATE SERVER] New ServerKey: {}", b64(&new_server_key));
    println!("[ROTATE SERVER] New ServerKey ID: {}\n", service.server_key_id());

    // Verify decryption still works after server key rotation
    let decrypted1_after = service.decrypt(&envelope1).expect("Post-rotation decrypt failed");
    println!("[VERIFY AFTER SERVER ROTATION] User 1 data: {}\n", String::from_utf8_lossy(&decrypted1_after));

    // Rotate User 1's KEK
    println!("=== User KEK Rotation ===\n");
    let old_kek_id = envelope1.kek_id;
    let kek_rotation = service.rotate_user_kek(&user1_id).expect("KEK rotation failed");

    println!("[ROTATE USER KEK] {}", kek_rotation);
    println!("[ROTATE USER KEK] Old KEK ID: {}", old_kek_id);
    println!("[ROTATE USER KEK] New KEK ID: {}\n", kek_rotation.new_key_id);

    // Verify User 1's data can still be decrypted after KEK rotation
    let decrypted1_after_kek = service.decrypt(&envelope1).expect("Post-KEK-rotation decrypt failed");
    println!("[VERIFY AFTER KEK ROTATION] User 1 data: {}\n", String::from_utf8_lossy(&decrypted1_after_kek));

    // Stats
    let stats = service.get_stats().expect("Failed to get stats");
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
}
