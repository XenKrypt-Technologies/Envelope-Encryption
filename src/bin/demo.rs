//! Envelope Encryption Demo
//! 
//! This binary demonstrates the full capabilities of the envelope encryption library.

use envelope_encryption::prelude::*;
use std::sync::Arc;
use uuid::Uuid;
use std::collections::HashMap;

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║         ENVELOPE ENCRYPTION DEMO - HSM-like Key Mgmt        ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // Initialize the encryption service with in-memory storage
    println!("📦 Initializing envelope encryption service...");
    let storage = Arc::new(InMemoryStorage::new());
    let mut service = EnvelopeEncryption::new(Arc::clone(&storage))
        .expect("Failed to create encryption service");
    
    // Initialize with default KEK
    let default_kek = service.initialize().expect("Failed to initialize");
    println!("   ✓ Master Key (MK) created: v{}", service.master_key_version());
    println!("   ✓ Default KEK created: {}", default_kek);
    println!();

    // ========================================================================
    // Demo 1: Basic Encryption/Decryption
    // ========================================================================
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📝 DEMO 1: Basic Envelope Encryption");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    let secret_message = "This is a highly confidential message! 🔐";
    println!("   Original: \"{}\"", secret_message);
    
    let envelope = service
        .encrypt(secret_message.as_bytes(), None, None)
        .expect("Encryption failed");
    
    println!("   Encrypted envelope:");
    println!("      Data ID:  {}", envelope.data_id);
    println!("      DEK ID:   {}", envelope.dek_id);
    println!("      KEK ID:   {}", envelope.kek_id);
    println!("      Ciphertext (base64): {}...", 
             &envelope.ciphertext_base64()[..50]);
    
    let decrypted = service.decrypt(&envelope).expect("Decryption failed");
    let decrypted_str = String::from_utf8(decrypted).expect("Invalid UTF-8");
    println!("   Decrypted: \"{}\"", decrypted_str);
    println!("   ✓ Encryption/Decryption successful!");
    println!();

    // ========================================================================
    // Demo 2: Multiple Documents with Metadata
    // ========================================================================
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📁 DEMO 2: Multiple Documents with Metadata");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    let documents = vec![
        ("Financial Report Q4 2024", "Revenue: $1.5M, Profit: $300K"),
        ("Employee Records", "John Doe, SSN: XXX-XX-XXXX"),
        ("Strategic Plan", "Expand to European market by 2026"),
    ];
    
    let mut encrypted_docs = Vec::new();
    
    for (title, content) in &documents {
        let data_id = Uuid::new_v4();
        let mut metadata = HashMap::new();
        metadata.insert("title".to_string(), title.to_string());
        metadata.insert("classification".to_string(), "CONFIDENTIAL".to_string());
        
        let envelope = service
            .encrypt(content.as_bytes(), Some(data_id), Some(metadata))
            .expect("Encryption failed");
        
        println!("   📄 Encrypted: \"{}\"", title);
        println!("      → Data ID: {}", envelope.data_id);
        
        encrypted_docs.push((title.to_string(), envelope));
    }
    
    // Decrypt by ID
    println!();
    println!("   Retrieving document by ID...");
    let (title, first_doc) = &encrypted_docs[0];
    let retrieved = service
        .decrypt_by_id(&first_doc.data_id)
        .expect("Decryption failed");
    println!("   ✓ Retrieved \"{}\": \"{}\"", title, 
             String::from_utf8(retrieved).unwrap());
    println!();

    // ========================================================================
    // Demo 3: Key Hierarchy and Statistics
    // ========================================================================
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("🔑 DEMO 3: Key Hierarchy Overview");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    let stats = service.get_stats().expect("Failed to get stats");
    println!("{}", stats);

    // ========================================================================
    // Demo 4: Multiple KEKs (Department Isolation)
    // ========================================================================
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("🏢 DEMO 4: Department Isolation with Multiple KEKs");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    // Create KEKs for different departments
    let hr_kek = service.generate_kek().expect("Failed to generate HR KEK");
    let finance_kek = service.generate_kek().expect("Failed to generate Finance KEK");
    
    println!("   Created department KEKs:");
    println!("      HR KEK:      {}", hr_kek);
    println!("      Finance KEK: {}", finance_kek);
    
    // Encrypt department-specific data
    let hr_data = "Employee performance reviews - CONFIDENTIAL";
    let finance_data = "Annual budget allocation - RESTRICTED";
    
    let hr_envelope = service
        .encrypt_with_kek(hr_data.as_bytes(), &hr_kek, None, None)
        .expect("HR encryption failed");
    
    let finance_envelope = service
        .encrypt_with_kek(finance_data.as_bytes(), &finance_kek, None, None)
        .expect("Finance encryption failed");
    
    println!("   ✓ HR data encrypted with HR KEK");
    println!("   ✓ Finance data encrypted with Finance KEK");
    
    // Verify both decrypt correctly
    let _ = service.decrypt(&hr_envelope).expect("HR decryption failed");
    let _ = service.decrypt(&finance_envelope).expect("Finance decryption failed");
    
    println!("   ✓ Both departments' data accessible");
    println!();

    // ========================================================================
    // Demo 5: Master Key Rotation
    // ========================================================================
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("🔄 DEMO 5: Master Key Rotation");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    println!("   Current Master Key version: v{}", service.master_key_version());
    println!("   Rotating Master Key...");
    
    let rotation_result = service
        .rotate_master_key()
        .expect("Master key rotation failed");
    
    println!("   ✓ {}", rotation_result);
    println!("   New Master Key version: v{}", service.master_key_version());
    
    // Verify all data still accessible after rotation
    println!("   Verifying data accessibility post-rotation...");
    let test_decrypted = service.decrypt(&envelope).expect("Post-rotation decrypt failed");
    assert_eq!(secret_message.as_bytes(), test_decrypted.as_slice());
    println!("   ✓ Original message still accessible");
    
    let hr_test = service.decrypt(&hr_envelope).expect("HR post-rotation failed");
    assert_eq!(hr_data.as_bytes(), hr_test.as_slice());
    println!("   ✓ HR data still accessible");
    println!();

    // ========================================================================
    // Demo 6: KEK Rotation
    // ========================================================================
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("🔄 DEMO 6: KEK Rotation (Re-wrapping DEKs)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    println!("   Rotating HR KEK...");
    let kek_rotation = service
        .rotate_kek(&hr_kek)
        .expect("KEK rotation failed");
    
    println!("   ✓ {}", kek_rotation);
    
    // Verify HR data still accessible
    let hr_post_rotation = service.decrypt(&hr_envelope).expect("Post-KEK-rotation failed");
    assert_eq!(hr_data.as_bytes(), hr_post_rotation.as_slice());
    println!("   ✓ HR data still accessible after KEK rotation");
    println!();

    // ========================================================================
    // Demo 7: Stateless/Derived Key Mode
    // ========================================================================
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("🧮 DEMO 7: Stateless Encryption (HKDF-derived DEKs)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    let data_id = Uuid::new_v4();
    let stateless_data = "Data encrypted with derived key - no DEK storage needed";
    
    println!("   Data ID: {}", data_id);
    println!("   Note: DEK is derived from Master Key + Data ID using HKDF-SHA256");
    println!("   (This is the upgraded approach from HMAC-SHA256 key derivation)");
    
    let encrypted = service
        .encrypt_stateless(stateless_data.as_bytes(), &data_id)
        .expect("Stateless encryption failed");
    
    println!("   ✓ Encrypted (no DEK stored)");
    
    let decrypted = service
        .decrypt_stateless(&encrypted, &data_id)
        .expect("Stateless decryption failed");
    
    assert_eq!(stateless_data.as_bytes(), decrypted.as_slice());
    println!("   ✓ Decrypted successfully using derived key");
    
    // Demonstrate determinism
    let encrypted2 = service
        .encrypt_stateless(stateless_data.as_bytes(), &data_id)
        .expect("Second encryption failed");
    
    let decrypted2 = service
        .decrypt_stateless(&encrypted2, &data_id)
        .expect("Second decryption failed");
    
    assert_eq!(stateless_data.as_bytes(), decrypted2.as_slice());
    println!("   ✓ Same Data ID produces same DEK (different nonce)");
    println!();

    // ========================================================================
    // Demo 8: JSON Serialization
    // ========================================================================
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📋 DEMO 8: Envelope Serialization (for transmission/storage)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    let json = envelope.to_json().expect("Serialization failed");
    println!("   JSON representation:");
    println!("   {}", json);
    
    let restored = EncryptedEnvelope::from_json(&json).expect("Deserialization failed");
    let restored_plaintext = service.decrypt(&restored).expect("Decrypt restored failed");
    assert_eq!(secret_message.as_bytes(), restored_plaintext.as_slice());
    println!("   ✓ Successfully restored and decrypted from JSON");
    println!();

    // ========================================================================
    // Final Statistics
    // ========================================================================
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📊 Final Key Hierarchy Statistics");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    let final_stats = service.get_stats().expect("Failed to get stats");
    println!("{}", final_stats);

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                    DEMO COMPLETE! ✅                         ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("Key features demonstrated:");
    println!("  • AES-256-GCM authenticated encryption");
    println!("  • Three-tier key hierarchy (MK → KEK → DEK)");
    println!("  • Master Key rotation with automatic KEK re-wrapping");
    println!("  • KEK rotation with automatic DEK re-wrapping");
    println!("  • Department isolation using multiple KEKs");
    println!("  • Stateless encryption with HKDF-derived keys");
    println!("  • JSON serialization for envelope transport");
    println!("  • In-memory storage (ready for PostgreSQL extension)");
}

