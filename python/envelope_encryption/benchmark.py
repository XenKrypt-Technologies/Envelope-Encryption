"""
Envelope Encryption Benchmark CLI.

Usage:
    envelope-benchmark

Or run directly:
    python -m envelope_encryption.benchmark

PostgreSQL setup:
    1. Run schema: psql -U postgres -f schema.sql
    2. Set DATABASE_URL environment variable or .env file
"""

from __future__ import annotations

import asyncio
import os
import random
import sys
import time
from pathlib import Path
from uuid import uuid4

import asyncpg
from dotenv import load_dotenv

from envelope_encryption.crypto import AesGcmCipher
from envelope_encryption.postgres import PostgresEnvelopeService, PostgresStorage


async def run_benchmark() -> None:
    """Run the envelope encryption benchmark."""
    print("=== Envelope Encryption Benchmark ===\n")

    # Load environment variables
    load_dotenv()

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        print("ERROR: DATABASE_URL must be set in environment or .env file")
        sys.exit(1)

    # Connect to PostgreSQL
    pool = await asyncpg.create_pool(database_url)
    if pool is None:
        print("ERROR: Failed to create connection pool")
        sys.exit(1)

    # Truncate tables on startup (if they exist)
    truncate_start = time.perf_counter()
    try:
        await pool.execute("TRUNCATE TABLE user_keks CASCADE")
        truncate_duration = (time.perf_counter() - truncate_start) * 1000
        print(f"[STARTUP] Tables truncated in {truncate_duration:.3f}ms")
    except Exception:
        print("[STARTUP] Tables will be created automatically")

    # Get test quantity from user
    try:
        user_input = input("Enter number of users to test (default: 125): ").strip()
        test_quantity = int(user_input) if user_input else 125
    except ValueError:
        test_quantity = 125
    print(f"Testing with {test_quantity} users\n")

    # Initialize storage and service
    storage = PostgresStorage(pool)
    service = await PostgresEnvelopeService.new(storage)

    print("=" * 70)
    print("                    BENCHMARK START")
    print("=" * 70 + "\n")

    # ========================================================================
    # Demo 1: Create users with KEKs
    # ========================================================================
    print("+" + "-" * 68 + "+")
    print(f"|  Demo 1: Create {test_quantity} Users with KEKs" + " " * (35 - len(str(test_quantity))) + "|")
    print("+" + "-" * 68 + "+")

    user_ids = []

    demo1_start = time.perf_counter()
    for i in range(test_quantity):
        user_id = uuid4()
        user_ids.append(user_id)
        await service.generate_dek(user_id)

        if (i + 1) % 25 == 0 or (i + 1) == test_quantity:
            print(f"  Progress: {i + 1}/{test_quantity}")

    demo1_duration = time.perf_counter() - demo1_start

    print(f"[OK] Created {test_quantity} users with ACTIVE KEKs")
    print(f"[PERF] Time: {demo1_duration * 1000:.3f}ms | Rate: {test_quantity / demo1_duration:.2f} ops/sec\n")

    # ========================================================================
    # Demo 2: Test basic encryption/decryption
    # ========================================================================
    print("+" + "-" * 68 + "+")
    print("|  Demo 2: Encryption/Decryption Benchmark                          |")
    print("+" + "-" * 68 + "+")

    test_user = user_ids[0]
    user_dek = await service.generate_dek(test_user)
    plaintext = b"Sensitive data protected by envelope encryption"
    content_id = uuid4()

    encrypt_start = time.perf_counter()
    encrypted = AesGcmCipher.encrypt(user_dek.dek, plaintext, content_id.bytes)
    encrypt_time = time.perf_counter() - encrypt_start

    decrypt_start = time.perf_counter()
    recovered_dek = await service.decrypt_edek(
        user_dek.dek_id,
        user_dek.edek_blob,
        test_user,
        user_dek.kek_version,
    )
    edek_decrypt_time = time.perf_counter() - decrypt_start

    decrypt_data_start = time.perf_counter()
    _decrypted = AesGcmCipher.decrypt(recovered_dek, encrypted, content_id.bytes)
    data_decrypt_time = time.perf_counter() - decrypt_data_start

    print("[OK] Data encrypted/decrypted successfully")
    print(f"[PERF] Encryption:      {encrypt_time * 1000:.3f}ms ({1.0 / encrypt_time:.2f} ops/sec)")
    print(f"[PERF] EDEK Decryption: {edek_decrypt_time * 1000:.3f}ms ({1.0 / edek_decrypt_time:.2f} ops/sec)")
    print(f"[PERF] Data Decryption: {data_decrypt_time * 1000:.3f}ms ({1.0 / data_decrypt_time:.2f} ops/sec)\n")

    # ========================================================================
    # Demo 3: Bulk KEK Rotation
    # ========================================================================
    print("+" + "-" * 68 + "+")
    print(f"|  Demo 3: Bulk KEK Rotation ({test_quantity} KEKs)" + " " * (40 - len(str(test_quantity))) + "|")
    print("+" + "-" * 68 + "+")

    demo3_start = time.perf_counter()
    rotation_result = await service.bulk_rotate_all_keks()
    demo3_duration = time.perf_counter() - demo3_start

    print("[OK] Bulk rotation complete")
    print(f"[PERF] Time: {demo3_duration * 1000:.3f}ms | Rate: {rotation_result.keks_rotated / demo3_duration:.2f} ops/sec")
    print(f"[DEBUG] KEKs marked RETIRED: {rotation_result.keks_marked_retired}")
    print(f"[DEBUG] KEKs rotated: {rotation_result.keks_rotated}\n")

    # ========================================================================
    # Demo 4: Lazy Rotation - Random User Access
    # ========================================================================
    print("+" + "-" * 68 + "+")
    print("|  Demo 4: Lazy Rotation Test                                       |")
    print("+" + "-" * 68 + "+")

    sample_size = min(10, test_quantity)
    random_users = list(user_ids[:sample_size])
    random.shuffle(random_users)
    test_sample = min(5, len(random_users))
    random_users = random_users[:test_sample]

    demo4_start = time.perf_counter()
    for idx, user_id in enumerate(random_users):
        user_start = time.perf_counter()
        dek = await service.generate_dek(user_id)
        user_time = time.perf_counter() - user_start

        print(f"  User {idx + 1}/{test_sample}: KEK v{dek.kek_version} | {user_time * 1000:.3f}ms ({1.0 / user_time:.2f} ops/sec)")

    demo4_duration = time.perf_counter() - demo4_start

    print(f"[OK] All {test_sample} users successfully generated DEKs")
    print(f"[PERF] Average: {demo4_duration * 1000 / test_sample:.3f}ms per user\n")

    # ========================================================================
    # Demo 5: Verify Old KEKs Can Still Decrypt
    # ========================================================================
    print("+" + "-" * 68 + "+")
    print("|  Demo 5: Backward Compatibility Test                              |")
    print("+" + "-" * 68 + "+")

    demo5_start = time.perf_counter()
    _old_dek = await service.decrypt_edek(
        user_dek.dek_id,
        user_dek.edek_blob,
        test_user,
        user_dek.kek_version,
    )
    demo5_duration = time.perf_counter() - demo5_start

    print(f"[OK] Old KEK (v{user_dek.kek_version}) can still decrypt EDEKs")
    print(f"[PERF] EDEK Decryption (old KEK): {demo5_duration * 1000:.3f}ms ({1.0 / demo5_duration:.2f} ops/sec)\n")

    # ========================================================================
    # Demo 6: KEK Lifecycle Management
    # ========================================================================
    print("+" + "-" * 68 + "+")
    print("|  Demo 6: KEK Lifecycle (Disable/Delete)                           |")
    print("+" + "-" * 68 + "+")

    manage_user_idx = min(10, test_quantity - 1)
    manage_user = user_ids[manage_user_idx]

    demo6_start = time.perf_counter()
    try:
        result = await service.disable_kek(manage_user, 1)
        disable_time = (time.perf_counter() - demo6_start) * 1000

        if result:
            print("[OK] KEK disabled")
            print(f"[PERF] Disable: {disable_time:.3f}ms ({1000.0 / disable_time:.2f} ops/sec)")

            delete_start = time.perf_counter()
            try:
                deleted = await service.delete_kek(manage_user, 1)
                delete_time = (time.perf_counter() - delete_start) * 1000

                if deleted:
                    print("[OK] KEK deleted")
                    print(f"[PERF] Delete: {delete_time:.3f}ms ({1000.0 / delete_time:.2f} ops/sec)\n")
            except Exception as e:
                print(f"[ERROR] Delete failed: {e}\n")
    except Exception as e:
        print(f"[ERROR] Disable failed: {e}\n")

    # ========================================================================
    # Summary
    # ========================================================================
    print("=" * 70)
    print("                    BENCHMARK SUMMARY")
    print("=" * 70 + "\n")

    final_stats = await service.get_kek_stats()
    print("KEK Statistics:")
    for status, count in final_stats:
        print(f"  - {status}: {count}")

    print("\n+- Performance Summary (HSM-Style) ---------------------------------+")
    print("|                                                                    |")

    kek_rate = f"{test_quantity / demo1_duration:.2f}"
    print(f"|  KEK Creation:      {kek_rate} ops/sec" + " " * (33 - len(kek_rate)) + "|")

    enc_rate = f"{1.0 / encrypt_time:.2f}"
    print(f"|  Encryption:        {enc_rate} ops/sec" + " " * (33 - len(enc_rate)) + "|")

    dec_rate = f"{1.0 / data_decrypt_time:.2f}"
    print(f"|  Decryption:        {dec_rate} ops/sec" + " " * (33 - len(dec_rate)) + "|")

    rot_rate = f"{rotation_result.keks_rotated / demo3_duration:.2f}"
    print(f"|  KEK Rotation:      {rot_rate} ops/sec" + " " * (33 - len(rot_rate)) + "|")

    print("|                                                                    |")
    print("+--------------------------------------------------------------------+")

    print("\nTest Configuration:")
    print(f"  - Total users tested: {test_quantity}")
    print("  - Crypto: AES-256-GCM with AEAD")
    print("  - KEK lifecycle: ACTIVE -> RETIRED -> DISABLED -> Deleted")
    print("  - Rotation: Bulk (batches of 50) + Lazy (on-access)")

    print("\n" + "=" * 70)
    print("                    BENCHMARK COMPLETE")
    print("=" * 70 + "\n")

    await pool.close()


def main() -> None:
    """CLI entry point for envelope-benchmark command."""
    asyncio.run(run_benchmark())


if __name__ == "__main__":
    main()
