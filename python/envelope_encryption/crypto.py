"""
Cryptographic primitives for AES-256-GCM envelope encryption.

This module provides:
- SecureKey: Secure key wrapper with automatic zeroization
- EncryptedData: Encrypted payload with nonce and ciphertext
- AesGcmCipher: AES-256-GCM encryption/decryption operations
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import CryptoError

# Cryptographic constants
AES_256_KEY_SIZE: int = 32  # 256 bits
NONCE_SIZE: int = 12  # 96 bits (standard for AES-GCM)
TAG_SIZE: int = 16  # 128 bits (authentication tag)


class SecureKey:
    """
    Secure key wrapper with automatic memory cleanup on deletion.

    Uses bytearray internally for mutable zeroing in __del__.
    Note: Python's garbage collector doesn't guarantee immediate cleanup,
    so this is best-effort zeroization.
    """

    __slots__ = ("_bytes",)

    def __init__(self, key_bytes: bytes | bytearray) -> None:
        """
        Create a SecureKey from raw bytes.

        Args:
            key_bytes: Raw key material (should be 32 bytes for AES-256)
        """
        if not isinstance(key_bytes, (bytes, bytearray)):
            raise CryptoError("Key must be bytes or bytearray")
        self._bytes = bytearray(key_bytes)

    @classmethod
    def generate(cls) -> SecureKey:
        """Generate a cryptographically secure random 32-byte key."""
        return cls(secrets.token_bytes(AES_256_KEY_SIZE))

    def as_bytes(self) -> bytes:
        """Return key as immutable bytes."""
        return bytes(self._bytes)

    def __len__(self) -> int:
        """Return key length in bytes."""
        return len(self._bytes)

    def __repr__(self) -> str:
        """Redacted representation to prevent accidental key disclosure."""
        return "SecureKey([REDACTED])"

    def __del__(self) -> None:
        """Zero memory on deletion (best-effort)."""
        if hasattr(self, "_bytes"):
            for i in range(len(self._bytes)):
                self._bytes[i] = 0


@dataclass
class EncryptedData:
    """
    Encrypted data container with nonce and ciphertext.

    The ciphertext includes the 16-byte authentication tag appended by AESGCM.
    """

    nonce: bytes  # 12 bytes
    ciphertext: bytes  # Ciphertext + 16-byte auth tag

    def to_aead_blob(self) -> bytes:
        """
        Convert to industry-standard AEAD blob format: nonce || ciphertext || tag.

        For AES-256-GCM encrypting a 32-byte key: 12 + 32 + 16 = 60 bytes total.
        """
        return self.nonce + self.ciphertext

    @classmethod
    def from_aead_blob(cls, blob: bytes) -> EncryptedData:
        """
        Parse from AEAD blob format: nonce || ciphertext || tag.

        Args:
            blob: Raw AEAD blob bytes

        Returns:
            EncryptedData instance

        Raises:
            CryptoError: If blob is too small
        """
        min_size = NONCE_SIZE + TAG_SIZE
        if len(blob) < min_size:
            raise CryptoError(
                f"AEAD blob too small: expected at least {min_size} bytes, got {len(blob)}"
            )
        return cls(nonce=blob[:NONCE_SIZE], ciphertext=blob[NONCE_SIZE:])

    def to_base64(self) -> str:
        """Encode as base64 string."""
        return base64.standard_b64encode(self.to_aead_blob()).decode("ascii")

    @classmethod
    def from_base64(cls, encoded: str) -> EncryptedData:
        """
        Decode from base64 string.

        Args:
            encoded: Base64-encoded AEAD blob

        Returns:
            EncryptedData instance

        Raises:
            CryptoError: If decoding fails or data is invalid
        """
        try:
            decoded = base64.standard_b64decode(encoded)
        except Exception as e:
            raise CryptoError(f"Base64 decode error: {e}")

        min_size = NONCE_SIZE + TAG_SIZE
        if len(decoded) < min_size:
            raise CryptoError("Invalid encrypted data length")

        return cls(nonce=decoded[:NONCE_SIZE], ciphertext=decoded[NONCE_SIZE:])


class AesGcmCipher:
    """
    AES-256-GCM authenticated encryption.

    Provides static methods for encryption and decryption with optional
    Additional Authenticated Data (AAD) for binding.
    """

    @staticmethod
    def encrypt(
        key: SecureKey,
        plaintext: bytes,
        aad: Optional[bytes] = None,
    ) -> EncryptedData:
        """
        Encrypt plaintext with AES-256-GCM.

        Args:
            key: 32-byte encryption key
            plaintext: Data to encrypt
            aad: Optional Additional Authenticated Data for binding

        Returns:
            EncryptedData with nonce and ciphertext (includes auth tag)

        Raises:
            CryptoError: If key size is invalid or encryption fails
        """
        if len(key) != AES_256_KEY_SIZE:
            raise CryptoError(
                f"Invalid key size: expected {AES_256_KEY_SIZE}, got {len(key)}"
            )

        nonce = secrets.token_bytes(NONCE_SIZE)
        aesgcm = AESGCM(key.as_bytes())

        try:
            ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        except Exception as e:
            raise CryptoError(f"Encryption error: {e}")

        return EncryptedData(nonce=nonce, ciphertext=ciphertext)

    @staticmethod
    def decrypt(
        key: SecureKey,
        encrypted: EncryptedData,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """
        Decrypt ciphertext with AES-256-GCM.

        Args:
            key: 32-byte decryption key
            encrypted: EncryptedData with nonce and ciphertext
            aad: Optional Additional Authenticated Data (must match encryption)

        Returns:
            Decrypted plaintext bytes

        Raises:
            CryptoError: If key/nonce size is invalid or decryption fails
        """
        if len(key) != AES_256_KEY_SIZE:
            raise CryptoError(
                f"Invalid key size: expected {AES_256_KEY_SIZE}, got {len(key)}"
            )

        if len(encrypted.nonce) != NONCE_SIZE:
            raise CryptoError(
                f"Invalid nonce size: expected {NONCE_SIZE}, got {len(encrypted.nonce)}"
            )

        aesgcm = AESGCM(key.as_bytes())

        try:
            return aesgcm.decrypt(encrypted.nonce, encrypted.ciphertext, aad)
        except Exception:
            # Generic error to prevent oracle attacks
            raise CryptoError("Decryption failed")


def generate_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.

    Args:
        length: Number of bytes to generate

    Returns:
        Random bytes of specified length
    """
    return secrets.token_bytes(length)
