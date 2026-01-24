"""
Exception classes for envelope encryption operations.

This module defines the exception hierarchy matching the Rust EnvelopeError enum.
"""

from __future__ import annotations


class EnvelopeError(Exception):
    """Base exception for all envelope encryption operations."""

    pass


class CryptoError(EnvelopeError):
    """Cryptographic operation failed (encryption, decryption, key generation)."""

    pass


class KeyNotFoundError(EnvelopeError):
    """Key not found in storage."""

    pass


class InvalidKeyStateError(EnvelopeError):
    """Key is in an invalid state for the requested operation."""

    pass


class StorageError(EnvelopeError):
    """Storage backend error (database, in-memory, etc.)."""

    pass


class SerializationError(EnvelopeError):
    """Serialization or deserialization error."""

    pass


class KeyRotationError(EnvelopeError):
    """Key rotation operation failed."""

    pass


class ConfigError(EnvelopeError):
    """Configuration error."""

    pass
