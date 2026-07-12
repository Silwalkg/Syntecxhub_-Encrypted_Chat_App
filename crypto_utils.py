"""
crypto_utils.py
---------------
Handles all cryptographic operations:
  - Diffie-Hellman key exchange (2048-bit MODP group)
  - AES-256-CBC encryption / decryption with random IV per message
  - PKCS7 padding
"""

import os
import json
import base64

from cryptography.hazmat.primitives.asymmetric.dh import (
    DHParameterNumbers,
    DHPublicNumbers,
    DHPrivateNumbers,
    generate_parameters,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend


# ---------------------------------------------------------------------------
# Diffie-Hellman helpers
# ---------------------------------------------------------------------------

def generate_dh_parameters():
    """Generate 2048-bit DH parameters (done once on the server)."""
    params = generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return params


def serialize_dh_parameters(params) -> bytes:
    """Serialize DH parameters to PEM so they can be sent to clients."""
    return params.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3,
    )


def deserialize_dh_parameters(pem: bytes):
    """Load DH parameters from PEM bytes."""
    from cryptography.hazmat.primitives.serialization import load_pem_parameters
    return load_pem_parameters(pem, backend=default_backend())


def generate_dh_keypair(params):
    """Generate an ephemeral DH private/public key pair."""
    private_key = params.generate_private_key()
    return private_key, private_key.public_key()


def serialize_public_key(public_key) -> bytes:
    """Serialize a DH public key to PEM."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(pem: bytes):
    """Load a DH public key from PEM bytes."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    return load_pem_public_key(pem, backend=default_backend())


def derive_shared_key(private_key, peer_public_key) -> bytes:
    """
    Perform DH key exchange and derive a 32-byte AES key using HKDF-SHA256.
    Returns the derived key as raw bytes.
    """
    shared_secret = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,          # 256 bits → AES-256
        salt=None,
        info=b"encrypted-chat-v1",
        backend=default_backend(),
    ).derive(shared_secret)
    return derived_key


# ---------------------------------------------------------------------------
# AES-256-CBC encryption / decryption
# ---------------------------------------------------------------------------

def encrypt_message(key: bytes, plaintext: str) -> str:
    """
    Encrypt a UTF-8 string with AES-256-CBC.
    A fresh random 16-byte IV is generated for every message.
    Returns a Base64-encoded JSON string: {"iv": <b64>, "ct": <b64>}
    """
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    payload = {
        "iv": base64.b64encode(iv).decode("ascii"),
        "ct": base64.b64encode(ciphertext).decode("ascii"),
    }
    return json.dumps(payload)


def decrypt_message(key: bytes, token: str) -> str:
    """
    Decrypt a token produced by encrypt_message().
    Returns the original plaintext string.
    Raises ValueError on tampered / malformed data.
    """
    try:
        payload = json.loads(token)
        iv = base64.b64decode(payload["iv"])
        ciphertext = base64.b64decode(payload["ct"])
    except (KeyError, ValueError, Exception) as exc:
        raise ValueError(f"Malformed message token: {exc}") from exc

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode("utf-8")
