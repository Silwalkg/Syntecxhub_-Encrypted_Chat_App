"""
crypto_utils.py
---------------
Handles all cryptographic operations:
  - Diffie-Hellman key exchange using RFC 3526 Group 14 (2048-bit safe prime)
  - AES-256-GCM authenticated encryption / decryption (confidentiality + integrity)
  - HKDF-SHA256 key derivation from DH shared secret

Security notes:
  - AES-GCM provides both encryption and authentication (AEAD) — no separate HMAC needed.
  - A fresh random 12-byte nonce is generated per message; reusing a nonce with the
    same key would be catastrophic, so os.urandom() is used exclusively.
  - The DH exchange uses precomputed RFC 3526 parameters (instant startup, same security
    as generating fresh 2048-bit params).
  - This implementation does NOT authenticate the DH handshake itself (no signatures),
    so it is vulnerable to an active man-in-the-middle who can intercept the TCP stream.
    Suitable for a trusted network / learning environment; production use would require
    certificate-based or SRP authentication of the handshake.
"""

import os
import json
import base64

from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


# ---------------------------------------------------------------------------
# RFC 3526 Group 14 — 2048-bit MODP safe prime (precomputed, instant startup)
# https://www.rfc-editor.org/rfc/rfc3526#section-3
# ---------------------------------------------------------------------------
_RFC3526_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
_RFC3526_G = 2


def get_dh_parameters():
    """
    Return DH parameters using the RFC 3526 Group 14 safe prime.
    Instant — no key generation required, same 2048-bit security as generating fresh params.
    """
    param_numbers = DHParameterNumbers(_RFC3526_P, _RFC3526_G)
    return param_numbers.parameters(default_backend())


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
# AES-256-GCM authenticated encryption / decryption
# ---------------------------------------------------------------------------

def encrypt_message(key: bytes, plaintext: str) -> str:
    """
    Encrypt a UTF-8 string with AES-256-GCM (AEAD).

    A fresh random 12-byte nonce is generated for every message.
    GCM produces a 16-byte authentication tag automatically — any
    bit-flip or tampering in transit will cause decryption to raise
    an InvalidTag exception rather than silently returning garbage.

    Returns a JSON string: {"nonce": <b64>, "ct": <b64>}
    The ciphertext bytes include the GCM auth tag appended by the library.
    """
    nonce = os.urandom(12)          # 96-bit nonce — GCM standard recommendation
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    payload = {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct":    base64.b64encode(ciphertext).decode("ascii"),
    }
    return json.dumps(payload)


def decrypt_message(key: bytes, token: str) -> str:
    """
    Decrypt and authenticate a token produced by encrypt_message().

    Raises:
      - ValueError  : malformed / unparseable token
      - cryptography.exceptions.InvalidTag : authentication failed (tampered ciphertext)
    """
    try:
        payload = json.loads(token)
        nonce      = base64.b64decode(payload["nonce"])
        ciphertext = base64.b64decode(payload["ct"])
    except Exception as exc:
        raise ValueError(f"Malformed message token: {exc}") from exc

    aesgcm = AESGCM(key)
    # Will raise InvalidTag if the ciphertext or tag has been modified
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext_bytes.decode("utf-8")
