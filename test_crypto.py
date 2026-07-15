"""Quick smoke test — run with: python test_crypto.py"""
from crypto_utils import (
    get_dh_parameters, serialize_dh_parameters, deserialize_dh_parameters,
    generate_dh_keypair, serialize_public_key, deserialize_public_key,
    derive_shared_key, encrypt_message, decrypt_message,
)
from cryptography.exceptions import InvalidTag
import json, base64

params = get_dh_parameters()
pem = serialize_dh_parameters(params)
p2 = deserialize_dh_parameters(pem)

sp, spub = generate_dh_keypair(p2)
cp, cpub = generate_dh_keypair(p2)

sk = derive_shared_key(sp, deserialize_public_key(serialize_public_key(cpub)))
ck = derive_shared_key(cp, deserialize_public_key(serialize_public_key(spub)))
assert sk == ck, "Key mismatch"
print("DH key exchange: OK")

msg = "Hello, authenticated world!"
token = encrypt_message(ck, msg)
assert decrypt_message(sk, token) == msg
print("AES-256-GCM encrypt/decrypt: OK")

token2 = encrypt_message(ck, msg)
assert token != token2
print("Unique nonce per message: OK")

payload = json.loads(token)
ct = base64.b64decode(payload["ct"])
payload["ct"] = base64.b64encode(bytes([ct[0] ^ 0xFF]) + ct[1:]).decode()
try:
    decrypt_message(sk, json.dumps(payload))
    print("FAIL: tamper not detected")
except InvalidTag:
    print("Tamper detection (InvalidTag): OK")

print("\nAll checks passed.")
