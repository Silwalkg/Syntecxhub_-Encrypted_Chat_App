# 🔒 Encrypted Chat App

A client/server chat application where every message is encrypted **and authenticated** with **AES-256-GCM** before it leaves the client. Keys are never hard-coded — each session negotiates a fresh key via **Diffie-Hellman** key exchange using the RFC 3526 Group 14 safe prime.

---

## Features

| Feature | Details |
|---|---|
| Encryption | AES-256-GCM (AEAD — confidentiality + integrity in one primitive) |
| Message authentication | Built-in GCM auth tag — tampered ciphertext raises `InvalidTag`, never silently decrypts |
| Key Exchange | Diffie-Hellman (RFC 3526 Group 14, 2048-bit) + HKDF-SHA256 key derivation |
| Nonce handling | Fresh random 12-byte nonce per message (GCM standard) |
| Transport | TCP with length-prefixed framing |
| Concurrency | One thread per client (server-side) |
| Logging | All messages logged to `chat.log` with timestamps |
| UI | Colour terminal (Windows, macOS, Linux) |

---

## Project Structure

```
Encrypted Chat App/
├── server.py        ← Multi-client server
├── client.py        ← Terminal chat client
├── crypto_utils.py  ← DH key exchange + AES-256-GCM helpers
├── protocol.py      ← Length-prefixed TCP framing
├── requirements.txt
└── README.md
```

---

## Setup

```bash
# 1. (Recommended) Create a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS / Linux

# 2. Install dependencies
pip install -r requirements.txt
```

---

## Running

### Start the server
```bash
python server.py
# Options:
#   --host  bind address  (default: 0.0.0.0)
#   --port  port number   (default: 9999)
```

The server loads RFC 3526 DH parameters instantly (no slow key generation) and begins listening.

### Start a client (open a new terminal per client)
```bash
python client.py
# Options:
#   --host  server address  (default: 127.0.0.1)
#   --port  port number     (default: 9999)
```

To connect to a remote server:
```bash
python client.py --host 192.168.1.10 --port 9999
```

### Commands inside the chat
| Command | Action |
|---|---|
| *(any text)* | Send encrypted message |
| `/quit` | Disconnect and exit |

---

## How the Encryption Works

```
Client A                          Server                         Client B
   │                                │                                │
   │── DH params + server pubkey ──▶│                                │
   │◀─ client A pubkey sent ────────│                                │
   │   [shared_key_A derived]       │   [shared_key_A derived]       │
   │                                │                                │
   │══ AES-256-GCM(shared_key_A) ══▶│ decrypt+verify → log           │
   │                                │        → re-encrypt            │
   │                                │══ AES-256-GCM(shared_key_B) ══▶│
```

1. Server loads RFC 3526 Group 14 DH parameters at startup (instant).
2. Each client gets those parameters + the server's ephemeral public key.
3. Client sends its own ephemeral public key back.
4. Both sides independently derive the **same** 256-bit key using HKDF-SHA256.
5. Every message uses AES-256-GCM: a fresh random 12-byte nonce + a 16-byte authentication tag ensure both **confidentiality and integrity**.
6. The server decrypts and verifies each message (to log it), then re-encrypts it with each recipient's individual key before forwarding.

---

## Security Notes

### What this protects against
- **Eavesdropping** — AES-256-GCM encrypts all message content.
- **Tampering / bit-flipping** — GCM's authentication tag detects any modification in transit; tampered messages raise `InvalidTag` and are dropped.
- **Key reuse leaking plaintext** — a fresh nonce is generated per message via `os.urandom()`.

### Known limitations (intentional for a learning project)
- **Not end-to-end encrypted** — this is *client-to-server* + *server-to-client* encryption. The server decrypts every message to log and re-encrypt it. The server is a trusted relay that can read plaintext.
- **No handshake authentication** — the DH exchange has no signatures or certificates. An active man-in-the-middle who can intercept the TCP stream during the handshake could negotiate separate keys with each side. This is acceptable on a trusted/local network but would require certificate-based or SRP authentication for production use.

---

## Dependencies

- [`cryptography`](https://cryptography.io/) — DH, AES-GCM, HKDF
- [`colorama`](https://pypi.org/project/colorama/) — Cross-platform colour terminal output
