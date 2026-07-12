# 🔒 Encrypted Chat App

A client/server chat application where every message is encrypted with **AES-256-CBC** before it leaves the client. Keys are never hard-coded — each session negotiates a fresh key via **Diffie-Hellman** key exchange.

---

## Features

| Feature | Details |
|---|---|
| Encryption | AES-256-CBC |
| Key Exchange | Diffie-Hellman (2048-bit MODP) + HKDF-SHA256 key derivation |
| IV handling | Fresh random 16-byte IV per message |
| Transport | TCP with length-prefixed framing |
| Concurrency | One thread per client (server-side) |
| Logging | All messages logged to `chat.log` with timestamps |
| UI | Colour terminal (works on Windows, macOS, Linux) |

---

## Project Structure

```
Encrypted Chat App/
├── server.py        ← Multi-client server
├── client.py        ← Terminal chat client
├── crypto_utils.py  ← DH key exchange + AES-256-CBC helpers
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

The server will generate DH parameters on startup (takes ~1–2 seconds), then listen for connections.

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
   │══ AES-256-CBC(shared_key_A) ══▶│ decrypt → log → re-encrypt     │
   │                                │══ AES-256-CBC(shared_key_B) ══▶│
```

1. Server generates 2048-bit DH parameters once at startup.
2. Each connecting client gets those parameters + the server's ephemeral public key.
3. Client sends its own ephemeral public key back.
4. Both sides independently derive the **same** 256-bit AES key using HKDF-SHA256.
5. Every message uses a **fresh random IV** — same plaintext never produces the same ciphertext.
6. The server decrypts each message (to log it), then re-encrypts it with each recipient's individual key before forwarding.

---

## Dependencies

- [`cryptography`](https://cryptography.io/) — DH, AES, HKDF
- [`colorama`](https://pypi.org/project/colorama/) — Cross-platform colour terminal output
