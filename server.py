"""
server.py
---------
Multi-client encrypted chat server.

Startup sequence per client:
  1. Send DH parameters (PEM)
  2. Send server's DH public key (PEM)
  3. Receive client's DH public key (PEM)
  4. Derive shared AES-256-GCM key via HKDF-SHA256
  5. Receive client's chosen username (encrypted + authenticated)
  6. Relay encrypted messages to all other connected clients

Security model:
  - Each client-server channel is encrypted and authenticated with AES-256-GCM.
  - This is client-to-server and server-to-client encryption (NOT end-to-end).
    The server decrypts each message to log it, then re-encrypts it per recipient.
    The server is a trusted relay — it can read plaintext messages.
  - The DH handshake is unauthenticated (no signatures/certificates), so an
    active man-in-the-middle on the TCP stream could intercept keys. Suitable
    for a trusted network or learning environment.

Usage:
    python server.py [--host HOST] [--port PORT]
"""

import socket
import threading
import argparse
import logging
from datetime import datetime
from pathlib import Path

import colorama
from colorama import Fore, Style

from crypto_utils import (
    get_dh_parameters,
    serialize_dh_parameters,
    generate_dh_keypair,
    serialize_public_key,
    deserialize_public_key,
    derive_shared_key,
    encrypt_message,
    decrypt_message,
)
from protocol import send_msg, recv_msg

colorama.init(autoreset=True)

# ---------------------------------------------------------------------------
# Logging — file only (verbose), console output handled by coloured prints
# ---------------------------------------------------------------------------
LOG_FILE = Path("chat.log")

_file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
_file_handler.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-8s  %(message)s"))

log = logging.getLogger("server")
log.setLevel(logging.INFO)
log.addHandler(_file_handler)
log.propagate = False   # prevent root-logger from echoing to the console


# ---------------------------------------------------------------------------
# Shared state (protected by a lock)
# ---------------------------------------------------------------------------
clients_lock = threading.Lock()
# { conn: {"username": str, "key": bytes, "addr": tuple} }
clients: dict = {}

# Serialise console output across threads
print_lock = threading.Lock()


def cprint(colour: str, msg: str) -> None:
    """Thread-safe coloured print."""
    with print_lock:
        print(colour + msg + Style.RESET_ALL)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def broadcast(sender_conn: socket.socket, plaintext: str) -> None:
    """Re-encrypt plaintext for every client except the sender."""
    dead = []
    with clients_lock:
        targets = dict(clients)

    for conn, info in targets.items():
        if conn is sender_conn:
            continue
        try:
            send_msg(conn, encrypt_message(info["key"], plaintext))
        except Exception:
            dead.append(conn)

    for conn in dead:
        remove_client(conn)


def remove_client(conn: socket.socket) -> None:
    with clients_lock:
        info = clients.pop(conn, None)
    if info:
        username = info["username"]
        online = len(clients)
        log.info("[-] %s disconnected. Online: %d", username, online)
        cprint(Fore.RED, f"  [-] {username} disconnected.  Online: {online}")
        broadcast(conn, f"[SERVER] {username} has left the chat.")
    try:
        conn.close()
    except Exception:
        pass


def server_banner() -> None:
    print(Fore.CYAN  + "=" * 58)
    print(Fore.CYAN  + "        🔒  Encrypted Chat Server  🔒")
    print(Fore.CYAN  + "=" * 58)
    print(Fore.YELLOW + "  AES-256-GCM (AEAD)  |  Diffie-Hellman key exchange")
    print(Fore.YELLOW + f"  Log → {LOG_FILE.resolve()}")
    print(Fore.CYAN  + "=" * 58 + Style.RESET_ALL)


# ---------------------------------------------------------------------------
# Per-client handler
# ---------------------------------------------------------------------------

def handle_client(conn: socket.socket, addr: tuple, dh_params) -> None:
    """Run DH handshake, register client, then relay messages."""
    username = "unknown"
    try:
        # 1. Send DH parameters
        send_msg(conn, serialize_dh_parameters(dh_params).decode("utf-8"))

        # 2. Ephemeral server keypair → send public key
        srv_priv, srv_pub = generate_dh_keypair(dh_params)
        send_msg(conn, serialize_public_key(srv_pub).decode("utf-8"))

        # 3. Receive client public key
        client_public = deserialize_public_key(recv_msg(conn).encode("utf-8"))

        # 4. Derive shared key
        shared_key = derive_shared_key(srv_priv, client_public)
        log.info("[+] Key exchange OK  %s:%s", *addr)

        # 5. Receive username (first encrypted message)
        username = decrypt_message(shared_key, recv_msg(conn))

        with clients_lock:
            clients[conn] = {"username": username, "key": shared_key, "addr": addr}

        online = len(clients)
        log.info("[+] '%s' joined from %s:%s  online=%d", username, addr[0], addr[1], online)
        cprint(Fore.GREEN, f"  [+] {username} joined ({addr[0]})  —  online: {online}")

        send_msg(conn, encrypt_message(shared_key,
                 f"[SERVER] Welcome, {username}! {online} user(s) online."))
        broadcast(conn, f"[SERVER] {username} has joined the chat.")

        # 6. Message relay loop
        while True:
            plaintext = decrypt_message(shared_key, recv_msg(conn))
            timestamp = datetime.now().strftime("%H:%M:%S")
            formatted = f"[{timestamp}] {username}: {plaintext}"

            log.info("MSG  %s", formatted)
            cprint(Fore.WHITE, f"  {formatted}")

            broadcast(conn, formatted)

    except (ConnectionError, OSError):
        pass
    except Exception as exc:
        log.warning("Error with %s: %s", addr, exc)
    finally:
        remove_client(conn)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypted Chat Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9999)
    args = parser.parse_args()

    server_banner()

    print(Fore.YELLOW + "  Loading RFC 3526 DH parameters … ", end="", flush=True)
    dh_params = get_dh_parameters()
    print(Fore.GREEN + "done." + Style.RESET_ALL)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(10)

    print(Fore.CYAN + f"\n  Listening on {args.host}:{args.port}  (Ctrl-C to stop)\n"
          + Style.RESET_ALL)
    log.info("Server listening on %s:%d", args.host, args.port)

    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_client,
                             args=(conn, addr, dh_params),
                             daemon=True).start()
    except KeyboardInterrupt:
        print(Fore.RED + "\n  Server shutting down.")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
