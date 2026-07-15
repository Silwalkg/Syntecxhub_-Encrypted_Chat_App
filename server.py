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
import json
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
# Logging setup – messages go to both console and chat.log
# ---------------------------------------------------------------------------
LOG_FILE = Path("chat.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("server")


# ---------------------------------------------------------------------------
# Shared state (protected by a lock)
# ---------------------------------------------------------------------------
clients_lock = threading.Lock()
# { conn: {"username": str, "key": bytes, "addr": tuple} }
clients: dict = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def broadcast(sender_conn: socket.socket, plaintext: str) -> None:
    """
    Re-encrypt plaintext for every client except the sender and send it.
    Removes dead clients on the fly.
    """
    dead = []
    with clients_lock:
        targets = dict(clients)   # snapshot

    for conn, info in targets.items():
        if conn is sender_conn:
            continue
        try:
            token = encrypt_message(info["key"], plaintext)
            send_msg(conn, token)
        except Exception:
            dead.append(conn)

    for conn in dead:
        remove_client(conn)


def remove_client(conn: socket.socket) -> None:
    with clients_lock:
        info = clients.pop(conn, None)
    if info:
        username = info["username"]
        log.info("[-] %s disconnected. Online: %d", username, len(clients))
        notify = f"[SERVER] {username} has left the chat."
        broadcast(conn, notify)
    try:
        conn.close()
    except Exception:
        pass


def server_banner() -> None:
    print(Fore.CYAN + "=" * 60)
    print(Fore.CYAN + "       🔒  Encrypted Chat Server  🔒")
    print(Fore.CYAN + "=" * 60)
    print(Fore.YELLOW + "  AES-256-GCM (AEAD)  |  Diffie-Hellman key exchange")
    print(Fore.YELLOW + f"  Log file : {LOG_FILE.resolve()}")
    print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)


# ---------------------------------------------------------------------------
# Per-client handler
# ---------------------------------------------------------------------------

def handle_client(conn: socket.socket, addr: tuple, dh_params) -> None:
    """Run DH handshake, register client, then relay messages."""
    username = "unknown"
    try:
        # ---- 1. Send DH parameters ----------------------------------------
        params_pem = serialize_dh_parameters(dh_params)
        send_msg(conn, params_pem.decode("utf-8"))

        # ---- 2. Generate ephemeral keypair & send public key ---------------
        server_private, server_public = generate_dh_keypair(dh_params)
        send_msg(conn, serialize_public_key(server_public).decode("utf-8"))

        # ---- 3. Receive client public key ----------------------------------
        client_pub_pem = recv_msg(conn).encode("utf-8")
        client_public_key = deserialize_public_key(client_pub_pem)

        # ---- 4. Derive shared key ------------------------------------------
        shared_key = derive_shared_key(server_private, client_public_key)
        log.info("[+] Key exchange complete with %s:%s", *addr)

        # ---- 5. Receive username (first encrypted message) -----------------
        token = recv_msg(conn)
        username = decrypt_message(shared_key, token)

        with clients_lock:
            clients[conn] = {"username": username, "key": shared_key, "addr": addr}

        log.info("[+] '%s' joined from %s:%s. Online: %d", username, addr[0], addr[1], len(clients))
        print(Fore.GREEN + f"  [+] {username} joined ({addr[0]}:{addr[1]}). "
              f"Total online: {len(clients)}")

        welcome = f"[SERVER] Welcome, {username}! {len(clients)} user(s) online."
        send_msg(conn, encrypt_message(shared_key, welcome))

        join_notice = f"[SERVER] {username} has joined the chat."
        broadcast(conn, join_notice)

        # ---- 6. Message relay loop ----------------------------------------
        while True:
            token = recv_msg(conn)
            plaintext = decrypt_message(shared_key, token)

            timestamp = datetime.now().strftime("%H:%M:%S")
            formatted = f"[{timestamp}] {username}: {plaintext}"
            log.info("MSG  %s", formatted)
            print(Fore.WHITE + f"  {formatted}")

            broadcast(conn, formatted)

    except (ConnectionError, OSError):
        pass
    except Exception as exc:
        log.warning("Error handling client %s: %s", addr, exc)
    finally:
        remove_client(conn)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypted Chat Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=9999, help="Port (default: 9999)")
    args = parser.parse_args()

    server_banner()

    # Use RFC 3526 precomputed DH parameters — instant startup, same 2048-bit security
    print(Fore.YELLOW + "  Loading RFC 3526 DH parameters (2048-bit) … ", end="", flush=True)
    dh_params = get_dh_parameters()
    print(Fore.GREEN + "done." + Style.RESET_ALL)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((args.host, args.port))
    server_sock.listen(10)

    log.info("Server listening on %s:%d", args.host, args.port)
    print(Fore.CYAN + f"\n  Listening on {args.host}:{args.port}  (Ctrl-C to stop)\n")

    try:
        while True:
            conn, addr = server_sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, dh_params), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print(Fore.RED + "\n  Server shutting down.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()
