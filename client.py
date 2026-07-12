"""
client.py
---------
Terminal chat client with AES-256-CBC encryption over a DH-negotiated key.

Startup sequence:
  1. Connect to server
  2. Receive DH parameters from server
  3. Generate ephemeral DH keypair
  4. Receive server's DH public key; send our own
  5. Derive shared AES-256 key via HKDF
  6. Send username (encrypted)
  7. Spin up a background thread to receive & print messages
  8. Read user input and send encrypted messages

Usage:
    python client.py [--host HOST] [--port PORT]
"""

import socket
import threading
import argparse
import sys
import os

import colorama
from colorama import Fore, Style

from crypto_utils import (
    deserialize_dh_parameters,
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
# Thread-safe print helper (avoids collisions with user input line)
# ---------------------------------------------------------------------------
print_lock = threading.Lock()


def safe_print(msg: str) -> None:
    with print_lock:
        # Move to a new line so incoming messages don't overwrite typed text
        sys.stdout.write("\r" + " " * 80 + "\r")
        print(msg)
        sys.stdout.write(Fore.GREEN + "You: " + Style.RESET_ALL)
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# Receive loop (runs in a background thread)
# ---------------------------------------------------------------------------

def receive_loop(sock: socket.socket, key: bytes, stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        try:
            token = recv_msg(sock)
            plaintext = decrypt_message(key, token)

            # Colour-code server notices vs peer messages
            if plaintext.startswith("[SERVER]"):
                safe_print(Fore.YELLOW + plaintext)
            else:
                safe_print(Fore.CYAN + plaintext)
        except (ConnectionError, OSError):
            if not stop_event.is_set():
                safe_print(Fore.RED + "\n[!] Connection to server lost.")
            stop_event.set()
            break
        except Exception as exc:
            safe_print(Fore.RED + f"[!] Receive error: {exc}")


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def client_banner() -> None:
    print(Fore.CYAN + "=" * 60)
    print(Fore.CYAN + "       🔒  Encrypted Chat Client  🔒")
    print(Fore.CYAN + "=" * 60)
    print(Fore.YELLOW + "  AES-256-CBC  |  Diffie-Hellman key exchange")
    print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypted Chat Client")
    parser.add_argument("--host", default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9999, help="Server port (default: 9999)")
    args = parser.parse_args()

    client_banner()

    # ---- Connect ----------------------------------------------------------
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        print(Fore.YELLOW + f"  Connecting to {args.host}:{args.port} … ", end="", flush=True)
        sock.connect((args.host, args.port))
        print(Fore.GREEN + "connected." + Style.RESET_ALL)
    except OSError as exc:
        print(Fore.RED + f"failed.\n[!] {exc}")
        sys.exit(1)

    # ---- DH Handshake -----------------------------------------------------
    print(Fore.YELLOW + "  Performing key exchange … ", end="", flush=True)

    # 1. Receive DH parameters
    params_pem = recv_msg(sock).encode("utf-8")
    dh_params = deserialize_dh_parameters(params_pem)

    # 2. Receive server public key
    server_pub_pem = recv_msg(sock).encode("utf-8")
    server_public_key = deserialize_public_key(server_pub_pem)

    # 3. Generate our keypair and send our public key
    our_private, our_public = generate_dh_keypair(dh_params)
    send_msg(sock, serialize_public_key(our_public).decode("utf-8"))

    # 4. Derive shared key
    shared_key = derive_shared_key(our_private, server_public_key)
    print(Fore.GREEN + "done." + Style.RESET_ALL)

    # ---- Username ---------------------------------------------------------
    print()
    username = input(Fore.WHITE + "  Enter your username: " + Style.RESET_ALL).strip()
    while not username:
        username = input(Fore.RED + "  Username cannot be empty: " + Style.RESET_ALL).strip()

    send_msg(sock, encrypt_message(shared_key, username))

    # ---- Chat UI ----------------------------------------------------------
    print(Fore.CYAN + "\n" + "=" * 60)
    print(Fore.CYAN + "  Type a message and press Enter to send.")
    print(Fore.CYAN + "  Type  /quit  to exit.")
    print(Fore.CYAN + "=" * 60 + Style.RESET_ALL + "\n")

    stop_event = threading.Event()
    recv_thread = threading.Thread(
        target=receive_loop, args=(sock, shared_key, stop_event), daemon=True
    )
    recv_thread.start()

    try:
        while not stop_event.is_set():
            sys.stdout.write(Fore.GREEN + "You: " + Style.RESET_ALL)
            sys.stdout.flush()
            try:
                message = input()
            except EOFError:
                break

            if not message.strip():
                continue

            if message.strip().lower() == "/quit":
                print(Fore.YELLOW + "  Disconnecting …")
                break

            try:
                token = encrypt_message(shared_key, message)
                send_msg(sock, token)
            except (ConnectionError, OSError):
                print(Fore.RED + "[!] Failed to send message. Connection lost.")
                break

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n  Interrupted.")
    finally:
        stop_event.set()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        sock.close()
        print(Fore.CYAN + "  Goodbye!")


if __name__ == "__main__":
    main()
