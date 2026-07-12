"""
protocol.py
-----------
Simple length-prefixed framing over TCP so we can send arbitrary-length
messages without worrying about stream boundaries.

Wire format for every frame:
    [4 bytes big-endian length][payload bytes]

All payloads are UTF-8 strings (JSON during the handshake, encrypted
message tokens afterwards).
"""

import struct
import socket


HEADER_SIZE = 4  # bytes


def send_msg(sock: socket.socket, data: str) -> None:
    """Frame and send a string over a connected socket."""
    encoded = data.encode("utf-8")
    header = struct.pack(">I", len(encoded))   # 4-byte big-endian length
    sock.sendall(header + encoded)


def recv_msg(sock: socket.socket) -> str:
    """
    Read exactly one framed message from the socket.
    Blocks until a complete message arrives.
    Returns the decoded string, or raises ConnectionError on disconnect.
    """
    raw_header = _recv_exact(sock, HEADER_SIZE)
    if not raw_header:
        raise ConnectionError("Connection closed by remote host.")
    length = struct.unpack(">I", raw_header)[0]
    raw_body = _recv_exact(sock, length)
    if not raw_body:
        raise ConnectionError("Connection closed while reading message body.")
    return raw_body.decode("utf-8")


def _recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """Read exactly num_bytes from the socket, handling partial reads."""
    buf = b""
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf
