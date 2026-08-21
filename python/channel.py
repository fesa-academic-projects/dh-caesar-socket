"""Diffie-Hellman handshake, Caesar cipher and framing over TCP."""

import socket
import struct

from _crypto import ffi, lib

# Parameters from the slides, useful to check the expected output
G_SLIDE, N_SLIDE = 17, 127
G_EXAMPLE, N_EXAMPLE = 7, 23


def encrypt(data: bytes, shift: int) -> bytes:
    n = len(data)
    if n == 0:
        return b""
    out = ffi.new("uint8_t[]", n)
    lib.caesar_encrypt(data, out, n, shift)
    return bytes(ffi.buffer(out, n))


def decrypt(data: bytes, shift: int) -> bytes:
    n = len(data)
    if n == 0:
        return b""
    out = ffi.new("uint8_t[]", n)
    lib.caesar_decrypt(data, out, n, shift)
    return bytes(ffi.buffer(out, n))


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """TCP delivers a stream, not messages: recv may return fewer than n."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed the connection")
        buf += chunk
    return buf


class Channel:
    """TCP socket with a DH-negotiated key and encrypted messages."""

    MAX_MSG = 1 << 20  # cap on the allocation the peer can ask for

    def __init__(self, sock, g=None, n=None, q=0):
        self.sock = sock
        self.n = lib.dh_default_n() if n is None else n
        self.g = lib.dh_default_g() if g is None else g
        # The subgroup check only makes sense with the default N.
        if g is None and n is None and q == 0:
            q = lib.dh_default_q()
        self.q = q

        self.priv = lib.dh_private_key(self.n)  # x
        if self.priv == 0:
            raise RuntimeError("failed to generate a private key")
        self.pub = lib.dh_public_key(self.g, self.n, self.priv)  # R1 = G^x mod N
        self.secret = None
        self.shift = None

    def handshake(self) -> None:
        """Exchange R1/R2. Both sides run exactly the same code."""
        self.sock.sendall(struct.pack("!Q", self.pub))
        their_pub = struct.unpack("!Q", _recv_exactly(self.sock, 8))[0]

        if not lib.dh_valid_public(their_pub, self.n, self.q):
            raise ValueError(f"invalid public key: {their_pub}")

        self.secret = lib.dh_shared_secret(their_pub, self.priv, self.n)
        self.shift = lib.caesar_key_from_secret(self.secret)

    def send(self, text: str) -> None:
        payload = encrypt(text.encode("utf-8"), self.shift)
        self.sock.sendall(struct.pack("!I", len(payload)) + payload)

    def receive(self) -> str:
        (size,) = struct.unpack("!I", _recv_exactly(self.sock, 4))
        if size > self.MAX_MSG:
            raise ValueError(f"message too large: {size}")
        return decrypt(_recv_exactly(self.sock, size), self.shift).decode("utf-8")

    def summary(self) -> str:
        return (
            f"G = {self.g}\nN = {self.n}\n"
            f"private = {self.priv}\npublic = {self.pub}\n"
            f"K = {self.secret}\nshift = {self.shift}"
        )
