"""End-to-end test: DH, cipher and socket."""

import socket
import threading
import time

from _crypto import lib
from channel import G_SLIDE, N_SLIDE, Channel, decrypt, encrypt


def check_dh(g, n):
    """Both sides reach the same K through different routes."""
    a, b = lib.dh_private_key(n), lib.dh_private_key(n)
    pa, pb = lib.dh_public_key(g, n, a), lib.dh_public_key(g, n, b)
    k1 = lib.dh_shared_secret(pb, a, n)
    k2 = lib.dh_shared_secret(pa, b, n)
    assert k1 == k2, (k1, k2)
    return k1


print("DH from the slides:", check_dh(G_SLIDE, N_SLIDE))
print("DH 64-bit:", check_dh(lib.dh_default_g(), lib.dh_default_n()))

# Degenerate public keys are rejected.
default_n, default_q = lib.dh_default_n(), lib.dh_default_q()
for bad in (0, 1, default_n - 1):
    assert lib.dh_valid_public(bad, default_n, default_q) == 0, bad
print("public key validation: ok")

# Cipher round-trip across all 256 shifts, with accented input.
msg = "Ola, acao 123".encode("utf-8")
for shift in range(256):
    assert decrypt(encrypt(msg, shift), shift) == msg, shift
print("caesar: ok across 256 shifts")


def server():
    with socket.socket() as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 5099))
        srv.listen(1)
        conn, _ = srv.accept()
        with conn:
            channel = Channel(conn, g=G_SLIDE, n=N_SLIDE)
            channel.handshake()
            channel.send(channel.receive().upper())


threading.Thread(target=server, daemon=True).start()
time.sleep(0.3)

with socket.socket() as sock:
    sock.connect(("127.0.0.1", 5099))
    channel = Channel(sock, g=G_SLIDE, n=N_SLIDE)
    channel.handshake()
    channel.send("secret message")
    print(f"socket: {channel.receive()!r} (K={channel.secret}, shift={channel.shift})")
