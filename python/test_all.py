"""End-to-end test: primality, Diffie-Hellman, Caesar and the socket pair."""

import os
import subprocess
import sys
import time

from _crypto import lib
from crypto import G_SLIDE, N_SLIDE, decrypt, encrypt
from primes import is_prime_fast, is_prime_miller_rabin, is_prime_sqrt

HERE = os.path.dirname(os.path.abspath(__file__))


def check_dh(g, n):
    """Both sides reach the same K through different routes."""
    a, b = lib.dh_private_key(n), lib.dh_private_key(n)
    pa, pb = lib.dh_public_key(g, n, a), lib.dh_public_key(g, n, b)
    k1 = lib.dh_shared_secret(pb, a, n)
    k2 = lib.dh_shared_secret(pa, b, n)
    assert k1 == k2, (k1, k2)
    return k1


# The three primality tests must agree on the same numbers.
for n in (2, 3, 4, 97, 561, 1000003, 1000000):
    expected = is_prime_fast(n)
    assert is_prime_sqrt(n) == expected, n
    assert is_prime_miller_rabin(n) == expected, n
print("primality: three implementations agree")

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

# The real pair, over a real socket.
env = dict(os.environ, HOST="127.0.0.1")
server = subprocess.Popen(
    [sys.executable, os.path.join(HERE, "Simple_tcpServer.py")],
    stdout=subprocess.PIPE, text=True, env=env,
)
time.sleep(1)
client = subprocess.run(
    [sys.executable, os.path.join(HERE, "Simple_tcpClient.py")],
    input="hello from the test\n", capture_output=True, text=True, env=env,
)
server_out = server.communicate(timeout=10)[0]

assert "HELLO FROM THE TEST" in client.stdout, client.stdout + client.stderr
assert "hello from the test" in server_out, server_out
print("socket: client and server agreed on the key and the message")
