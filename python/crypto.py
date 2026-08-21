"""Thin Python layer over the C module in src/crypto.c.

Only marshalling lives here. The Caesar cipher and the Diffie-Hellman
arithmetic are in C; cffi is the bridge, not a cryptography library.
"""

from _crypto import ffi, lib

# Public parameters used in class
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
