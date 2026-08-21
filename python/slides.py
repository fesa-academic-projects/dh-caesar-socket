"""Reproduce the examples from the slides by calling into the C code."""

from _crypto import lib
from channel import G_EXAMPLE, G_SLIDE, N_EXAMPLE, N_SLIDE


def exchange(g, n, x, y):
    r1 = lib.dh_public_key(g, n, x)
    r2 = lib.dh_public_key(g, n, y)
    return r1, r2, lib.dh_shared_secret(r2, x, n), lib.dh_shared_secret(r1, y, n)


for g, n, x, y, expected in [
    (G_SLIDE, N_SLIDE, 500000, 60003322, (115, 69, 113, 113)),
    (G_EXAMPLE, N_EXAMPLE, 3, 6, (21, 4, 18, 18)),
]:
    r1, r2, k1, k2 = exchange(g, n, x, y)
    print(f"G={g:<3} N={n:<4} R1={r1:<4} R2={r2:<4} K1={k1:<4} K2={k2}")
    assert (r1, r2, k1, k2) == expected

print("matches the slides")
