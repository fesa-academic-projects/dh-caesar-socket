"""Recover the session key from a capture, to show why a small N fails.

Feed it the two public values read off Wireshark:

    python3 python/eavesdrop.py 2 113                 # G=17, N=127 by default
    python3 python/eavesdrop.py 21 4 --g 7 --n 23
"""

import argparse

from _crypto import lib
from channel import decrypt

G_SLIDE, N_SLIDE = 17, 127


def discrete_log(g, n, target):
    """Brute force: try every exponent until G^x mod N matches."""
    for x in range(1, n):
        if lib.dh_public_key(g, n, x) == target:
            return x
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("r1", type=int, help="Alice's public value, from the capture")
    ap.add_argument("r2", type=int, help="Bob's public value, from the capture")
    ap.add_argument("--g", type=int, default=G_SLIDE)
    ap.add_argument("--n", type=int, default=N_SLIDE)
    ap.add_argument("--hex", help="ciphertext hex from the capture, to decrypt")
    args = ap.parse_args()

    x = discrete_log(args.g, args.n, args.r1)
    if x is None:
        print("no exponent found: check G and N")
        return 1

    k = lib.dh_shared_secret(args.r2, x, args.n)
    shift = lib.caesar_key_from_secret(k)
    print(f"recovered x = {x}")
    print(f"K = {k}, shift = {shift}")

    if args.hex:
        data = bytes.fromhex(args.hex.replace(":", "").replace(" ", ""))
        print(f"plaintext = {decrypt(data, shift).decode('utf-8', 'replace')!r}")
    else:
        print("the eavesdropper can now decrypt every message in the capture")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
