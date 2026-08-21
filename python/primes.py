"""Primality tests, from the naive loop to Miller-Rabin.

Pure Python, standard library only. Run it to compare the algorithms:

    python3 primes.py 2147483647
    python3 primes.py 2147483647 --skip-slow
"""

import sys
import time


def is_prime_slow(n):
    """Trial division up to n-1, counting every divisor found.

    Never stops early, so a number like 1000000 costs the same as a prime
    of the same size. This is the reference implementation from class.
    """
    if n < 2:
        return False
    count = 0
    i = 2
    while i < n:
        if n % i == 0:
            count += 1
        i += 1
    return count == 0


def is_prime_fast(n):
    """Same loop, but returns as soon as one divisor appears.

    Only helps for composites: for a prime the loop still runs to n-1,
    so the worst case is unchanged.
    """
    if n < 2:
        return False
    i = 2
    while i < n:
        if n % i == 0:
            return False
        i += 1
    return True


def is_prime_sqrt(n):
    """Trial division up to sqrt(n), skipping even numbers.

    If n = a * b then one of the factors is <= sqrt(n), so testing past
    that point can never find anything new. This is what actually makes
    the naive test fast: O(sqrt(n)) instead of O(n).
    """
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def _try_composite(a, d, n, s):
    """One Miller-Rabin round: True means a proves n composite."""
    x = pow(a, d, n)
    if x == 1 or x == n - 1:
        return False
    for _ in range(s - 1):
        x = x * x % n
        if x == n - 1:
            return False
    return True


def is_prime_miller_rabin(n):
    """Miller-Rabin with fixed bases: exact for every n below 3.3e24.

    Writes n-1 as d * 2^s and checks whether each base behaves the way a
    square root of 1 must behave modulo a prime. Cost is O(log n) per
    base, so a 64-bit number takes microseconds.
    """
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in small:
        if n % p == 0:
            return n == p

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    return not any(_try_composite(a, d, n, s) for a in small)


def is_safe_prime(n):
    """True when n and (n-1)/2 are both prime.

    Diffie-Hellman wants this: it forces the order of every element to be
    1, 2, q or 2q, leaving no small subgroup for an attacker to use.
    """
    if not is_prime_miller_rabin(n):
        return False
    return is_prime_miller_rabin((n - 1) // 2)


def next_safe_prime(start):
    """First safe prime at or above start. Used to pick N for the exchange."""
    n = start if start % 2 else start + 1
    while not is_safe_prime(n):
        n += 2
    return n


def _timed(fn, n):
    begin = time.perf_counter()
    result = fn(n)
    return result, time.perf_counter() - begin


def main(argv):
    if len(argv) > 1:
        n = int(argv[1])
    else:
        n = int(input("N: "))
    skip_slow = "--skip-slow" in argv

    tests = [
        ("slow  (trial division to n-1, no break)", is_prime_slow),
        ("fast  (trial division to n-1, break)", is_prime_fast),
        ("sqrt  (trial division to sqrt n)", is_prime_sqrt),
        ("miller-rabin (fixed bases)", is_prime_miller_rabin),
    ]
    if skip_slow:
        tests = tests[2:]

    print(f"N = {n}\n")
    baseline = None
    for label, fn in tests:
        prime, elapsed = _timed(fn, n)
        speedup = "" if baseline is None else f"  {baseline / max(elapsed, 1e-9):>12,.0f}x"
        baseline = elapsed if baseline is None else baseline
        print(f"{label:<42} {str(prime):<6} {elapsed:>10.6f}s{speedup}")

    print(f"\nsafe prime (N and (N-1)/2 both prime): {is_safe_prime(n)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
