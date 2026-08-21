#ifndef CRYPTO_H
#define CRYPTO_H

#include "types.h"
#include <stddef.h>
#include <stdint.h>

/* Diffie-Hellman: R = G^x mod N, K = R^x mod N. G and N are public. */
u64 dh_public_key(u64 g, u64 n, u64 priv);
u64 dh_shared_secret(u64 their_pub, u64 priv, u64 n);

/* Random exponent from /dev/urandom. Returns 0 on failure. */
u64 dh_private_key(u64 n);

/* 64-bit safe prime N, and G of order (N-1)/2. */
u64 dh_default_n(void);
u64 dh_default_g(void);

/* Rejects 0, 1 and n-1. With q > 0 also checks the subgroup; q = 0 skips it. */
int dh_valid_public(u64 pub, u64 n, u64 q);

/* One-byte shift derived from K. A real system would use a KDF. */
u8 caesar_key_from_secret(u64 secret);

/* Caesar over bytes (mod 256): UTF-8 and binary safe. in == out is fine. */
void caesar_encrypt(const u8 *in, u8 *out, size_t n, u8 shift);
void caesar_decrypt(const u8 *in, u8 *out, size_t n, u8 shift);

#endif // CRYPTO_H
