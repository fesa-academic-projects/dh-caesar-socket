#include "../include/crypto.h"
#include <stdio.h>

#define DH_DEFAULT_N 0xFFFFFFFFFFFFFA43ULL /* 18446744073709550147 */
#define DH_DEFAULT_Q 0x7FFFFFFFFFFFFD21ULL /* (N-1)/2 */
#define DH_DEFAULT_G 4ULL

/* 128-bit product: a * b overflows 64 bits before the remainder. */
static u64 mulmod(u64 a, u64 b, u64 m) { return (u64)((u128)a * (u128)b % m); }

/* Repeated squaring: O(log exp) instead of exp multiplications. */
static u64 powmod(u64 base, u64 exp, u64 m) {
  u64 result = 1;

  if (m <= 1)
    return 0;
  base %= m;
  while (exp > 0) {
    if (exp & 1ULL)
      result = mulmod(result, base, m);
    base = mulmod(base, base, m);
    exp >>= 1;
  }
  return result;
}

u64 dh_public_key(u64 g, u64 n, u64 priv) { return powmod(g, priv, n); }

u64 dh_shared_secret(u64 their_pub, u64 priv, u64 n) {
  return powmod(their_pub, priv, n);
}

u64 dh_private_key(u64 n) {
  FILE *f;
  u64 raw = 0;

  if (n < 5ULL)
    return 0;
  f = fopen("/dev/urandom", "rb");
  if (!f)
    return 0;
  if (fread(&raw, sizeof raw, 1, f) != 1) {
    fclose(f);
    return 0;
  }
  fclose(f);

  return 2ULL + (raw % (n - 4ULL)); /* [2, n-3] */
}

u64 dh_default_n(void) { return DH_DEFAULT_N; }
u64 dh_default_g(void) { return DH_DEFAULT_G; }
u64 dh_default_q(void) { return DH_DEFAULT_Q; }

/* Without this, an R2 of 1 forces K = 1 for any private key. */
int dh_valid_public(u64 pub, u64 n, u64 q) {
  if (pub < 2ULL || pub > n - 2ULL) {
    return 0;
  }
  if (q > 0ULL && powmod(pub, q, n) != 1ULL) {
    return 0;
  }
  return 1;
}

u8 caesar_key_from_secret(u64 secret) {
  u8 k = 0;
  int i;

  for (i = 0; i < 8; i++)
    k = (u8)(k + (u8)(secret >> (8 * i)));
  return k;
}

void caesar_encrypt(const u8 *in, u8 *out, size_t n, u8 shift) {
  size_t i;

  for (i = 0; i < n; i++)
    out[i] = (u8)(in[i] + shift); /* mod 256 is implicit in u8 */
}

/* Inverse in the cipher's own modulus: 256 - shift, truncated back to u8. */
void caesar_decrypt(const u8 *in, u8 *out, size_t n, u8 shift) {
  caesar_encrypt(in, out, n, (u8)(256 - shift));
}
