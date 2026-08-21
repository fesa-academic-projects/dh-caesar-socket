"""Compile src/crypto.c into the Python module python/_crypto."""

import os

from cffi import FFI

ROOT = os.path.dirname(os.path.abspath(__file__))

ffi = FFI()

# cffi does not run the preprocessor: declarations only, no #include, no u64.
ffi.cdef("""
    uint64_t dh_public_key(uint64_t g, uint64_t n, uint64_t priv);
    uint64_t dh_shared_secret(uint64_t their_pub, uint64_t priv, uint64_t n);
    uint64_t dh_private_key(uint64_t n);

    uint64_t dh_default_n(void);
    uint64_t dh_default_g(void);
    uint64_t dh_default_q(void);
    int      dh_valid_public(uint64_t pub, uint64_t n, uint64_t q);

    uint8_t  caesar_key_from_secret(uint64_t secret);
    void caesar_encrypt(const uint8_t *in, uint8_t *out, size_t n, uint8_t shift);
    void caesar_decrypt(const uint8_t *in, uint8_t *out, size_t n, uint8_t shift);
""")

# Absolute paths: tmpdir changes the working directory of the compilation.
ffi.set_source(
    "_crypto",
    '#include "crypto.h"',
    sources=[os.path.join(ROOT, "src", "crypto.c")],
    include_dirs=[os.path.join(ROOT, "include")],
    extra_compile_args=["-O2", "-std=c11", "-Wall", "-Wextra"],
)

if __name__ == "__main__":
    ffi.compile(tmpdir=os.path.join(ROOT, "python"), verbose=True)
