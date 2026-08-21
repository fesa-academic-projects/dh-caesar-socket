# dh-caesar-socket

Caesar cipher with a session key negotiated by Diffie-Hellman, carried over
a TCP socket. The cryptographic core is written in C and called from Python
through cffi. No cryptography library is used anywhere.

Built on the `Simple_tcpClient.py` and `Simple_tcpServer.py` files handed
out in class, which are kept untouched in `original/` so the modification
is visible as a diff.

```
Alice: picks x,  R1 = G^x mod N   ->  sends R1
Bob:   picks y,  R2 = G^y mod N   ->  sends R2
both:  K = G^(xy) mod N           ->  K becomes the Caesar shift
```

Alice is the client, Bob is the server, port 1300.

## Assignment steps

| step | what it asks | where it lives |
|---|---|---|
| 1 | run the class client and server on separate machines and watch the traffic | `original/`, captured in `captures/` |
| 2 | Caesar cipher, written by us, no libraries | `src/crypto.c`: `caesar_encrypt`, `caesar_decrypt` |
| 3 | Diffie-Hellman key exchange | `src/crypto.c`: `dh_public_key`, `dh_shared_secret` |
| extra | primality testing | `python/primes.py` |

The cipher and the key exchange are our own C code. cffi is the bridge that
lets Python call it, not a cryptography library. `python/primes.py` is pure
Python and imports nothing beyond `sys` and `time`.

## Layout

| path | role |
|---|---|
| `include/types.h` | integer type aliases |
| `include/crypto.h`, `src/crypto.c` | mulmod, powmod, Diffie-Hellman and Caesar |
| `build.py` | cffi compiles the C into `python/_crypto` |
| `python/Simple_tcpClient.py` | Alice, the class client with DH and Caesar added |
| `python/Simple_tcpServer.py` | Bob, the class server with DH and Caesar added |
| `python/crypto.py` | thin Python layer over the C module |
| `python/primes.py` | primality tests and safe-prime helpers |
| `python/eavesdrop.py` | recovers the session key from a capture |
| `python/slides.py` | reproduces the examples from the assignment |
| `python/test_all.py` | end-to-end test |
| `original/` | the class files, untouched |
| `captures/` | Wireshark evidence |

## Building and running

```sh
xbps-install -S python3-devel gcc     # Void
apk add python3-dev py3-cffi py3-setuptools gcc musl-dev make   # Alpine

make          # build the extension
make test     # primality, DH, cipher and a real socket round-trip
make slides   # check against the values in the assignment
make diff     # what changed from the class files
```

```sh
# Bob
python3 python/Simple_tcpServer.py

# Alice
HOST=<bob's address> python3 python/Simple_tcpClient.py
```

The class files hardcode the server address; the modified client reads it
from the environment instead, so a DHCP change does not mean editing the
file. The server handles one connection and exits, matching the original.

## Wire protocol

```
Alice (client)                        Bob (server)
   |----- R1 = G^x mod N (8 bytes BE) ---->|
   |<---- R2 = G^y mod N (8 bytes BE) -----|
   |----- ciphertext --------------------->|
   |<---- ciphertext ----------------------|
```

The eight bytes are read back with a loop rather than a single `recv`,
because TCP delivers a byte stream and one `recv` may return less than
asked for.

## Evidence

[Demonstration video](https://www.youtube.com/watch?v=rp8OIEAMTR4) (4 min)

`captures/etapa1-etapa2.pcapng` holds both runs, captured on the `virbr0`
bridge between two Alpine VMs under QEMU/KVM. Alice is 192.168.122.5, Bob
is 192.168.122.83.

Display filter: `tcp.port == 1300 && tcp.len > 0`

| frame | payload | what it is |
|---|---|---|
| 4 | `74 65 73 74 65` | step 1: `teste` in plain ASCII |
| 6 | `54 45 53 54 45` | step 1: `TESTE` coming back |
| 14 | `00 00 00 00 00 00 00 54` | R1 = 84, Alice to Bob |
| 16 | `00 00 00 00 00 00 00 40` | R2 = 64, Bob to Alice |
| 18 | `78 69 77 78 69` | same word, now encrypted |
| 19 | `58 49 57 58 49` | reply, encrypted |

The two runs are separate TCP connections: source port 56316 for step 1,
38362 for steps 2 and 3. With N = 127 the public values fit in one byte,
which is why the first seven bytes of frames 14 and 16 are zeros.

`captures/flow-graph.pdf` is the Wireshark flow graph of the same file. The
second session carries two extra data exchanges before the first message:
those are R1 and R2, and they have no counterpart in the first session.

### Reproducing the attack

Everything below comes from the capture alone. Nothing was read off the
two machines.

```sh
python3 python/eavesdrop.py 84 64 --hex "78 69 77 78 69"
```

```
recovered x = 40
K = 4, shift = 4
plaintext = 'teste'
```

The shift checks out by hand as well: `t` is `0x74`, and `0x74 + 4 = 0x78`,
the first byte of frame 18.

## Primality

```sh
python3 python/primes.py 1000003
```

```
slow  (trial division to n-1, no break)    True     0.053893s
fast  (trial division to n-1, break)       True     0.052039s             1x
sqrt  (trial division to sqrt n)           True     0.000036s         1,498x
miller-rabin (fixed bases)                 True     0.000027s         1,965x
```

The two loops from class are the same algorithm; the only difference is the
early `break`, which helps on composites and does nothing on primes. For a
prime both run all the way to n-1, so they tie. Stopping at sqrt(n) is what
actually changes the cost, because if n = a * b then one factor is at most
sqrt(n). On 2147483647 the class versions take about three minutes and the
sqrt version takes two milliseconds.

Note that N = 127 is prime but not a safe prime: (127-1)/2 = 63 is
composite, so G = 17 generates only 63 of the 126 possible values.

## Limitations

1. **N is tiny.** With N = 127 the discrete log falls to brute force
   instantly, which is exactly what `eavesdrop.py` demonstrates. Real use
   needs 2048 bits (RFC 3526) or X25519. `dh_default_n()` provides a 64-bit
   safe prime, still not production grade.
2. **Caesar has 256 keys.** Frequency analysis breaks it immediately.
3. **Plain DH does not authenticate.** A man in the middle runs one
   handshake with each side and reads everything. The fix is signing R1/R2.
4. **No integrity.** An HMAC or an AEAD cipher would be needed.
5. `powmod` is not constant-time.
6. The shift comes from summing the bytes of K, not from a KDF such as
   HKDF-SHA256.
7. `dh_private_key` has modulo bias in `raw % (n - 4)`: negligible for a
   small N, small for a 64-bit N, but present.

## License

BSD 3-Clause. See `LICENSE`; contributors are listed in `AUTHORS`.

`original/` holds the class handout files, which are the professor's work
and are kept only as the starting point the assignment asks us to modify.
