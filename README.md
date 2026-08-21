# dh-caesar-socket

Caesar cipher with a key negotiated by Diffie-Hellman. The core is written
in C, called from Python through cffi, and carried over a TCP socket.

```
Alice: picks x,  R1 = G^x mod N   ->  sends R1
Bob:   picks y,  R2 = G^y mod N   ->  sends R2
both:  K = G^(xy) mod N           ->  K becomes the cipher shift
```

## Assignment steps

| step | what it asks | where it lives |
|---|---|---|
| 1 | run the class client and server on separate machines, watch the traffic | `python/Simple_tcpClient.py`, `python/Simple_tcpServer.py` (capture the originals first, see below) |
| 2 | Caesar cipher, written by us, no libraries | `src/crypto.c` (`caesar_encrypt`, `caesar_decrypt`) |
| 3 | Diffie-Hellman key exchange | `src/crypto.c` (`dh_public_key`, `dh_shared_secret`) |
| extra | primality testing | `python/primes.py` |

Alice is the client and Bob the server. The cipher and the key exchange
are our own C code; cffi is only the bridge that lets Python call it, not
a cryptography library. `python/primes.py` is pure Python with no imports
beyond `sys` and `time`.

## Layout

| path | role |
|---|---|
| `include/types.h` | integer type aliases |
| `include/crypto.h`, `src/crypto.c` | mulmod, powmod, DH and Caesar |
| `build.py` | cffi compiles the C into `python/_crypto` |
| `python/crypto.py` | thin Python layer over the C module |
| `python/slides.py` | reproduces the examples from the assignment |
| `python/test_all.py` | end-to-end test |

## Running

```sh
xbps-install -S python3-devel gcc   # Void
pip install cffi

make          # build the extension
make slides   # check against the assignment
make test     # DH, cipher and socket

python3 python/Simple_tcpServer.py                     # Bob
HOST=<bob's address> python3 python/Simple_tcpClient.py  # Alice
```

Output of `make slides`:

```
G=17  N=127  R1=115  R2=69   K1=113  K2=113
G=7   N=23   R1=21   R2=4    K1=18   K2=18
```

## Wire protocol

```
client                           server
   |----- R1 = G^x mod N (8 bytes BE) ---->|
   |<---- R2 = G^y mod N (8 bytes BE) -----|
   |----- length (4 bytes BE) + ciphertext >|
   |<---- length (4 bytes BE) + ciphertext -|
```

The length prefix exists because TCP delivers a byte stream, not messages:
a single `recv` may return half a message or two of them at once.

## Capturing the exchange with Wireshark

Run the server on one VM and the client on another, both on the same
libvirt network, then capture on the host bridge:

```sh
ip -4 addr show virbr0                       # host side of the virtual network
sudo wireshark -k -i virbr0 -f "tcp port 1300"
```

Display filter inside Wireshark:

```
tcp.port == 1300 && tcp.len > 0
```

What to look for:

| packet | bytes | meaning |
|---|---|---|
| 1st with payload | 8 | R1 = G^x mod N, big-endian |
| 2nd with payload | 8 | R2 = G^y mod N, big-endian |
| following | 4 + len | length prefix, then the ciphertext |

With N = 127 the public values fit in one byte, so the first seven bytes
are zeros and the value is the eighth. Follow TCP Stream shows the whole
session; the ciphertext is unreadable, but the shift is a constant offset
away from the plaintext.

Then break it, using only what the capture shows:

```sh
python3 python/eavesdrop.py <R1> <R2>
```

It brute-forces x from R1, derives K and prints the shift. That is the
point of the exercise: R1 and R2 travel in the clear by design, and the
secrecy of K rests entirely on N being large enough.

## Limitations

1. **N is tiny.** With N = 127 the discrete log falls to brute force
   instantly. Real use needs 2048 bits (RFC 3526) or X25519.
   `dh_default_n()` provides a 64-bit safe prime, still not production grade.
2. **Caesar has 256 keys.** Frequency analysis breaks it immediately.
3. **Plain DH does not authenticate.** A man in the middle runs one
   handshake with each side and reads everything. The fix is signing R1/R2.
4. **No integrity.** An HMAC or an AEAD cipher would be needed.
5. `powmod` is not constant-time.
6. The shift comes from summing the bytes of K, not from a KDF such as
   HKDF-SHA256.
7. `dh_private_key` has modulo bias in `raw % (n - 4)`: negligible for a
   small N, small for a 64-bit N, but present.


## What changed from the class files

The handout files are kept untouched in `original/`. The versions with
Caesar and Diffie-Hellman are in `python/`, under the same names. To see
exactly what was added:

```sh
make diff
```

`original/` is what step 1 is captured with: it sends the sentence in
clear text, so Follow TCP Stream shows it. `python/` is what steps 2 and
3 are captured with.

One difference is not about cryptography: the class client hardcodes the
server address, while the modified one reads it from the environment, so
the DHCP address of the other VM does not have to be edited into the file
every time.

```sh
HOST=192.168.122.83 python3 python/Simple_tcpClient.py
```

## The assignment run

Build once on each machine, then:

```sh
# Bob
python3 python/Simple_tcpServer.py

# Alice
HOST=<bob's address> python3 python/Simple_tcpClient.py
```

Capture on the bridge between them:

```sh
wireshark -k -i virbr0 -f "tcp port 1300"
```

Take two captures. The first with the unmodified class files, where the
sentence is readable in Follow TCP Stream. The second after steps 2 and 3,
where the same sentence is a run of bytes. The contrast between them is
the evidence.

The first two packets carrying data are R1 and R2, eight bytes each. With
N = 127 the value sits in the last byte. Feed them to the eavesdropper
along with any ciphertext from the capture:

```sh
python3 python/eavesdrop.py 2 113 --hex "78 75 7c 7c 7f 30 87 7f 82 7c 74"
```

```
recovered x = 45
K = 16, shift = 16
plaintext = 'hello world'
```

Nothing there came from the two machines: R1, R2 and the ciphertext were
all read off the wire. That is the point of choosing N large.

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

The two loops from class are the same algorithm; the difference is the
early `break`, which only helps on composites. For a prime both run to
n-1, so they tie. Stopping at sqrt(n) is what actually changes the cost,
because if n = a * b then one factor is at most sqrt(n).

Note that N = 127 is prime but not a safe prime: 63 = (127-1)/2 is
composite, so G = 17 generates only 63 of the 126 possible values.

## License

BSD 3-Clause. See `LICENSE`; contributors are listed in `AUTHORS`.

`original/` holds the class handout files, which are the professor's work
and are kept only as the starting point the assignment asks us to modify.
