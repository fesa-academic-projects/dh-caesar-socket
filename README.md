# dh-caesar-socket

Caesar cipher with a key negotiated by Diffie-Hellman. The core is written
in C, called from Python through cffi, and carried over a TCP socket.

```
Alice: picks x,  R1 = G^x mod N   ->  sends R1
Bob:   picks y,  R2 = G^y mod N   ->  sends R2
both:  K = G^(xy) mod N           ->  K becomes the cipher shift
```

## Layout

| path | role |
|---|---|
| `include/types.h` | integer type aliases |
| `include/crypto.h`, `src/crypto.c` | mulmod, powmod, DH and Caesar |
| `build.py` | cffi compiles the C into `python/_crypto` |
| `python/channel.py` | handshake, framing and cipher |
| `python/server.py`, `python/client.py` | the two ends of the socket |
| `python/slides.py` | reproduces the examples from the assignment |
| `python/test_all.py` | end-to-end test |

## Running

```sh
xbps-install -S python3-devel gcc   # Void
pip install cffi

make          # build the extension
make slides   # check against the assignment
make test     # DH, cipher and socket

python3 python/server.py   # terminal 1
python3 python/client.py   # terminal 2
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
