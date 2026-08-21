# Simple_tcpServer.py  --  Bob (server)
#
# Based on the class file. What was added:
#   - Diffie-Hellman handshake before the message exchange (step 3)
#   - Caesar cipher on everything that crosses the socket (step 2)
#   - primality check on N, so the parameters are not taken on faith
#
# The cipher and the key exchange are our own C code in src/crypto.c,
# reached through cffi. No cryptography library is used anywhere.

from socket import *

from _crypto import lib
from crypto import decrypt, encrypt
from primes import is_prime_miller_rabin, is_safe_prime

SERVER_PORT = 1300

# Public parameters, the same ones used in class.
G = 17
N = 127


def recv_exactly(sock, size):
    """TCP is a stream: one recv may return fewer bytes than asked for."""
    buffer = b""
    while len(buffer) < size:
        chunk = sock.recv(size - len(buffer))
        if not chunk:
            raise ConnectionError("client closed the connection")
        buffer += chunk
    return buffer


print("TCP Server (Bob)\n")

# Step 3, part one: check the parameters before trusting them.
print(f"G = {G}, N = {N}")
print(f"N is prime: {is_prime_miller_rabin(N)}")
print(f"N is a safe prime: {is_safe_prime(N)}\n")

serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
serverSocket.bind(("", SERVER_PORT))
serverSocket.listen(5)

connectionSocket, addr = serverSocket.accept()
print("Connection from:", addr)

# Diffie-Hellman: y is secret, R2 = G^y mod N goes on the wire.
y = lib.dh_private_key(N)
R2 = lib.dh_public_key(G, N, y)
connectionSocket.send(R2.to_bytes(8, "big"))

R1 = int.from_bytes(recv_exactly(connectionSocket, 8), "big")
K = lib.dh_shared_secret(R1, y, N)
shift = lib.caesar_key_from_secret(K)

print(f"private y = {y}")
print(f"public  R2 = {R2}")
print(f"received R1 = {R1}")
print(f"shared key K = {K}  ->  Caesar shift = {shift}\n")

# From here on every byte on the socket is ciphertext.
sentence = connectionSocket.recv(65000)
print("Received from Client (encrypted):", sentence.hex(" "))

received = str(decrypt(sentence, shift), "utf-8")
print("Received from Client (decrypted):", received)

capitalizedSentence = encrypt(received.upper().encode("utf-8"), shift)
connectionSocket.send(capitalizedSentence)

print("Sent back to Client (encrypted):", capitalizedSentence.hex(" "))
print("Sent back to Client (plain):", received.upper())
connectionSocket.close()
