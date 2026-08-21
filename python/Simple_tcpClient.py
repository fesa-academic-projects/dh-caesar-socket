# Simple_tcpClient.py  --  Alice (client)
#
# Based on the class file. What was added:
#   - Diffie-Hellman handshake before the message exchange (step 3)
#   - Caesar cipher on everything that crosses the socket (step 2)
#   - primality check on N, so the parameters are not taken on faith
#
# The cipher and the key exchange are our own C code in src/crypto.c,
# reached through cffi. No cryptography library is used anywhere.

import os
from socket import *

from _crypto import lib
from channel import decrypt, encrypt
from primes import is_prime_miller_rabin, is_safe_prime

# Address of Bob. Override without editing the file:
#   HOST=192.168.122.5 python3 python/Simple_tcpClient.py
serverName = os.environ.get("HOST", "192.168.122.5")
serverPort = 1300

# Public parameters, the same ones used in class.
G = 17
N = 127


def recv_exactly(sock, size):
    """TCP is a stream: one recv may return fewer bytes than asked for."""
    buffer = b""
    while len(buffer) < size:
        chunk = sock.recv(size - len(buffer))
        if not chunk:
            raise ConnectionError("server closed the connection")
        buffer += chunk
    return buffer


print("TCP Client (Alice)\n")

# Step 3, part one: check the parameters before trusting them.
print(f"G = {G}, N = {N}")
print(f"N is prime: {is_prime_miller_rabin(N)}")
print(f"N is a safe prime: {is_safe_prime(N)}\n")

clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverName, serverPort))

# Diffie-Hellman: x is secret, R1 = G^x mod N goes on the wire.
x = lib.dh_private_key(N)
R1 = lib.dh_public_key(G, N, x)
clientSocket.send(R1.to_bytes(8, "big"))

R2 = int.from_bytes(recv_exactly(clientSocket, 8), "big")
K = lib.dh_shared_secret(R2, x, N)
shift = lib.caesar_key_from_secret(K)

print(f"private x = {x}")
print(f"public  R1 = {R1}")
print(f"received R2 = {R2}")
print(f"shared key K = {K}  ->  Caesar shift = {shift}\n")

# From here on every byte on the socket is ciphertext.
sentence = input("Input lowercase sentence: ")
payload = encrypt(bytes(sentence, "utf-8"), shift)
clientSocket.send(payload)
print("Sent to Server (encrypted):", payload.hex(" "))

modifiedSentence = clientSocket.recv(1024)
print("Received from Server (encrypted):", modifiedSentence.hex(" "))

text = str(decrypt(modifiedSentence, shift), "utf-8")
print("Received from Make Upper Case Server:", text)
clientSocket.close()
