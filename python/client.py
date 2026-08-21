"""Client: connects, negotiates the key and sends encrypted lines."""

import socket
import sys

from channel import G_SLIDE, N_SLIDE, Channel

HOST, PORT = "127.0.0.1", 5000


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        channel = Channel(sock, g=G_SLIDE, n=N_SLIDE)
        channel.handshake()
        print(channel.summary())
        print("type a message (or 'quit'):")

        for line in sys.stdin:
            text = line.rstrip("\n")
            if not text:
                continue
            channel.send(text)
            print(f"[client] reply: {channel.receive()!r}")
            if text == "quit":
                break


if __name__ == "__main__":
    sys.exit(main())
