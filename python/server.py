"""Server: accepts one connection, negotiates the key and echoes in upper case."""

import socket
import sys

from channel import G_SLIDE, N_SLIDE, Channel

HOST, PORT = "127.0.0.1", 5000


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        # Avoids "address already in use" right after a restart.
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)
        print(f"[server] listening on {HOST}:{PORT}")

        conn, addr = srv.accept()
        with conn:
            print(f"[server] connection from {addr}")
            channel = Channel(conn, g=G_SLIDE, n=N_SLIDE)
            channel.handshake()
            print(channel.summary())

            while True:
                try:
                    msg = channel.receive()
                except ConnectionError:
                    break
                print(f"[server] received: {msg!r}")
                if msg == "quit":
                    channel.send("bye")
                    break
                channel.send(msg.upper())

    print("[server] closed")


if __name__ == "__main__":
    sys.exit(main())
