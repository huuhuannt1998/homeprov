"""Runs inside dz-harness (the household's client device on the internal network dz-net): copies bytes between its
stdin/stdout and one TCP connection to HOST:PORT. The host-side tunnel.py starts one relay per connection with
`docker exec -i`, so host tools reach the hub without the hub publishing a port; the hub sees the harness's address."""
import os
import socket
import sys
import threading

host, port = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((host, port))


def up():
    try:
        while True:
            b = os.read(0, 65536)
            if not b:
                break
            s.sendall(b)
    except OSError:
        pass
    try:
        s.shutdown(socket.SHUT_WR)
    except OSError:
        pass


threading.Thread(target=up, daemon=True).start()
try:
    while True:
        b = s.recv(65536)
        if not b:
            break
        os.write(1, b)
except OSError:
    pass
