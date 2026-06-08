#!/usr/bin/env python3
"""Local smoke test for tls_proxy.py: drive the tunnel like the Amiga would.

Connects to a running daemon, sends the CONNECT handshake for example.com:443,
then a plaintext HTTP/1.1 GET, and checks a real HTTPS response comes back.
"""
import socket
import sys

HOST, PORT = "127.0.0.1", 8443
TARGET = "example.com"

def main():
    s = socket.create_connection((HOST, PORT), timeout=30)
    s.sendall(f"CONNECT {TARGET} 443\n".encode())

    # read the status line
    status = b""
    while not status.endswith(b"\n"):
        b = s.recv(1)
        if not b:
            print("FAIL: daemon closed before status"); return 1
        status += b
    print("status:", status.strip().decode())
    if not status.startswith(b"OK"):
        return 1

    # now the tunnel is transparent plaintext -> TLS
    req = (f"GET / HTTP/1.1\r\nHost: {TARGET}\r\n"
           "Connection: close\r\nUser-Agent: amissl-emu-smoke\r\n\r\n")
    s.sendall(req.encode())

    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > 4096:
            break
    s.close()
    head = data.split(b"\r\n", 1)[0].decode("latin1")
    print("server said:", head)
    return 0 if head.startswith("HTTP/") else 1

if __name__ == "__main__":
    sys.exit(main())
