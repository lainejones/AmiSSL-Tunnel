#!/usr/bin/env python3
"""
Model B reference 'shim simulator' — does EXACTLY what the Amiga amissl shim will do,
in Python, so the protocol + memory-BIO dance can be validated before any 68k exists.

Like iBrowse over a native stack, it:
  1. opens its OWN socket to the target server:443 (the real TLS record transport),
  2. opens a control socket to the tls_oracle daemon,
  3. drives the handshake as a pump: oracle gives ciphertext -> we send to server;
     server gives ciphertext -> we feed oracle; loop until DONE,
  4. WRITE plaintext request -> oracle returns ciphertext -> we send to server,
  5. READ: feed server ciphertext to oracle -> get plaintext, until EOF.

Every byte of crypto happens in the oracle; this process only moves bytes.

Usage:  python3 oracle_sim.py [oracle_host] [oracle_port] [target_host]
        defaults: 127.0.0.1 8443 example.com
"""
import socket
import struct
import sys

OP_NEW, OP_HANDSHAKE, OP_WRITE, OP_READ, OP_SHUTDOWN, OP_FREE = 1, 2, 3, 4, 5, 6
ST_OK, ST_WANT_READ, ST_EOF, ST_ERROR = 0, 1, 2, 3


def recvn(sock, n):
    buf = bytearray()
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            return None
        buf.extend(c)
    return bytes(buf)


def rpc(ctrl, op, ssl_id, data=b"", aux=0):
    ctrl.sendall(struct.pack(">BIII", op, ssl_id, aux, len(data)) + data)
    hdr = recvn(ctrl, 9)
    if hdr is None:
        raise ConnectionError("oracle closed")
    status, pending, outlen = struct.unpack(">BII", hdr)
    out = recvn(ctrl, outlen) if outlen else b""
    return status, pending, out


def main():
    oracle_host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    oracle_port = int(sys.argv[2] if len(sys.argv) > 2 else "8443")
    target = sys.argv[3] if len(sys.argv) > 3 else "example.com"
    maxlen = int(sys.argv[4]) if len(sys.argv) > 4 else 16384

    server = socket.create_connection((target, 443), timeout=30)   # iBrowse's own socket
    ctrl = socket.create_connection((oracle_host, oracle_port), timeout=30)

    status, _pend, out = rpc(ctrl, OP_NEW, 0, target.encode())
    if status != ST_OK:
        print("FAIL: NEW"); return 1
    ssl_id = struct.unpack(">I", out)[0]
    print(f"ssl_id={ssl_id}")

    # --- handshake pump ---
    cipher_in = b""
    while True:
        status, _pend, out = rpc(ctrl, OP_HANDSHAKE, ssl_id, cipher_in)
        cipher_in = b""
        if out:
            server.sendall(out)               # our flight -> server
        if status == ST_OK:
            print("handshake DONE")
            break
        if status == ST_WANT_READ:
            cipher_in = server.recv(16384)     # server's flight -> oracle next loop
            if not cipher_in:
                print("FAIL: server closed mid-handshake"); return 1
        else:
            print("FAIL: handshake error"); return 1

    # --- send the HTTP request (plaintext -> oracle -> ciphertext -> server) ---
    req = (f"GET / HTTP/1.1\r\nHost: {target}\r\n"
           "Connection: close\r\nUser-Agent: amissl-emu-modelB\r\n\r\n").encode()
    status, _pend, out = rpc(ctrl, OP_WRITE, ssl_id, req)
    if status != ST_OK:
        print("FAIL: WRITE"); return 1
    server.sendall(out)

    # --- read pump (maxlen-driven; daemon holds leftover, reports `pending`) ---
    resp = b""
    feed = b""
    MAXLEN = maxlen
    while True:
        status, pend, out = rpc(ctrl, OP_READ, ssl_id, feed, aux=MAXLEN)
        feed = b""
        if status == ST_OK:
            resp += out
            if pend > 0:
                continue                       # leftover buffered on daemon; drain it
            c = server.recv(16384)             # need fresh ciphertext (or EOF)
            if not c:
                break
            feed = c
            continue
        if status == ST_EOF:
            break
        if status == ST_WANT_READ:
            c = server.recv(16384)
            if not c:
                break
            feed = c
            continue
        print("FAIL: read error"); return 1

    rpc(ctrl, OP_FREE, ssl_id)
    server.close(); ctrl.close()

    head = resp.split(b"\r\n", 1)[0].decode("latin1") if resp else "(no data)"
    print("bytes:", len(resp), "| first line:", head)
    return 0 if head.startswith("HTTP/") else 1


if __name__ == "__main__":
    sys.exit(main())
