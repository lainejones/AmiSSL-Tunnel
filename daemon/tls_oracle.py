#!/usr/bin/env python3
"""
AmiSSL emu — Model B: TLS crypto-ORACLE daemon (memory BIO, no sockets its end).

The Amiga app (iBrowse) keeps its OWN socket to server:443 over the native stack;
that socket carries real TLS records. This daemon never touches the network to the
server. It is a pure crypto oracle: feed it ciphertext, it returns plaintext (and
the ciphertext to put on the wire), via ssl.SSLObject + two ssl.MemoryBIO.

This preserves the fd-locality / WaitSelect contract that iBrowse relies on
(DESIGN §3, "socket locality") while offloading the slow crypto to a fast LAN host.

Wire protocol (one control TCP connection per shim; big-endian to match 68k):
    request :  op(1) ssl_id(4) aux(4) inlen(4) in[inlen]
    response:  status(1) pending(4) outlen(4) out[outlen]
  aux      = maxlen for READ (bytes the app asked for); 0 for other ops.
  pending  = plaintext bytes still buffered in the SSLObject after this op, so the
             shim can answer SSL_pending() and drain without a network read.
See docs/PROTOCOL.md "Model B" for op/status semantics and the in/out meaning.

Run:  python3 tls_oracle.py [host] [port]   (default 0.0.0.0:8443)
"""

import logging
import os
import socketserver
import ssl
import struct
import sys

LOG = logging.getLogger("tls_oracle")

# Opcodes
OP_NEW, OP_HANDSHAKE, OP_WRITE, OP_READ, OP_SHUTDOWN, OP_FREE = 1, 2, 3, 4, 5, 6
OP_PROBE = 7   # diagnostic: log aux as a marker, no session needed
# Status (ST_OK doubles as DONE for handshake / DATA for read)
ST_OK, ST_WANT_READ, ST_EOF, ST_ERROR = 0, 1, 2, 3

PLAINTEXT_CAP = 32768   # max plaintext returned per READ (bounds message size)


def recvn(sock, n):
    """Read exactly n bytes or return None on EOF."""
    buf = bytearray()
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            return None
        buf.extend(c)
    return bytes(buf)


def read_req(sock):
    hdr = recvn(sock, 13)
    if hdr is None:
        return None
    op, ssl_id, aux, inlen = struct.unpack(">BIII", hdr)
    data = b"" if inlen == 0 else recvn(sock, inlen)
    if inlen and data is None:
        return None
    return op, ssl_id, aux, data


def send_resp(sock, status, pending=0, out=b""):
    sock.sendall(struct.pack(">BII", status, pending, len(out)) + out)


class OracleHandler(socketserver.BaseRequestHandler):
    def setup(self):
        self.ctx = ssl.create_default_context()   # verifying, system CA bundle
        self.objs = {}                             # ssl_id -> {obj, inb, outb, host}
        self.next_id = 1

    def handle(self):
        sock = self.request
        LOG.info("control connection from %s", self.client_address)
        try:
            while True:
                req = read_req(sock)
                if req is None:
                    break
                self.dispatch(sock, *req)
        except (ConnectionError, OSError) as e:
            LOG.warning("%s: connection error: %s", self.client_address, e)
        finally:
            LOG.info("control connection closed %s", self.client_address)

    def dispatch(self, sock, op, ssl_id, aux, data):
        if op == OP_PROBE:
            LOG.info("PROBE marker=0x%X", aux)
            send_resp(sock, ST_OK)
            return
        if op == OP_NEW:
            host = data.decode("ascii", "replace")
            inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
            obj = self.ctx.wrap_bio(inb, outb, server_hostname=host)
            sid = self.next_id
            self.next_id += 1
            self.objs[sid] = {"obj": obj, "inb": inb, "outb": outb, "host": host}
            LOG.info("NEW ssl_id=%d host=%s", sid, host)
            send_resp(sock, ST_OK, 0, struct.pack(">I", sid))
            return

        o = self.objs.get(ssl_id)
        if o is None:
            LOG.warning("op=%d for unknown ssl_id=%d", op, ssl_id)
            send_resp(sock, ST_ERROR)
            return
        obj, inb, outb = o["obj"], o["inb"], o["outb"]

        if op == OP_HANDSHAKE:
            if data:
                inb.write(data)            # ciphertext from the server
            try:
                obj.do_handshake()
                out = outb.read()          # last flight to the server
                LOG.info("HANDSHAKE ssl_id=%d DONE %s %s", ssl_id,
                         obj.version(), obj.cipher())
                send_resp(sock, ST_OK, 0, out)
            except ssl.SSLWantReadError:
                out = outb.read()          # our flight to send, then need more
                send_resp(sock, ST_WANT_READ, 0, out)
            except ssl.SSLError as e:
                LOG.warning("HANDSHAKE ssl_id=%d failed: %s", ssl_id, e)
                send_resp(sock, ST_ERROR)

        elif op == OP_WRITE:
            try:
                # NOTE: we deliberately do NOT rewrite the request anymore.  Forcing
                # "Connection: close" was meant to make the browser read to EOF, but
                # diagnostics proved iBrowse does NOT read to EOF here — it reads body
                # in 2048-aligned chunks, ignores nothing-but stops after a fixed
                # budget, and never polls.  With keep-alive (server's natural mode for
                # aminet) iBrowse reads exactly Content-Length body bytes = the WHOLE
                # gzip body, which is what we want.  Pass the request through verbatim.
                obj.write(data)            # plaintext in
                out = outb.read()          # ciphertext to send
                reqline = data.split(b"\r\n", 1)[0][:120].decode("latin1")
                LOG.info("WRITE ssl_id=%d plain=%d cipher=%d | REQ: %s",
                         ssl_id, len(data), len(out), reqline)
                send_resp(sock, ST_OK, 0, out)
            except ssl.SSLError as e:
                LOG.warning("WRITE ssl_id=%d failed: %s", ssl_id, e)
                send_resp(sock, ST_ERROR)

        elif op == OP_READ:
            if data:
                inb.write(data)            # ciphertext from the server
            maxlen = aux if 0 < aux <= PLAINTEXT_CAP else PLAINTEXT_CAP
            try:
                p = obj.read(maxlen)       # up to maxlen; rest stays buffered here
                tag = ""
                if p[:5] == b"HTTP/":      # log the full response headers once
                    he = p.find(b"\r\n\r\n")
                    hdrs = p[:he if he >= 0 else 400]
                    tag = " | RESP: " + hdrs.replace(b"\r\n", b" | ").decode("latin1")[:380]
                LOG.info("READ ssl_id=%d req=%d feed=%d -> plain=%d pending=%d%s",
                         ssl_id, aux, len(data), len(p), obj.pending(), tag)
                send_resp(sock, ST_OK, obj.pending(), p)
            except ssl.SSLWantReadError:
                LOG.info("READ ssl_id=%d req=%d feed=%d -> WANT_READ", ssl_id, aux, len(data))
                send_resp(sock, ST_WANT_READ)        # need more ciphertext from wire
            except ssl.SSLZeroReturnError:
                LOG.info("READ ssl_id=%d -> EOF", ssl_id)
                send_resp(sock, ST_EOF)              # clean close_notify
            except ssl.SSLError as e:
                LOG.warning("READ ssl_id=%d failed: %s", ssl_id, e)
                send_resp(sock, ST_ERROR)

        elif op == OP_SHUTDOWN:
            if data:
                inb.write(data)
            try:
                obj.unwrap()               # emit close_notify
            except ssl.SSLError:
                pass
            LOG.info("SHUTDOWN ssl_id=%d", ssl_id)
            send_resp(sock, ST_OK, 0, outb.read())

        elif op == OP_FREE:
            self.objs.pop(ssl_id, None)
            LOG.info("FREE ssl_id=%d", ssl_id)
            send_resp(sock, ST_OK)

        else:
            LOG.warning("unknown op=%d", op)
            send_resp(sock, ST_ERROR)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    host = (sys.argv[1] if len(sys.argv) > 1
            else os.environ.get("AMISSL_LISTEN_HOST", "0.0.0.0"))
    port = int(sys.argv[2] if len(sys.argv) > 2
               else os.environ.get("AMISSL_LISTEN_PORT", "8443"))
    with Server((host, port), OracleHandler) as srv:
        LOG.info("AmiSSL emu TLS oracle (Model B) listening on %s:%d", host, port)
        srv.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    try:
        main()
    except KeyboardInterrupt:
        pass
