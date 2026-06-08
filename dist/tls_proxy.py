#!/usr/bin/env python3
"""
AmiSSL-Tunnel — LAN TLS offload daemon.

Listens for plaintext TCP from an Amiga (via its resident bsdsocket.library),
reads a one-line CONNECT handshake naming the target server, performs the TLS
handshake AND the outbound TCP connection to that server, then relays bytes
transparently:  Amiga plaintext  <->  daemon  <->  TLS to server.

This is what the shipping amissl.library speaks to. See the project README.

Run on the Ubuntu/LAN box:
    python3 tls_proxy.py                 # listen 0.0.0.0:8443
    python3 tls_proxy.py 0.0.0.0 8443    # explicit host/port
Env overrides: AMISSL_LISTEN_HOST, AMISSL_LISTEN_PORT.

Trust model (DESIGN §7): the Amiga<->daemon hop is plaintext on the trusted LAN;
the daemon holds the CA bundle and makes the cert-verification decision.
"""

import asyncio
import os
import re
import ssl
import sys
import logging

LOG = logging.getLogger("tls_proxy")

# Match Content-Length in response headers (to detect truncated bodies).
CL_RE = re.compile(rb"\r\nContent-Length:\s*(\d+)\r\n", re.IGNORECASE)

# Bytes to buffer per relay pump.
CHUNK = 16384
# Cap on the handshake line so a misbehaving/garbage client can't grow it forever.
MAX_HANDSHAKE = 512


def make_client_context() -> ssl.SSLContext:
    """Default verifying client context: system CA bundle, hostname check on."""
    ctx = ssl.create_default_context()
    # create_default_context() already sets verify_mode=CERT_REQUIRED and
    # check_hostname=True. Keep it strict — verification is the whole point.
    return ctx


async def read_handshake(reader: asyncio.StreamReader) -> bytes:
    """Read one LF-terminated line, bounded by MAX_HANDSHAKE."""
    line = await reader.readuntil(b"\n")
    if len(line) > MAX_HANDSHAKE:
        raise ValueError("handshake line too long")
    return line


def parse_handshake(line: bytes):
    """Parse 'CONNECT <host> <port> [<sni>]'. Returns (host, port, sni)."""
    text = line.decode("ascii", "replace").strip()
    parts = text.split()
    if len(parts) < 3 or parts[0].upper() != "CONNECT":
        raise ValueError(f"bad handshake: {text!r}")
    host = parts[1]
    try:
        port = int(parts[2])
    except ValueError:
        raise ValueError(f"bad port: {parts[2]!r}")
    if not (0 < port < 65536):
        raise ValueError(f"port out of range: {port}")
    sni = parts[3] if len(parts) >= 4 else host
    return host, port, sni


async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter, tag="?", track=False):
    """One direction of the relay until EOF/error.

    When track=True (the server->amiga direction) we sniff the HTTP response
    headers for Content-Length and, at EOF, report whether the body arrived in
    full or was truncated — so we can tell relay-side cut-offs from iBrowse-side
    issues when an inline image fails to load.
    """
    total = 0
    first = True
    head = b""
    clen = None          # parsed Content-Length, or -1 if none present
    body_start = 0       # byte offset where the body begins
    stopped = "EOF"
    try:
        while True:
            data = await src.read(CHUNK)
            if not data:
                break
            if first:
                LOG.info("relay %s: first %d bytes: %r", tag, len(data), data[:48])
                first = False
            if track and clen is None:
                head += data
                i = head.find(b"\r\n\r\n")
                if i >= 0:
                    m = CL_RE.search(head[:i + 4])
                    clen = int(m.group(1)) if m else -1
                    body_start = i + 4
                    # 304/204 carry no body — treat as 0-length so we close at the
                    # header boundary instead of lingering on the server keep-alive
                    # (an open 304 revalidation otherwise shows iBrowse "busy" ~75s).
                    sline = head[:head.find(b"\r\n")]
                    if b" 304 " in sline or b" 204 " in sline:
                        clen = 0
            total += len(data)
            dst.write(data)
            await dst.drain()
            # Once the full Content-Length body is delivered, close instead of
            # lingering on the server's keep-alive. iBrowse opens a fresh
            # connection per image and caps concurrent connections (~5); a
            # lingering tunnel holds a slot for ~75s and starves the remaining
            # image fetches. Closing promptly frees the slot so all images load.
            if track and clen is not None and clen >= 0 and (total - body_start) >= clen:
                stopped = "complete"
                break
    except (ConnectionError, asyncio.IncompleteReadError) as e:
        stopped = type(e).__name__
    finally:
        if track and clen is not None and clen >= 0:
            body = total - body_start
            verdict = "OK" if body >= clen else "TRUNCATED"
            LOG.info("relay %s: %s total=%d body=%d/%d %s",
                     tag, stopped, total, body, clen, verdict)
        else:
            LOG.info("relay %s: %s after %d bytes", tag, stopped, total)
        try:
            dst.write_eof()
        except (OSError, RuntimeError):
            pass


async def handle_client(a_reader, a_writer):
    peer = a_writer.get_extra_info("peername")
    s_writer = None
    try:
        try:
            # The shim's diagnostic probe is a 13-byte binary frame whose first
            # byte is OP_PROBE (7); decode the marker (bytes 5..8) and log it so
            # we can trace the app's AmiSSL call sequence (used to debug AWeb).
            first = await a_reader.readexactly(1)
            if first == b"\x07":
                hdr = await a_reader.readexactly(12)
                marker = int.from_bytes(hdr[4:8], "big")
                LOG.info("[%s] PROBE marker=0x%08X", peer, marker)
                return
            line = first + await read_handshake(a_reader)
            host, port, sni = parse_handshake(line)
        except (asyncio.IncompleteReadError, ValueError, asyncio.LimitOverrunError) as e:
            LOG.warning("[%s] handshake failed: %s", peer, e)
            a_writer.write(b"ERR bad-handshake\n")
            await a_writer.drain()
            return

        LOG.info("[%s] CONNECT %s:%d (sni=%s)", peer, host, port, sni)

        ctx = make_client_context()
        try:
            s_reader, s_writer = await asyncio.wait_for(
                asyncio.open_connection(host=host, port=port, ssl=ctx,
                                        server_hostname=sni),
                timeout=30,
            )
        except ssl.SSLCertVerificationError as e:
            LOG.warning("[%s] cert verify failed for %s: %s", peer, sni, e)
            a_writer.write(b"ERR cert-verify\n")
            await a_writer.drain()
            return
        except (asyncio.TimeoutError, OSError, ssl.SSLError) as e:
            LOG.warning("[%s] connect to %s:%d failed: %s", peer, host, port, e)
            a_writer.write(b"ERR connect\n")
            await a_writer.drain()
            return

        a_writer.write(b"OK\n")
        await a_writer.drain()
        LOG.info("[%s] tunnel open -> %s:%d", peer, host, port)

        p = f"{peer[1]}" if isinstance(peer, tuple) else str(peer)
        await asyncio.gather(
            pump(a_reader, s_writer, f"[{p}] A->S"),               # Amiga plaintext -> server (TLS)
            pump(s_reader, a_writer, f"[{p}] S->A", track=True),   # server (TLS) -> Amiga plaintext
            return_exceptions=True,   # one side erroring must not destroy the other mid-flight
        )
    except Exception:
        LOG.exception("[%s] unhandled error", peer)
    finally:
        for w in (s_writer, a_writer):
            if w is not None:
                try:
                    w.close()
                except OSError:
                    pass
        LOG.info("[%s] closed", peer)


async def main():
    host = (sys.argv[1] if len(sys.argv) > 1
            else os.environ.get("AMISSL_LISTEN_HOST", "0.0.0.0"))
    port = int(sys.argv[2] if len(sys.argv) > 2
               else os.environ.get("AMISSL_LISTEN_PORT", "8443"))

    server = await asyncio.start_server(handle_client, host, port)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    LOG.info("AmiSSL-Tunnel TLS daemon listening on %s", addrs)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
