# Wire protocol — Model B (crypto oracle)

> ⚠️ **Historical / planned, NOT what ships.** The shipping `amissl.library`
> speaks the **Option-1 tunnel** (CONNECT + plaintext relay) to
> `daemon/tls_proxy.py` — see the README and `docs/DESIGN.md`. Model B (this
> document) is a planned alternative whose `OOP_*` opcodes exist in `amiga/amissl.c`
> but are not used by `sess_connect`. `tls_oracle.py`/`oracle_sim.py` validate it
> standalone. Read this as the design for a possible future, not current behaviour.

Validated on the Mint VM 2026-05-30 (`tls_oracle.py` + `oracle_sim.py`, real
`HTTP/1.1 200 OK` from example.com over TLSv1.3). The Option-1 tunnel below is what
the current shim actually uses.

The shim opens ONE control TCP connection to the daemon (the LAN box) and
multiplexes many TLS objects over it. The app's own socket to `server:443` (over the
native Amiga stack) carries the real TLS records; the daemon never talks to the
server. All multi-byte fields are big-endian (68k-native).

```
request :  op(1)  ssl_id(4)  aux(4)  inlen(4)  in[inlen]
response:  status(1)  pending(4)  outlen(4)  out[outlen]
```

- `aux` = `maxlen` for READ (bytes the app asked for); 0 for all other ops.
- `pending` = plaintext bytes still buffered in the daemon's SSLObject *after* this op.
  The shim caches this to answer `SSL_pending()` and to know it can drain more without
  a network read. **This is why the 68k shim needs no plaintext buffer of its own.**
- Status: `0 OK` (also = handshake DONE / read DATA), `1 WANT_READ`, `2 EOF`, `3 ERROR`.

| op | name | `aux` | `in` | `out` | notes |
|----|------|-------|------|-------|-------|
| 1 | NEW | 0 | SNI hostname | ssl_id (4 B) | creates SSLObject(server_hostname=SNI) + 2 MemoryBIOs |
| 2 | HANDSHAKE | 0 | ciphertext from server (may be empty) | ciphertext to send to server | loop until status OK |
| 3 | WRITE | 0 | plaintext | ciphertext to send to server | status OK |
| 4 | READ | maxlen | ciphertext from server (may be empty) | ≤maxlen plaintext | OK=got data (check `pending` for leftover), WANT_READ=need more ciphertext, EOF=close_notify |
| 5 | SHUTDOWN | 0 | ciphertext from server (opt) | close_notify ciphertext | |
| 6 | FREE | 0 | — | — | drop the SSLObject |

**Pump pattern (what the shim does):**
- *Handshake:* `HANDSHAKE(ssl_id, cipher_in)`; send any `out` to server; if `WANT_READ`,
  `recv()` from server into `cipher_in` and loop; stop on `OK`.
- *Write:* `WRITE(ssl_id, plaintext)` → `send(out)` to server.
- *Read:* `READ(ssl_id, ciphertext, maxlen)`; on `OK`, hand `out` to the app; if
  `pending>0`, the daemon still has buffered plaintext — next `SSL_read` calls `READ`
  with empty `in` (no network read needed); when `pending==0`, `recv()` more ciphertext;
  on `WANT_READ` `recv()` and feed; on `EOF` stop.
- *SSL_pending():* return the cached `pending` from the last response — never 0 by
  default (see DESIGN §10).

Validated on the Mint VM 2026-05-30 against example.com, including `maxlen=64` to
exercise the `pending`-driven drain path across many small reads.

---

# Wire protocol — Option 1 (tunnel)  [REFERENCE ONLY, not chosen]

The Amiga↔daemon link is a plain TCP connection. After connecting, the Amiga sends a
single CRLF/LF-terminated handshake line, the daemon replies with one status line,
and from then on the connection is a transparent byte tunnel (plaintext on the Amiga
side, TLS on the server side).

## Handshake

Amiga → daemon (one line, terminated by `\n`; `\r` tolerated):

```
CONNECT <host> <port> [<sni>]\n
```

- `<host>`  — target server hostname or dotted-decimal IPv4 (no spaces)
- `<port>`  — target TCP port, decimal (usually `443`)
- `<sni>`   — optional TLS SNI / cert-verification name; defaults to `<host>`

Daemon → Amiga (one line, terminated by `\n`):

```
OK\n                  TLS handshake to the server succeeded; tunnel is open
ERR <reason>\n        failure (DNS, connect, TLS verify, etc.); daemon then closes
```

## Relay

After `OK`:

- Bytes the Amiga writes → daemon encrypts and writes to the server.
- Bytes the server sends → daemon decrypts and writes to the Amiga.
- Either side closing ends the tunnel.

## Notes / future

- **Auth:** none yet. If LAN trust is insufficient, prepend a shared token:
  `CONNECT <token> <host> <port> [<sni>]`. Decide in DESIGN §9.4.
- **Why a text line:** trivial to generate from 68k C and trivial to debug with
  `nc`/`telnet`. A binary header buys nothing here.
- This protocol is intentionally NOT the `BSDOP_SSL_*` opcode set — that is Option 2.
