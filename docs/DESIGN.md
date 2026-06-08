# AmiSSL-Tunnel — design notes

> **How the shipping shim works** is described in the project README. In short:
> at `SSL_connect` the shim opens a socket to the daemon, sends `CONNECT host port`,
> and once the daemon has done the verified TLS handshake it `Dup2Socket`s that
> socket onto the app's fd and relays plaintext.
>
> The rest of this file is **design history** — it records the alternatives that
> were considered during development (including a crypto-oracle approach that was
> never built). Kept for context; not a description of current behaviour.

## 1. Goal

Let an unmodified Amiga TLS app (iBrowse 3.0, AWeb) do HTTPS while the TLS crypto
runs on a fast LAN host. Decouple the offload from A314 entirely so it works over
*any* resident `bsdsocket.library` (Roadshow / AmiTCP / Miami / a314bsd).

## 2. Two reusable assets from a314SSLlib

The hard-won work splits cleanly into two pieces, and **only the second is tied to
A314**:

1. **AmiSSL / OpenSSL ABI emulation** — `amissl.library` + `amisslmaster.library`:
   the 5452-slot LVO table, `VERSION=50`, the `OpenAmiSSLTagList → InitAmiSSLA →
   write GetAmiSSLBase` base-acquisition dance, the BIO path, the a6-wrapper
   trampolines, the "callback getters must return a real callable, never 0/1UL"
   rule. **This is transport-agnostic. Reuse verbatim.**

2. **TLS-offload backend** — `SSL_connect/read/write` ship `BSDOP_SSL_*` RPCs
   (`include/ssl_proto.h` in a314bsd) over the **A314 stream** to `bsdsocket.py`.
   **This is the part that gets replaced** with a TCP transport to a LAN daemon.

The whole project is: keep asset #1, give asset #2 a new bottom end.

## 3. The crux — how does the target server reach the daemon?

This is the real open question, because in the A314 design the Pi owned *both* the
plain socket *and* the TLS wrap (same machine, shared fd namespace), so `SSL_set_fd`
worked: the app connected (proxied) to the server, got a Pi-side fd, then
`SSL_set_fd(ssl, fd)` told the Pi to TLS-wrap *that exact socket*.

On a LAN, the app's TCP connection terminates at the **daemon**, not the server. So
the daemon must make its own outbound connection to the server, which means it has
to be *told the target*. Where does that target come from? Depends on the app's call
path:

- **BIO path** (what the a314SSLlib build-10 code drives): `amissl` itself does the
  `gethostbyname → socket → connect` inside `BIO_do_connect`, and it already knows
  the target from `BIO_ctrl(cmd=100, "host:port")`. **So `amissl` controls socket
  creation and can connect to the daemon instead of the server, passing the real
  target along.** Clean.

- **Direct `SSL_set_fd` path**: the app does its *own* `socket()/connect()` (through
  the resident bsdsocket, straight to the server) and hands `amissl` an
  already-connected fd. Here `amissl` does *not* control the connect target, so it
  cannot transparently redirect to the daemon. Options:
    - require the app to use the BIO path (iBrowse 3.0's network module — confirm),
    - or intercept at the resident-bsdsocket level (heavier; a SOCKS-ish shim),
    - or capture the intended host from the SNI set later and re-dial — ugly.

**Action item:** confirm which path iBrowse 3.0 and AWeb actually use for HTTPS.
a314SSLlib build-23..27 notes say iBrowse crashed on `SSL_new` (so it uses the
`SSL_new` object path), but build 10 implemented the BIO path because `op=52
SSL_NEW` never fired — i.e. iBrowse drove the **BIO** path. Re-verify against the
final working a314bsd build before committing.

### FINDING (2026-05-30, from reading a314bsd/amiga/amissl.c)

Both paths are implemented. `ami_BIO_ctrl(cmd=10)` (lines 894-955) owns the full
chain itself: `_bsd_gethostbyname → _bsd_socket → _bsd_connect(host:port) → SSL_new
→ SSL_set_fd → SSL_set_sni → SSL_connect`. `ami_SSL_set_fd` (line 629) is the direct
path. **a314SSLlib build-26 disassembly proved iBrowse 3.0's main binary calls
`SSL_CTX_new`, `SSL_CTX_ctrl`, and `SSL_set_fd` directly — i.e. iBrowse uses the
DIRECT path and does its OWN `socket()/connect()`.** The shim does NOT own the
connect for iBrowse.

### The deeper insight: SOCKET LOCALITY

a314bsd's TLS offload works *because the socket and the TLS engine live on the same
machine (the Pi)*. iBrowse does `connect()` → a314bsd proxies it → the **Pi** holds
the socket. `SSL_set_fd(ssl, fd)` then says "wrap the socket you already own," and
`WaitSelect` on that fd proxies to the Pi's `select`. Offload is trivial because the
socket was never on the Amiga.

The moment you use a **native Amiga stack (Roadshow/AmiTCP/Miami)** over real
Ethernet, the socket lives **on the Amiga**, divorced from the TLS engine on the LAN
box. `SSL_set_fd(ssl, local_fd)` hands the offload box a socket it cannot see. You
cannot do "TLS over that socket" on a remote machine without either moving the bytes
(breaks the fd-readiness/`WaitSelect` contract, adds latency) or shipping TLS
*records* back and forth. **This is the core constraint the tunnel model (Option 1)
silently assumed away.**

### Three honest models (supersedes the §4 framing for the native-stack case)

- **Model P — generalise a314bsd to Ethernet.** LAN box runs the bsdsocket+SSL
  service (exactly today's Pi role); Amiga reaches it over TCP instead of A314.
  Socket+TLS co-located again → `SSL_set_fd` works, iBrowse works, *all* the
  a314bsd/a314SSLlib design reused. BUT this means the Amiga runs a *proxy*
  bsdsocket, not its native stack — which for an Ethernet-equipped Amiga is
  redundant, and for an A314 Amiga is just... a314bsd. Limited new value.
- **Model T — BIO-path tunnel (the Option-1 daemon, already built & validated).**
  Clean and simple, but only serves apps that drive `BIO_new_ssl_connect/
  BIO_do_connect` (shim owns connect → redirect to daemon). **iBrowse 3.0 does NOT**;
  AWeb/Amelinium/others unknown — must check per app.
- **Model B — crypto-only via memory BIOs.** iBrowse's native socket really connects
  to `server:443` and carries real TLS records; the shim ships records↔plaintext to
  the daemon, which runs `ssl.SSLObject` + `MemoryBIO` (no sockets). Preserves the
  `WaitSelect`/fd contract AND offloads crypto on a native stack — the only model
  that does both. Cost: record-oriented protocol redesign + per-SSL-id TLS state on
  the daemon; chatty but LAN-local latency.

**Decision needed (see §9).** The validated tunnel daemon is real and useful, but it
does not by itself give iBrowse HTTPS over a native stack.

## 4. Daemon models

### Option 1 — full TLS-terminating tunnel (recommended)

The daemon is a forward proxy. `amissl` opens a plain TCP socket to the daemon,
sends a one-line handshake naming the target (see `docs/PROTOCOL.md`), the daemon
does the TLS handshake *and* the TCP connection to the real server, then it's a
transparent byte pipe. `SSL_read`/`SSL_write` collapse to `recv`/`send`.

- **Deletes the entire `BSDOP_SSL_*` opcode surface.** `amissl`'s job shrinks to
  "relay bytes through a tunnel."
- The shim already fakes `SSL_get_version`→"TLSv1.3", cipher bits→256,
  `verify_result`→OK with sentinels, so losing per-object introspection costs
  almost nothing.
- Daemon is ~130 lines of Python asyncio (see `daemon/tls_proxy.py`). Could even be
  stunnel/haproxy with a control shim, but a tiny custom daemon keeps the dynamic
  per-connection target trivial.

### Option 2 — SSL-object RPC over TCP

Reuse the `BSDOP_SSL_*` opcodes (`ssl_proto.h`) but carry them over a TCP socket
instead of the A314 stream. The daemon is the SSL half of `bsdsocket.py` with the
252-byte A314 chunk framing stripped and a TCP listener bolted on.

- Maximal reuse of the existing Pi-side SSL code.
- More protocol surface to maintain, and the `SSL_set_fd` fd-namespace problem from
  §3 still bites (the fd is to the daemon, not the server).

**Lean:** Option 1. The opcode plumbing was most of the a314SSLlib pain; the tunnel
throws it away.

## 5. Transport: module, not a new library — DECIDED

Keep the call-out logic as **plain C inside `amissl.library`** (a small
`proxy_transport.c` driving a TCP socket via the resident bsdsocket). A *new* shared
library means a new LVO table, Open/Close, base management — re-entering exactly the
swamp that ate a314SSLlib builds 1–27. Only promote to a real library if something
other than `amissl` needs to dial the daemon.

The transport needs only a tiny, portable socket subset: `gethostbyname`/`inet_addr`,
`socket`, `connect`, `send`, `recv`, `close`. Roadshow/AmiTCP/Miami all agree on
that core, which sidesteps most of the `MSG_PEEK` / `WaitSelect`-sigmask / `sin_len`
quirks documented in the a314bsd notes (those were about matching *app* expectations;
here we own both ends of the internal client socket).

## 6. Config pointer — DECIDED

`ENV:AMISSLPROXY = "192.168.1.50:8443"`, read once at `InitAmiSSL`. Falls back to a
compiled-in default if unset. AmigaOS-native, no extra config file format.
**Set by the Installer program** at install time (same approach/experience as the
A314Install project) — the user is asked for the daemon host:port and the Installer
writes `ENVARC:AMISSLPROXY` (persistent) + `ENV:AMISSLPROXY` (live).

## 7. Trust / security model — DECIDED (deliberately minimal)

- **No Amiga-side authentication.** Rationale: these are ~40-year-old machines with
  essentially no network security stack, and the deployment is always a local *home*
  LAN. Over-engineering auth here buys nothing real. The **LAN itself is the trust
  boundary.**
- The Amiga↔daemon hop is **plaintext** (same as the A314 link was) — accepted.
- The **daemon** holds the CA bundle and makes the certificate-verification decision
  (apt-managed, always current — the original advantage over on-Amiga AmiSSL). The
  Amiga trusts the daemon's verdict. This is where real security lives.
- Bind the daemon to the LAN interface; firewall asymmetry is Amiga→daemon inbound on
  the listener port, daemon→internet:443 outbound.
- *If* a hostile-LAN scenario ever matters, the cheapest add is a shared token in the
  handshake line — but it is explicitly out of scope for now.

## 8. What dropping A314 buys

- **No dispatcher task, no 252-byte chunking, no FPU-poisoning saga.** Those existed
  because A314 reads were chunked and preempted mid-RPC, poisoning the shared FPU and
  wrecking wget's float math. A normal blocking `recv()` on a real socket has none of
  that.
- **Tiny, portable socket subset** (§5) avoids most bsdsocket-quirk landmines.

## 9. Open questions / next steps

1. **Confirm iBrowse 3.0 / AWeb HTTPS call path** (BIO vs `SSL_set_fd`) — decides §3.
2. **Pick Option 1 vs Option 2** — decides how much of `bsdsocket.py` is reused.
3. Fork the AmiSSL shim source from a314bsd into `amiga/` once 1–2 are settled
   (the model determines how much of `amissl.c`'s transport gets rewritten).

Resolved: **Model = B (crypto oracle), target = native stack (Roadshow/AmiTCP) +
real Ethernet** (user, 2026-05-30); transport = module (§5); config =
`ENV:AMISSLPROXY` set by Installer (§6); auth = none, LAN is the trust boundary (§7).

## 10. Model B — Amiga port plan

**Validated:** `daemon/tls_oracle.py` + `daemon/oracle_sim.py` fetch real HTTPS over
TLSv1.3 on the VM. `oracle_sim.py` is the exact reference for the shim's behaviour.
Protocol in `docs/PROTOCOL.md` (Model B).

The shim keeps ONE control socket to the daemon (open lazily on first connect, cached
— e.g. in BsdBase or a global, multiplexing ssl_ids). The app's fd (from
`SSL_set_fd`) is the real TLS-record transport. Function mapping in `amissl.c`:

| iBrowse call | shim action |
|--------------|-------------|
| `SSL_new(ctx)` | allocate local handle; oracle `ssl_id` deferred to connect |
| `SSL_set_fd(ssl, fd)` | store iBrowse's own server socket fd |
| `SSL_ctrl(55, host)` | store SNI (already done: `g_last_sni`) |
| `SSL_connect(ssl)` | ensure control socket; `NEW(sni)`→ssl_id; handshake pump: `HANDSHAKE`↔`bsd_send/bsd_recv` on fd until OK |
| `SSL_write(ssl, p, n)` | `WRITE(ssl_id, p)`→ciphertext; `bsd_send(fd, ciphertext)`; return n |
| `SSL_read(ssl, b, n)` | `READ(ssl_id, ciphertext, maxlen=n)`; if cached `pending>0` feed empty (no recv); else `bsd_recv(fd)`→feed on WANT_READ; copy ≤ n plaintext out; cache `pending` from response |
| `SSL_pending(ssl)` | **return the cached `pending` from the last READ response — NOT 0** (see gotcha) |
| `SSL_shutdown` / `SSL_free` | `SHUTDOWN`→`bsd_send` close_notify; `FREE` |

**CRITICAL gotcha — `SSL_pending` must be real.** A decrypted TLS record can yield
more plaintext than iBrowse's `SSL_read` asked for; the shim buffers the rest. iBrowse
then `WaitSelect`s on its fd — but no NEW network data may arrive, so it would block
forever while decrypted plaintext sits in the shim. iBrowse checks `SSL_pending()`
before `WaitSelect`; the shim MUST report its buffered byte count. The current a314bsd
shim stubs `SSL_pending`→0 (fine there, because the Pi held the bytes); for Model B
that stub will hang the UI. Fix it when porting.

**Other port notes:**
- Reuse all of asset #1 unchanged (LVO table, base acquisition, BIO path, wrappers).
  Only the SSL object I/O functions (`ami_SSL_new/set_fd/connect/read/write/ctrl(55)/
  shutdown/free`) change, swapping the `BSDSSL_LVO_*` A314 calls for the oracle RPC +
  `bsd_send/bsd_recv` on the app fd. The plain `_bsd_socket/_bsd_connect/_bsd_send/
  _bsd_recv` helpers already exist (used by the BIO path).
- The BIO path (`ami_BIO_ctrl`) can be re-pointed to the oracle too, so BIO-style apps
  work without the tunnel daemon — single backend for both.
- Renegotiation / post-handshake writes during READ are deferred (rare; TLS1.3 servers
  generally don't). Revisit if an app needs it.

## 11. Browser validation + the per-task SocketBase finding (2026-06-01)

Both **iBrowse 3** and **AWeb 3.6b8** now load `https://aminet.net` over the Option-1 tunnel
in WinUAE (`bsdsocket_emu`) — full page **plus all 14 inline images, 0 failures, first pass**.
Three lessons came out of getting AWeb and concurrent image loading clean (full write-up in
`README.md` → *Lessons learned*); the architecture-level one belongs here:

**Concurrency: a bsdsocket `SocketBase` is per-task — the shim must track it per task.**
`InitAmiSSLA` is called once per app task, each carrying that task's own `SocketBase` (via the
`AmiSSL_SocketBase` tag). The shim originally stored it in the single shared field
`AmiSSLBase->BsdBase`. Browsers fetch inline images in several **parallel tasks**; each task's
`InitAmiSSLA` overwrote the shared field, so a task's `SSL_connect`/`SSL_read`/`SSL_write` could
run socket I/O on *another* task's base. Against the tunnel that surfaced as a daemon-side
connect with no `CONNECT` line ("0 bytes read") and a dropped image. The diagnostic signature is
distinctive: a **simultaneous burst of fetches all fails while one-at-a-time retries succeed.**

Fix (in `amiga/amissl.c`): a small `g_task_bb[]` map (`Task* → SocketBase`) populated by
`InitAmiSSLA` and cleared by `CleanupAmiSSLA`; `SSL_new` copies the *calling* task's base into the
session (`struct SslSess.bbase`); `sess_connect`/`sess_read`/`sess_write` use `s->bbase`, never the
shared field. Result: 14/14 images, 0 failures, both browsers.

**Relevance to Model B and to `a314SSLlib`.** The parent `a314SSLlib` (`amiga/amissl.c`) keeps the
socket/SSL base in the same single shared `base->BsdBase` (it `OpenLibrary`s one SSL-extended
bsdsocket base and routes every task's `BSDSSL_LVO_*` op through it — no per-task isolation). That
is the same defect class and a strong candidate for unreliable behaviour with concurrent-image
browsers there. **When porting to Model B, carry the per-task base map forward** — the oracle path
multiplexes `ssl_id`s over one control socket, but the *app fd* socket I/O (`SSL_set_fd` fd +
`bsd_send`/`bsd_recv`) is still per-task and must use the calling task's `SocketBase`.
