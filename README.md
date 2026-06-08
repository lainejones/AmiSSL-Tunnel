# amissl-tunnel — LAN TLS offload for AmigaOS

Take the AmiSSL/OpenSSL ABI emulation proven in **a314SSLlib** (now merged into
**a314bsd**) and generalise it: offload TLS to a **generic machine on the LAN**
(an Ubuntu box, anything that runs Python) reached over **ordinary TCP sockets**,
instead of to the A314 Pi over the A314 bus.

The win: the AmiSSL shim no longer assumes the A314 ecosystem. It rides whatever
`bsdsocket.library` is resident — **Roadshow, AmiTCP, Miami, or a314bsd** — so any
Amiga with a working TCP stack can do HTTPS in iBrowse/AWeb while the slow crypto
runs on a fast LAN host.

```
iBrowse / AWeb
   │  OpenSSL / AmiSSL LVO calls
   ▼
amissl.library + amisslmaster.library      ← reused, ABI-frozen (a314SSLlib builds 1–27)
   │  "open a connection, relay these bytes"
   ▼
[transport module]  ──TCP via resident bsdsocket──►  LAN TLS daemon  ──TLS──►  server
   (Roadshow / AmiTCP / Miami / a314bsd)               (Ubuntu, Python)
```

## Status

**Working end-to-end on 68k for BOTH iBrowse 3 and AWeb 3.6b8 — the built shim is the
Option-1 TUNNEL, not Model B.**

The 68k shim in `amiga/` (`amissl.library` + `amisslmaster.library`) is built and
**validated in WinUAE** (2026-06-01): a clean OS 3.2 / 68020 box with WinUAE's
`bsdsocket_emu`. **iBrowse 3** and **AWeb 3.6b8** both load **https://aminet.net** over the
offload — full page **plus all 14 inline images, zero failures, on the first pass**. The chain is
`browser → amisslmaster → amissl shim → tls_proxy.py → TLS to server → plaintext relay`.

Getting AWeb (and clean concurrent image loading in both) working took three fixes beyond
the initial tunnel; see **Lessons learned** below.

What the built shim actually does (despite the Model-B framing below): at
`SSL_connect` it opens its own socket to the daemon, sends `CONNECT <sni> 443\n`,
gets `OK\n` (daemon has done the verified TLS to the real server), then
`Dup2Socket`s that socket onto iBrowse's fd and relays plaintext. So `SSL_read/write`
are plain `recv/send`. **The matching daemon is `daemon/tls_proxy.py`** (the tunnel),
NOT `tls_oracle.py`.

**Model B (crypto oracle) — the originally-decided model — is still TODO.** The
`OOP_NEW/HANDSHAKE/...` opcodes are defined in `amissl.c` but `sess_connect` doesn't
use them; rewriting it to the oracle pump (+ the `SSL_pending` fix, DESIGN §10) is
the remaining work. `tls_oracle.py` + `oracle_sim.py` validate that path on the
daemon side (real `HTTP/1.1 200 OK` from example.com over TLSv1.3 on the Mint VM).

Known gaps from the WinUAE test: iBrowse caps concurrent connections (~5), so the
tunnel daemon must **close each connection once the response body is delivered** or
later images starve (fixed in `tls_proxy.py`). iBrowse's missing **throbber/spinning
animation** is a missing *install* asset (rerun the iBrowse installer), not an offload issue.

## Lessons learned (debugging AWeb + concurrent images)

These are the non-obvious things that cost time; they are baked into the current `amiga/amissl.c`.

1. **Sentinel pointers must look like real pointers.** AWeb range-checks every `SSL`/`SSL_CTX`
   it receives from AmiSSL against `[0x1000, 0xFFFFFFF0)` and frees+rejects anything below
   `0x1000` (see AWeb's `GetSharedSSLCTX`). The shim originally returned `1` for `SSL_CTX` and a
   small session index (1..16) for `SSL`, so AWeb aborted the secure connection right after
   `SSL_CTX_new`. iBrowse never range-checked, so `1` worked there. Fix: `SSL_CTX → 0x4000`,
   `SSL handle → 0x5000 + index` (decoded back in `sess_from_ssl`).

2. **The diagnostic probe build does not survive concurrency — ship with `AMISSL_PROBE 0`.**
   With probes on, *every* AmiSSL LVO opens its own TCP connection to the daemon to emit a marker.
   Fine sequentially; under a burst of parallel image fetches it floods/races and the real
   connections fail. Probes are a debug aid only.

3. **A bsdsocket `SocketBase` is per-task; the shim must not keep it in one shared field.**
   `InitAmiSSLA` receives the app's `SocketBase` per task, but the shim stored it in the single
   shared `base->BsdBase`. Browsers fetch inline images in ~6–7 **parallel tasks**; each init
   clobbered the shared field, so a task's `sess_connect` ran socket I/O on another task's base —
   the daemon saw a connect with no `CONNECT` line ("0 bytes read") and the image failed. The
   timeline proof was unmistakable: *simultaneous* bursts all failed, the browser's *one-at-a-time*
   retries succeeded. Fix: a `g_task_bb[]` map (task → SocketBase) filled by `InitAmiSSLA` / cleared
   by `CleanupAmiSSLA`; `SSL_new` pins the caller task's base into `struct SslSess.bbase`;
   `sess_connect`/`sess_read`/`sess_write` use `s->bbase`, never the shared field. This is what took
   both browsers from "partial, flaky" to "14/14 images, zero failures, first pass."

   **This same defect exists in the parent `a314SSLlib`** (`amiga/amissl.c` `OpenLibrary`s one
   bsdsocket base into the shared `base->BsdBase` and routes all tasks' SSL ops through it, with no
   per-task isolation). It is a strong candidate for why concurrent-image browsers behaved
   unreliably there — the per-task isolation added here was simply missing.

4. **Browser-side image behaviour ≠ transport.** AWeb's default `IMAGELOADING` is not `ALL`, so it
   instantiates inline `<img>` as suppressed placeholders and never fetches them (a plain refresh
   serves cache). Force with ARexx `IMAGELOADING ALL` + `RELOAD IMAGES` (port `AWEB.#`), and make it
   permanent with `SAVESETTINGS` (writes `ENVARC:AWeb3/`). iBrowse autoloads images by default.

5. **Write Amiga scripts LF-only.** A Windows-CRLF `S/autotest` makes AmigaDOS pass the trailing
   `\r` as part of a URL argument → `GET /path\r HTTP/1.1` → `400 Bad Request`. Use WSL `printf`,
   not PowerShell `Set-Content`.

## Credits / acknowledgements

- **AWeb** source (`Source/AWebAPL/amissl.c`, ARexx docs) — © 2002 **Yvon Rozijn**, changes © 2025
  **amigazen project**, distributed under the **AWeb Public License**. Reading AWeb's open source is
  what revealed the `[0x1000, 0xFFFFFFF0)` pointer range-check (lesson 1) and the `IMAGELOADING`/
  `RELOAD IMAGES`/`SAVESETTINGS` ARexx commands (lesson 4). We did not copy AWeb code — we studied it
  to understand what AWeb expects from AmiSSL.
- **AmiSSL / OpenSSL ABI** — the LVO table and ABI emulated here follow AmiSSL (OpenSSL on AmigaOS).
- **a314SSLlib / a314bsd** — the parent project this forks the *idea* from; the AmiSSL ABI shim was
  first debugged there (builds 1–27). See "Relationship to existing projects" below.
- **Test site:** **aminet.net** — a small, Amiga-friendly HTTPS site used as the rendering target.
- **Tooling:** WinUAE (`bsdsocket_emu`), the amiga-gcc/Bebbo cross toolchain, and Python/asyncio for
  the `tls_proxy.py` daemon.

## Layout

| Path | Contents |
|------|----------|
| `docs/DESIGN.md` | Architecture, reusable assets, socket-locality finding, the three models, **Model B port plan (§10)** |
| `docs/PROTOCOL.md` | **Model B oracle protocol** (chosen); Option-1 tunnel kept for reference |
| `daemon/tls_proxy.py` | **The ACTIVE daemon** — Option-1 tunnel; this is what the built 68k shim speaks. Run it: `python3 tls_proxy.py 0.0.0.0 8443` |
| `daemon/tls_oracle.py` | Model B crypto-oracle daemon (memory BIO). Validated standalone, but NOT yet wired to the 68k shim (Model B port is TODO). |
| `daemon/oracle_sim.py` | Reference 'shim simulator' for Model B — what the Amiga side would do once ported |
| `daemon/smoke_test.py` | Smoke test for the tunnel daemon |
| `amiga/` | **Built tunnel shim**: `amissl.c`/`amisslmaster.c` (+ `_start.S`), compiled `amissl.library` (~53 KB) + `amisslmaster.library`. `make` under WSL (amiga-gcc). |
| `include/` | (empty) shared headers |

## Relationship to existing projects

- **a314bsd** — bsdsocket proxy over A314; an earlier home of the AmiSSL shim.
  This project is a clean, separate fork of the *idea*, not the code.
- **a314SSLlib** — the original dev sandbox where the AmiSSL ABI shim was first
  debugged (builds 1–27). The lessons captured there are the starting capital for
  this project.
