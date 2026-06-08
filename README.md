# AmiSSL-Tunnel — LAN TLS offload for AmigaOS

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

**Working end-to-end on 68k AmigaOS.** The shim in `amiga/` (`amissl.library` +
`amisslmaster.library`) is built and validated in WinUAE (clean OS 3.2 / 68020 with
`bsdsocket_emu`): **iBrowse 3**, **AWeb 3.6b8** and **Amelinium** all load
**https://aminet.net** over the offload — full page **plus all 14 inline images, zero
failures, on the first pass**. The chain is
`browser → amisslmaster → amissl shim → tls_proxy.py → TLS to server → plaintext relay`.

**How it works:** at `SSL_connect` the shim opens a socket to the daemon and sends
`CONNECT <host> <port>`; once the daemon has completed the verified TLS handshake to
the real server it `Dup2Socket`s that socket onto the app's fd and relays plaintext, so
`SSL_read`/`SSL_write` become plain `recv`/`send`. The port is read from the app's own
connected fd (`getpeername`), so the offload is generic — HTTPS, IMAPS, etc. The daemon
is `daemon/tls_proxy.py`.

Getting AWeb and clean concurrent image loading working took three non-obvious fixes;
see **Lessons learned** below.

**Operational notes:** iBrowse caps concurrent connections (~5), so the daemon closes
each connection as soon as the response body is delivered, or later images starve
(handled in `tls_proxy.py`).

## Installation

Two halves: a **daemon** on a fast LAN machine (Linux, Raspberry Pi, Mac, PC) and the
**shim** (`amissl.library` + `amisslmaster.library`) on the Amiga. Prebuilt libraries
and both installers are in [`dist/`](dist/).

### 1 — Daemon (the LAN box)

Requires **Python 3 only** (standard library; no pip packages).

**Linux / Raspberry Pi (systemd — installs and starts on boot):**

```sh
cd dist
sudo ./install-daemon.sh                      # listen on 0.0.0.0:8443
# sudo AMISSL_PORT=9000 ./install-daemon.sh    # custom port
```

This copies `tls_proxy.py` to `/opt/amissl-tunnel/`, creates a sandboxed systemd
service `amissl-tunnel`, starts it, and prints the **IP + port** to enter on the
Amiga. Manage it with:

```sh
systemctl status amissl-tunnel
journalctl -u amissl-tunnel -f                # live request log
```

**macOS / Windows / WSL, or just to try it** — run it directly:

```sh
python3 dist/tls_proxy.py 0.0.0.0 8443
```

**Firewall:** allow inbound TCP on the chosen port (default **8443**) from your LAN.
The daemon makes the outbound TLS connection and holds the system CA bundle, so it
does the certificate verification; the Amiga↔daemon hop is plaintext on your trusted
LAN.

### 2 — Shim (the Amiga)

Requires a working TCP/IP stack that provides `bsdsocket.library` — **Roadshow,
AmiTCP, Miami, or a314bsd**.

Copy the contents of `dist/` to the Amiga (network share, ADF, etc.), then from a
Shell **inside that folder**:

```
Installer Install
```

The installer backs up any existing `LIBS:amissl.library` / `amisslmaster.library`
to `*.bak` (so you can restore real AmiSSL later), copies the two shim libraries to
`LIBS:`, and asks for the **daemon address + port**, saving it to `ENV:` and
`ENVARC:AMISSLPROXY`.

**Manual install** (no Installer):

```
Copy amissl.library LIBS:
Copy amisslmaster.library LIBS:
SetEnv SAVE AMISSLPROXY 192.168.1.50:8443      ; your daemon's IP:port
```

(`SetEnv SAVE` writes both `ENV:` and `ENVARC:`.)

### 3 — Verify

With the daemon running and your stack up, launch iBrowse, AWeb, or Amelinium and
open an `https://` site such as `https://aminet.net`. The daemon log should show
`CONNECT aminet.net:443 → … → HTTP/1.1 200`.

### Configuration

`ENV:AMISSLPROXY` = `host:port`

- `host` — the daemon's LAN IP (e.g. `192.168.1.50`) or a hostname your stack resolves.
- `port` — the daemon's port (default `8443`).
- Unset/unparseable → the shim falls back to its compiled default `127.0.0.1:8443`
  (handy for local/VM testing).

It's read once at the first TLS connect. The outbound port the daemon dials is taken
from the app's own socket (`getpeername`), so HTTPS, mail (IMAPS / POP3S / SMTPS),
IRC, and FTPS all work — not just port 443.

### Uninstall

Restore the backups (`Copy LIBS:amissl.library.bak LIBS:amissl.library` and the
master), or just delete the two shim libraries if you had no prior AmiSSL.

### Build from source

`cd amiga && make` under WSL with the bebbo amiga-gcc toolchain on PATH builds both
libraries — see [`amiga/Makefile`](amiga/Makefile).

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
| `amiga/` | The shim: `amissl.c`/`amisslmaster.c` (+ `_start.S` LVO tables). `make` under WSL (amiga-gcc) builds `amissl.library` (~53 KB) + `amisslmaster.library`. |
| `daemon/tls_proxy.py` | The LAN daemon — this is what the 68k shim speaks to. Run it: `python3 tls_proxy.py 0.0.0.0 8443` |
| `daemon/smoke_test.py` | Smoke test for the daemon |
| `dist/` | Ready-to-install package: `Install` script, prebuilt libraries, daemon + `install-daemon.sh`. |
| `docs/DESIGN.md` | Architecture and design notes |

## Relationship to existing projects

- **a314bsd** — bsdsocket proxy over A314; an earlier home of the AmiSSL shim.
  This project is a clean, separate fork of the *idea*, not the code.
- **a314SSLlib** — the original dev sandbox where the AmiSSL ABI shim was first
  debugged (builds 1–27). The lessons captured there are the starting capital for
  this project.
