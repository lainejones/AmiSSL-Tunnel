# AmiSSL-Tunnel — deployment

Give a plain 68k Amiga `https://` by offloading the TLS to a fast machine on
your LAN. Two installs: the **daemon** on the LAN box, the **shim** on the Amiga.

```
iBrowse / AWeb / Amelinium  (Amiga, this shim)
        │  plaintext over your TCP/IP stack
        ▼
   tls_proxy.py  (LAN box: Linux/Pi/Mac/PC)  ──TLS──►  the real https:// server
```

## 1. Daemon (the LAN box)

Needs **python3** only (stdlib — no pip packages).

**Linux / Raspberry Pi (systemd):**
```sh
sudo ./install-daemon.sh          # listens on 0.0.0.0:8443, starts on boot
# sudo AMISSL_PORT=9000 ./install-daemon.sh   # custom port
```
It prints the **IP and port** to type into the Amiga installer.

**macOS / Windows / WSL (or just to try it):** run it directly —
```sh
python3 tls_proxy.py 0.0.0.0 8443
```

The daemon holds the CA bundle and does the certificate verification; the
Amiga↔daemon hop is plaintext on your trusted LAN (see `docs/DESIGN.md` §7).

## 2. Shim (the Amiga)

From the extracted archive on the Amiga:
```
Installer Install
```
It backs up any existing AmiSSL, copies `amissl.library` + `amisslmaster.library`
to `LIBS:`, and asks for the **daemon address + port** — saved to
`ENV:`/`ENVARC:AMISSLPROXY` so it persists. No recompile needed to point it
somewhere else later: re-run the Installer or edit `ENVARC:AMISSLPROXY`.

Requirements: a working TCP/IP stack (Roadshow, AmiTCP, Miami, or a314bsd).

## 3. Test

Make sure the daemon is running and your stack is up, then launch iBrowse, AWeb,
or Amelinium and load an `https://` site (e.g. `https://aminet.net`).

## Configuration reference

`ENV:AMISSLPROXY` = `host:port`
- `host` — the daemon's LAN IP (e.g. `192.168.1.50`) or a hostname your stack
  can resolve.
- `port` — the daemon's port (default `8443`).
- If unset/unparseable, the shim falls back to its compiled default
  (`127.0.0.1:8443`, used for local/VM testing).

The shim reads it once at first TLS connect. The tunnel port the daemon connects
out on is taken from the app's own socket (`getpeername`), so HTTPS, mail
(IMAPS/POP3S/SMTPS), IRC, and FTPS all work — not just port 443.
