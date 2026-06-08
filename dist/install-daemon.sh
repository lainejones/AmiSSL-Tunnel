#!/usr/bin/env bash
# ===========================================================================
# AmiSSL emu - daemon (tls_proxy.py) installer for Linux / Raspberry Pi.
#
# Installs the LAN TLS-offload daemon as a systemd service so it starts on
# boot, then prints the IP + port to enter in the Amiga-side Installer.
#
#   sudo ./install-daemon.sh            # listen on 0.0.0.0:8443
#   sudo AMISSL_PORT=9000 ./install-daemon.sh
#
# Requirements: python3 (stdlib only - asyncio + ssl, no pip packages),
# systemd, root. For non-systemd hosts (macOS, Windows, WSL) just run the
# daemon directly:  python3 tls_proxy.py 0.0.0.0 8443
# ===========================================================================
set -euo pipefail

PREFIX=/opt/amissl-emu
SERVICE=amissl-emu
PORT="${AMISSL_PORT:-8443}"
LISTEN="${AMISSL_LISTEN:-0.0.0.0}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root:  sudo $0" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required. Install it (e.g. 'apt install python3') and re-run." >&2
    exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemd not found. On a non-systemd host, just run the daemon directly:" >&2
    echo "    python3 $(dirname "$0")/tls_proxy.py ${LISTEN} ${PORT}" >&2
    exit 1
fi

SRC="$(cd "$(dirname "$0")" && pwd)/tls_proxy.py"
if [ ! -f "$SRC" ]; then
    echo "tls_proxy.py not found next to this installer (expected $SRC)." >&2
    exit 1
fi

echo "Installing tls_proxy.py to ${PREFIX} ..."
install -d "$PREFIX"
install -m 0755 "$SRC" "$PREFIX/tls_proxy.py"

echo "Writing systemd unit /etc/systemd/system/${SERVICE}.service ..."
cat >"/etc/systemd/system/${SERVICE}.service" <<EOF
[Unit]
Description=AmiSSL emu LAN TLS offload daemon
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/env python3 -u ${PREFIX}/tls_proxy.py ${LISTEN} ${PORT}
Restart=on-failure
RestartSec=2
# Run sandboxed; the daemon only needs outbound TCP + the system CA bundle.
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF

echo "Enabling and starting the service ..."
systemctl daemon-reload
systemctl enable --now "${SERVICE}.service"

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

cat <<EOF

-------------------------------------------------------------------
AmiSSL emu daemon installed and running.

  service : ${SERVICE}
  listen  : ${LISTEN}:${PORT}
  status  : systemctl status ${SERVICE}
  logs    : journalctl -u ${SERVICE} -f

On the Amiga, run the AmiSSL emu Installer and enter:
  daemon address : ${IP:-<this-box-LAN-IP>}
  daemon port    : ${PORT}
-------------------------------------------------------------------
EOF
