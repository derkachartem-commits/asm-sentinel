#!/usr/bin/env bash
# ASM Sentinel — offline installer.
# Installs Python dependencies from vendor/wheels. No network access required.
#
# Usage:
#   sudo ./install-offline.sh                 # /opt/asm-sentinel, user asm, port 8000
#   sudo ./install-offline.sh --root          # run as root (nmap SYN scan)
#   sudo ./install-offline.sh --no-zap        # don't look for ZAP
#   sudo ./install-offline.sh --no-nuclei     # don't require nuclei
#
# System tools (python3 + venv, nmap, nuclei, Java/ZAP) must already be present.

set -Eeuo pipefail

APP_NAME="ASM Sentinel"
SERVICE_NAME="asm-sentinel"
INSTALL_DIR="${ASM_INSTALL_DIR:-/opt/asm-sentinel}"
ENV_DIR="${ASM_ENV_DIR:-/etc/asm-sentinel}"
ENV_FILE="$ENV_DIR/$SERVICE_NAME.env"
RUN_USER="${ASM_RUN_USER:-asm}"
PORT="${ASM_PORT:-8000}"
BIND="${ASM_HOST:-127.0.0.1}"
ADMIN_PASSWORD="${ASM_ADMIN_PASSWORD:-}"
RUN_AS_ROOT=0
WITH_ZAP=1
WITH_NUCLEI=1
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

step() { printf '\n==> %s\n' "$*"; }
ok() { printf '  ok  %s\n' "$*"; }
warn() { printf '  !!  %s\n' "$*"; }
die() { printf ' error: %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --port) PORT="${2:?missing value}"; shift 2 ;;
        --bind) BIND="${2:?missing value}"; shift 2 ;;
        --dir) INSTALL_DIR="${2:?missing value}"; shift 2 ;;
        --password) ADMIN_PASSWORD="${2:?missing value}"; shift 2 ;;
        --root) RUN_AS_ROOT=1; shift ;;
        --no-zap) WITH_ZAP=0; shift ;;
        --no-nuclei) WITH_NUCLEI=0; shift ;;
        -h|--help) usage ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run as root: sudo $0"
[ -d "$SRC_DIR/vendor/wheels" ] || die "vendor/wheels not found — use the offline repository bundle"

step "Checking offline dependencies"
for bin in python3 nmap tar; do
    command -v "$bin" >/dev/null || die "$bin is missing (install it from your offline media)"
done
python3 -c "import venv" >/dev/null 2>&1 || die "python3-venv is missing"
ok "python $(python3 -V | awk '{print $2}'), nmap present"

if [ "$WITH_NUCLEI" -eq 1 ]; then
    command -v nuclei >/dev/null || warn "nuclei not found — scans will work without nuclei until installed"
    [ -d "$INSTALL_DIR/data/nuclei-templates" ] || warn "nuclei templates not found: $INSTALL_DIR/data/nuclei-templates"
fi
ZAP_HOME=""
if [ "$WITH_ZAP" -eq 1 ]; then
    for candidate in /opt/ZAP_2.17.0 /usr/share/zaproxy; do
        [ -x "$candidate/zap.sh" ] && ZAP_HOME="$candidate" && break
    done
    [ -n "$ZAP_HOME" ] || warn "ZAP not found — set ASM_ZAP_HOME later or use --no-zap"
fi

step "Preparing service account"
if [ "$RUN_AS_ROOT" -eq 1 ]; then
    RUN_USER="root"
    warn "service will run as root (nmap SYN scan enabled)"
elif ! id "$RUN_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin "$RUN_USER"
    ok "created system user: $RUN_USER"
else
    ok "system user exists: $RUN_USER"
fi

step "Installing application to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
if [ "$SRC_DIR" != "$INSTALL_DIR" ]; then
    tar -C "$SRC_DIR" \
        --exclude=.git --exclude=.venv --exclude=data --exclude=__pycache__ \
        --exclude='*.pyc' --exclude=docs/screenshots \
        -cf - . | tar -C "$INSTALL_DIR" -xf -
    ok "source copied"
fi
mkdir -p "$INSTALL_DIR/data"
chown -R "$RUN_USER":"$RUN_USER" "$INSTALL_DIR/data"

step "Creating Python virtualenv (offline)"
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install -q --no-index --find-links "$INSTALL_DIR/vendor/wheels" -r "$INSTALL_DIR/requirements.txt"
ok "python dependencies installed from vendor/wheels"

step "Writing configuration"
PREV_PASSWORD=""
PREV_SECRET=""
if [ -f "$ENV_FILE" ]; then
    PREV_PASSWORD="$(sed -n 's/^ASM_ADMIN_PASSWORD=//p' "$ENV_FILE" | head -1)"
    PREV_SECRET="$(sed -n 's/^ASM_SECRET=//p' "$ENV_FILE" | head -1)"
fi
if [ -n "$PREV_PASSWORD" ]; then
    ADMIN_PASSWORD="$PREV_PASSWORD"
elif [ -z "$ADMIN_PASSWORD" ]; then
    ADMIN_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(10))')"
fi
SECRET="${PREV_SECRET:-$(python3 -c 'import secrets; print(secrets.token_hex(32))')}"

mkdir -p "$ENV_DIR"
umask 077
cat > "$ENV_FILE" <<EOF
ASM_ADMIN_PASSWORD=$ADMIN_PASSWORD
ASM_SECRET=$SECRET
ASM_DATA_DIR=$INSTALL_DIR/data
ASM_HOST=$BIND
ASM_PORT=$PORT
ASM_ZAP_HOME=$ZAP_HOME
ASM_ZAP_MAX_URLS=5
ASM_COOKIE_SECURE=0
EOF
chmod 600 "$ENV_FILE"
chown -R "$RUN_USER":"$RUN_USER" "$INSTALL_DIR"
chmod 750 "$INSTALL_DIR"
chmod 700 "$INSTALL_DIR/data"
ok "configuration: $ENV_FILE"

step "Installing systemd service"
cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=$APP_NAME - self-hosted attack surface management
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
Group=$RUN_USER
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$ENV_FILE
Environment=HOME=$INSTALL_DIR/data
ExecStart=$INSTALL_DIR/.venv/bin/python run.py
Restart=always
RestartSec=5
TimeoutStopSec=30
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=$INSTALL_DIR/data

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null
systemctl restart "$SERVICE_NAME"

step "Waiting for the service"
for i in $(seq 1 30); do
    if command -v curl >/dev/null 2>&1; then
        curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && { ok "service is up"; break; }
    else
        python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$PORT/healthz', timeout=2)" >/dev/null 2>&1 && { ok "service is up"; break; }
    fi
    [ "$i" -eq 30 ] && die "service did not start: journalctl -u $SERVICE_NAME -n 50"
    sleep 1
done

cat <<EOF

ASM Sentinel installed offline
  Interface : http://${BIND}:$PORT
  Login     : admin
  Password  : $ADMIN_PASSWORD
  Config    : $ENV_FILE
  Data      : $INSTALL_DIR/data
  Service   : systemctl status $SERVICE_NAME
EOF
