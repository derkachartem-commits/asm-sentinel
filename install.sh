#!/usr/bin/env bash
# ASM Sentinel installer for Debian / Ubuntu / Kali Linux
#
# Usage:
#   sudo ./install.sh                     # install to /opt/asm-sentinel, port 8000
#   sudo ./install.sh --port 8080         # custom port
#   sudo ./install.sh --root              # run service as root (enables nmap SYN scan)
#   sudo ./install.sh --no-zap            # skip ZAP download (web passive/active checks off)
#   sudo ./install.sh --password 'S3cret' # preset admin password
#   sudo ./install.sh --skip-deps         # do not run apt-get (deps preinstalled)
#
# The installer is idempotent: re-running it keeps the existing database,
# secret key and admin password, and only updates code / dependencies.

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
WITH_ZAP=1
WITH_NUCLEI=1
WITH_DEPS=1
RUN_AS_ROOT=0
NUCLEI_VERSION="${NUCLEI_VERSION:-3.11.0}"
ZAP_VERSION="${ZAP_VERSION:-2.17.0}"

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ------------------------------------------------------------------ helpers

c_reset=$'\033[0m'; c_bold=$'\033[1m'; c_green=$'\033[32m'; c_yellow=$'\033[33m'; c_red=$'\033[31m'; c_blue=$'\033[36m'

step() { printf '\n%s==>%s %s%s\n' "$c_blue" "$c_reset" "$c_bold" "$*$c_reset"; }
ok()   { printf '%s  ok%s %s\n' "$c_green" "$c_reset" "$*"; }
warn() { printf '%s  !!%s %s\n' "$c_yellow" "$c_reset" "$*"; }
die()  { printf '%s error:%s %s\n' "$c_red" "$c_reset" "$*" >&2; exit 1; }

usage() {
    sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

need_root() {
    [ "$(id -u)" -eq 0 ] || die "run as root: sudo $0 $*"
}

arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l) echo "armv7" ;;
        *) die "unsupported architecture: $(uname -m)" ;;
    esac
}

# ------------------------------------------------------------------ args

while [ $# -gt 0 ]; do
    case "$1" in
        --port)       PORT="${2:?missing value}"; shift 2 ;;
        --bind)       BIND="${2:?missing value}"; shift 2 ;;
        --dir)        INSTALL_DIR="${2:?missing value}"; shift 2 ;;
        --password)   ADMIN_PASSWORD="${2:?missing value}"; shift 2 ;;
        --root)       RUN_AS_ROOT=1; shift ;;
        --no-zap)     WITH_ZAP=0; shift ;;
        --no-nuclei)  WITH_NUCLEI=0; shift ;;
        --skip-deps)  WITH_DEPS=0; shift ;;
        -h|--help)    usage ;;
        *)            die "unknown option: $1 (try --help)" ;;
    esac
done

need_root "$@"

# ------------------------------------------------------------------ checks

step "Checking system"
[ -r /etc/os-release ] || die "unsupported OS (no /etc/os-release)"
. /etc/os-release
case "${ID:-} ${ID_LIKE:-}" in
    *debian*|*ubuntu*) : ;;
    *) die "this installer supports Debian/Ubuntu/Kali; detected: ${PRETTY_NAME:-unknown}" ;;
esac
command -v apt-get >/dev/null || die "apt-get not found"
ok "${PRETTY_NAME:-$ID} · $(uname -m)"

export DEBIAN_FRONTEND=noninteractive

step "Installing system packages"
if [ "$WITH_DEPS" -eq 1 ]; then
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
        python3 python3-venv python3-pip \
        nmap curl unzip ca-certificates openssl tar >/dev/null
    ok "python $(python3 -V | awk '{print $2}'), nmap $(nmap --version | head -1 | awk '{print $3}')"
else
    for bin in python3 nmap curl openssl tar; do
        command -v "$bin" >/dev/null || die "$bin is missing and --skip-deps was given"
    done
    ok "system dependencies present"
fi

# ------------------------------------------------------------------ user

step "Preparing service account"
if [ "$RUN_AS_ROOT" -eq 1 ]; then
    RUN_USER="root"
    warn "service will run as root (nmap SYN scan + raw sockets enabled)"
elif ! id "$RUN_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin "$RUN_USER"
    ok "created system user: $RUN_USER"
else
    ok "system user exists: $RUN_USER"
fi

# ------------------------------------------------------------------ code

step "Installing application to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
if [ "$SRC_DIR" != "$INSTALL_DIR" ]; then
    tar -C "$SRC_DIR" \
        --exclude=.git --exclude=.venv --exclude=data --exclude=__pycache__ \
        --exclude='*.pyc' --exclude=docs/screenshots \
        -cf - . | tar -C "$INSTALL_DIR" -xf -
    ok "source copied"
else
    ok "running from install directory, source kept in place"
fi
mkdir -p "$INSTALL_DIR/data"
chown -R "$RUN_USER":"$RUN_USER" "$INSTALL_DIR/data"

step "Creating Python virtualenv"
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install -q --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt"
ok "python dependencies installed"

# ------------------------------------------------------------------ nuclei

if [ "$WITH_NUCLEI" -eq 1 ]; then
    step "Installing nuclei"
    if command -v nuclei >/dev/null 2>&1; then
        ok "nuclei already installed: $(nuclei -version 2>&1 | head -1)"
    else
        tmp="$(mktemp -d)"
        url="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_$(arch).zip"
        curl -fsSL "$url" -o "$tmp/nuclei.zip" || die "failed to download nuclei: $url"
        unzip -q -o "$tmp/nuclei.zip" -d "$tmp" nuclei
        install -m 0755 "$tmp/nuclei" /usr/local/bin/nuclei
        rm -rf "$tmp"
        ok "nuclei $(nuclei -version 2>&1 | head -1 | awk '{print $2}')"
    fi

    step "Updating nuclei templates"
    if [ "$RUN_USER" = "root" ]; then
        UPDATE_CMD=(nuclei -update-templates -duc)
    else
        UPDATE_CMD=(runuser -u "$RUN_USER" -- env HOME="$INSTALL_DIR/data" nuclei -update-templates -duc)
    fi
    if "${UPDATE_CMD[@]}" >/dev/null 2>&1; then
        ok "templates updated in $INSTALL_DIR/data/nuclei-templates"
    else
        warn "automatic template update failed, downloading archive"
        tmp="$(mktemp -d)"
        curl -fsSL https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.tar.gz \
            -o "$tmp/templates.tgz" || die "failed to download nuclei templates"
        tar -xzf "$tmp/templates.tgz" -C "$tmp"
        tdir="$(find "$tmp" -maxdepth 1 -type d -name 'nuclei-templates-*' | head -1)"
        mkdir -p "$INSTALL_DIR/data/nuclei-templates"
        cp -a "$tdir/." "$INSTALL_DIR/data/nuclei-templates/"
        rm -rf "$tmp"
        ok "templates installed to $INSTALL_DIR/data/nuclei-templates"
    fi
fi

# ------------------------------------------------------------------ zap

if [ "$WITH_ZAP" -eq 1 ]; then
    step "Installing OWASP ZAP"
    ZAP_HOME="/opt/ZAP_$ZAP_VERSION"
    if [ -x "$ZAP_HOME/zap.sh" ]; then
        ok "ZAP already installed: $ZAP_HOME"
    elif [ -x /usr/share/zaproxy/zap.sh ]; then
        ZAP_HOME=/usr/share/zaproxy
        ok "using system ZAP: $ZAP_HOME"
    else
        apt-get install -y -qq --no-install-recommends default-jre-headless >/dev/null
        tmp="$(mktemp -d)"
        url="https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz"
        curl -fsSL "$url" -o "$tmp/zap.tgz" || die "failed to download ZAP: $url"
        tar -xzf "$tmp/zap.tgz" -C /opt
        rm -rf "$tmp"
        [ -x "$ZAP_HOME/zap.sh" ] || die "ZAP archive layout unexpected, expected $ZAP_HOME/zap.sh"
        ok "ZAP installed: $ZAP_HOME"
    fi
else
    ZAP_HOME=""
    warn "ZAP skipped (--no-zap), web application scanning disabled"
fi

# ------------------------------------------------------------------ config

step "Writing configuration"
PREV_PASSWORD=""
PREV_SECRET=""
if [ -f "$ENV_FILE" ]; then
    PREV_PASSWORD="$(sed -n 's/^ASM_ADMIN_PASSWORD=//p' "$ENV_FILE" | head -1)"
    PREV_SECRET="$(sed -n 's/^ASM_SECRET=//p' "$ENV_FILE" | head -1)"
fi

if [ -n "$PREV_PASSWORD" ]; then
    ADMIN_PASSWORD="$PREV_PASSWORD"
    ok "keeping existing admin password from $ENV_FILE"
elif [ -n "$ADMIN_PASSWORD" ]; then
    ok "using admin password from --password"
else
    ADMIN_PASSWORD="$(openssl rand -hex 10)"
    ok "generated admin password"
fi
SECRET="${PREV_SECRET:-$(umask 077; openssl rand -hex 32)}"

mkdir -p "$ENV_DIR"
umask 077
cat > "$ENV_FILE" <<EOF
# ASM Sentinel configuration
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
ok "configuration written to $ENV_FILE"
EXISTING_PASSWORD="$ADMIN_PASSWORD"

chown -R "$RUN_USER":"$RUN_USER" "$INSTALL_DIR"
chmod 750 "$INSTALL_DIR"
chmod 700 "$INSTALL_DIR/data"
chmod 600 "$ENV_FILE"

# ------------------------------------------------------------------ systemd

step "Installing systemd service"
cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=$APP_NAME - self-hosted attack surface management
Documentation=https://github.com/derkachartem-commits/asm-sentinel
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

# Sandboxing (keeps raw-socket capability for nmap when running as root)
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
    if curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
        ok "service is up"
        break
    fi
    [ "$i" -eq 30 ] && die "service did not start, check: journalctl -u $SERVICE_NAME -n 50"
    sleep 1
done

# ------------------------------------------------------------------ summary

HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<EOF

${c_green}${c_bold}ASM Sentinel installed${c_reset}

  Interface : http://${HOST_IP:-127.0.0.1}:$PORT
  Login     : admin
  Password  : ${EXISTING_PASSWORD}
  Secrets   : $ENV_FILE (mode 600)
  Data      : $INSTALL_DIR/data
  Service   : systemctl status $SERVICE_NAME
  Logs      : journalctl -u $SERVICE_NAME -f

Next steps:
  1. Open the interface and add your first target.
  2. Put a TLS reverse proxy in front (see docs/nginx.md) before exposing it.
  3. Read the security notes in README.md - scanning must stay within your own assets.
EOF
