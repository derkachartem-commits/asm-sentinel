#!/usr/bin/env bash
# ASM Sentinel uninstaller.
#
# Removes the systemd service, virtualenv and code. The data directory
# (database, scan logs, reports) is kept unless --purge is given.

set -Eeuo pipefail

SERVICE_NAME="asm-sentinel"
INSTALL_DIR="${ASM_INSTALL_DIR:-/opt/asm-sentinel}"
ENV_FILE="${ASM_ENV_FILE:-/etc/asm-sentinel/$SERVICE_NAME.env}"
RUN_USER="${ASM_RUN_USER:-asm}"
PURGE=0

for arg in "$@"; do
    case "$arg" in
        --purge) PURGE=1 ;;
        -h|--help) sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 1 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0" >&2; exit 1; }

echo "==> stopping service"
systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
rm -f "/etc/systemd/system/$SERVICE_NAME.service"
systemctl daemon-reload

echo "==> removing application"
if [ "$PURGE" -eq 1 ]; then
    rm -rf "$INSTALL_DIR" "$ENV_FILE"
    rmdir "$(dirname "$ENV_FILE")" 2>/dev/null || true
    id "$RUN_USER" >/dev/null 2>&1 && userdel "$RUN_USER" 2>/dev/null || true
    echo "    code, data, configuration and service user removed"
else
    find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 ! -name data -exec rm -rf {} +
    echo "    code removed, data kept in $INSTALL_DIR/data"
    echo "    configuration kept in $ENV_FILE"
fi

echo "done."
