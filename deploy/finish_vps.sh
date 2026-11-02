#!/bin/bash
set -e
APP_DIR=/opt/asm-sentinel

echo "== deps =="
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"
"$APP_DIR/.venv/bin/python" -c "import fastapi, uvicorn, jinja2, itsdangerous, multipart; print('deps ok', fastapi.__version__)"

echo "== nuclei =="
if ! command -v nuclei >/dev/null 2>&1; then
  python3 - <<'PY'
import zipfile
zipfile.ZipFile('/nuclei/nuclei_3.11.0_linux_amd64.zip').extract('nuclei', '/usr/local/bin')
PY
  chmod +x /usr/local/bin/nuclei
fi
nuclei -version 2>&1 | head -2

echo "== templates =="
nuclei -update-templates -duc 2>&1 | tail -3 || true
find /root/nuclei-templates -name '*.yaml' 2>/dev/null | wc -l

echo "== env =="
if [ ! -f /etc/asm-sentinel.env ]; then
  PW=$(openssl rand -hex 10)
  SECRET=$(openssl rand -hex 32)
  cat > /etc/asm-sentinel.env <<EOF
ASM_ADMIN_PASSWORD=$PW
ASM_SECRET=$SECRET
ASM_DATA_DIR=$APP_DIR/data
ASM_PORT=8000
ASM_ZAP_HOME=/opt/ZAP_2.17.0
ASM_ZAP_HEAP=384
ASM_ZAP_MAX_URLS=3
ASM_COOKIE_SECURE=0
EOF
  chmod 600 /etc/asm-sentinel.env
  printf 'ASM Sentinel\nURL: https://109.61.111.177:8443\nlogin: admin\npassword: %s\n' "$PW" > /root/asm-sentinel-credential.txt
  chmod 600 /root/asm-sentinel-credential.txt
fi

echo "== service =="
cp "$APP_DIR/deploy/asm-sentinel.service" /etc/systemd/system/asm-sentinel.service
systemctl daemon-reload
systemctl enable asm-sentinel >/dev/null 2>&1
systemctl restart asm-sentinel
sleep 5
systemctl --no-pager status asm-sentinel | head -10
curl -s -o /dev/null -w "local_login=%{http_code}\n" http://127.0.0.1:8000/login
curl -s http://127.0.0.1:8000/healthz; echo

echo "== disk =="
df -h / | tail -1
