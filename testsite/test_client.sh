#!/bin/bash
# Клиентский тест ASM Sentinel: логин, создание цели, запуск скана.
set -u
BASE="${BASE:-http://127.0.0.1:8000}"
PASS="${PASS:-TestPass123}"
CJ=/tmp/asm_cookies.txt
rm -f "$CJ"

code=$(curl -s -c "$CJ" -b "$CJ" -o /dev/null -w '%{http_code}' -d "password=$PASS" "$BASE/login")
echo "login: $code"

csrf=$(curl -s -b "$CJ" "$BASE/targets/new" | grep -o 'name="csrf" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"$//')
if [ -z "$csrf" ]; then echo "csrf: FAIL"; exit 1; fi
echo "csrf: ok"

resp=$(curl -s -b "$CJ" -c "$CJ" -o /dev/null -w '%{http_code} %{redirect_url}' \
  --data-urlencode "csrf=$csrf" \
  --data-urlencode "name=Test Portal" \
  --data-urlencode "address=127.0.0.1" \
  --data-urlencode "interval_hours=24" \
  --data-urlencode "scan_ports=1-9000" \
  --data-urlencode "zap_mode=baseline" \
  --data-urlencode "nuclei_severity=info,low,medium,high,critical" \
  --data-urlencode "enabled=1" \
  "$BASE/targets/new")
echo "create: $resp"

curl -s -b "$CJ" "$BASE/api/scans/active"
echo
