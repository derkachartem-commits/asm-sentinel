#!/bin/bash
set -e
echo "== before =="
df -h / | tail -1

echo "== journal =="
journalctl --vacuum-size=100M 2>&1 | tail -2

echo "== btmp =="
gzip -9 -f /var/log/btmp.1 2>/dev/null || true
truncate -s 0 /var/log/btmp

echo "== rotated logs =="
for f in /var/log/auth.log.1 /var/log/kern.log.1 /var/log/ufw.log.1 /var/log/syslog.1; do
  if [ -f "$f" ]; then gzip -9 -f "$f"; fi
done

echo "== apt cache =="
rm -f /var/cache/apt/pkgcache.bin /var/cache/apt/srcpkgcache.bin

echo "== home cache =="
rm -rf /root/.cache/*

echo "== nuclei installers =="
rm -f /nuclei/nuclei_3.11.0_linux_amd64.zip /nuclei/nuclei_3.11.0_linux_amd64.zip.1

echo "== after =="
df -h / | tail -1
