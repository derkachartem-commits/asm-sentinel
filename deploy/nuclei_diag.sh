#!/bin/bash
echo "== version =="
nuclei -version 2>&1 | head -3
echo "== config =="
cat /root/.config/nuclei/config.yaml 2>/dev/null | head -20
echo "== net =="
curl -sS -o /dev/null -w "github=%{http_code}\n" --max-time 15 https://github.com 2>&1
curl -sS -o /dev/null -w "api=%{http_code}\n" --max-time 15 https://api.github.com 2>&1
echo "== update =="
nuclei -update-templates -duc -v 2>&1 | tail -30
echo "exit=$?"
echo "== result =="
ls -la /root/nuclei-templates 2>/dev/null | head -5
find / -maxdepth 4 -type d -name 'nuclei-templates' 2>/dev/null
df -h / | tail -1
