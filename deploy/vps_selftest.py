import http.cookiejar
import json
import re
import time
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8000"
pw = ""
for line in open("/root/asm-sentinel-credential.txt", encoding="utf-8"):
    if line.startswith("password:"):
        pw = line.split(":", 1)[1].strip()

cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

body = urllib.parse.urlencode({"password": pw}).encode()
r = op.open(urllib.request.Request(BASE + "/login", data=body))
print("login:", r.status, r.geturl())

html = op.open(BASE + "/targets/new").read().decode()
csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)

data = urllib.parse.urlencode({
    "csrf": csrf, "name": "VPS self-test", "address": "127.0.0.1",
    "interval_hours": "24", "scan_ports": "1-2000", "zap_mode": "off",
    "nuclei_severity": "critical", "enabled": "1",
}).encode()
r = op.open(urllib.request.Request(BASE + "/targets/new", data=data))
print("create:", r.status, r.geturl())
tid = re.search(r"/targets/(\d+)", r.geturl()).group(1)

for _ in range(120):
    active = json.loads(op.open(BASE + "/api/scans/active").read())
    if not active:
        break
    print("active:", active[0]["stage"], active[0]["progress"])
    time.sleep(5)

page = op.open(BASE + "/scans").read().decode()
rows = re.findall(r'href="/scans/(\d+)"', page)
sid = rows[0] if rows else "1"
detail = op.open(BASE + f"/scans/{sid}").read().decode()
print("scan page ok:", "Скан #" in detail)
stat = re.search(r"Открытых портов</div><div class=\"v sm\">(\d+)", detail)
print("open ports:", stat.group(1) if stat else "?")
print("has failed:", "Ошибка" in detail)

# cleanup test target
html = op.open(BASE + f"/targets/{tid}").read().decode()
csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
r = op.open(urllib.request.Request(BASE + f"/targets/{tid}/delete",
                                   data=urllib.parse.urlencode({"csrf": csrf}).encode()))
print("cleanup:", r.status, r.geturl())
