import http.cookiejar
import re
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8000"
pw = ""
for line in open("/root/asm-sentinel-credential.txt", encoding="utf-8"):
    if line.startswith("password:"):
        pw = line.split(":", 1)[1].strip()

cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
op.open(urllib.request.Request(BASE + "/login", data=urllib.parse.urlencode({"password": pw}).encode()))

page = op.open(BASE + "/targets").read().decode()
ids = re.findall(r'href="/targets/(\d+)"', page)
for tid in sorted(set(ids)):
    html = op.open(BASE + f"/targets/{tid}/edit").read().decode()
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    if not m:
        print("no csrf for", tid)
        continue
    r = op.open(urllib.request.Request(BASE + f"/targets/{tid}/delete",
                                       data=urllib.parse.urlencode({"csrf": m.group(1)}).encode()))
    print("deleted target", tid, r.status, r.geturl())
