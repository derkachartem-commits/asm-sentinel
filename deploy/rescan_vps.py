import http.cookiejar
import json
import re
import sqlite3
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8000"
DB = "/opt/asm-sentinel/data/asm.db"

# 1) чиним адрес цели: URL -> hostname
con = sqlite3.connect(DB)
row = con.execute("SELECT id, address FROM targets ORDER BY id DESC LIMIT 1").fetchone()
if row:
    tid, addr = row
    fixed = addr
    if "://" in addr:
        fixed = urllib.parse.urlsplit(addr).hostname or addr
    elif re.match(r"^[A-Za-z0-9_.\-]+:\d+$", addr):
        fixed = addr.rsplit(":", 1)[0]
    if fixed != addr:
        con.execute("UPDATE targets SET address=? WHERE id=?", (fixed, tid))
        con.commit()
        print(f"target {tid}: {addr} -> {fixed}")
    print("target:", tid, "address:", fixed)

con.close()

# 2) логин и запуск скана
pw = ""
for line in open("/root/asm-sentinel-credential.txt", encoding="utf-8"):
    if line.startswith("password:"):
        pw = line.split(":", 1)[1].strip()

cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
op.open(urllib.request.Request(BASE + "/login", data=urllib.parse.urlencode({"password": pw}).encode()))

r = op.open(urllib.request.Request(BASE + f"/api/targets/{tid}/scan", data=b""))
print("scan:", r.read().decode())
