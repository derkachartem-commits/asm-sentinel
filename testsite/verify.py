import http.cookiejar
import re
import sys
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8000"
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

data = urllib.parse.urlencode({"password": "TestPass123"}).encode()
resp = opener.open(urllib.request.Request(BASE + "/login", data=data))
print("login final:", resp.status, resp.geturl())

html = opener.open(BASE + "/findings").read().decode("utf-8")
rows = re.findall(r'href="(/findings/(\d+))">([^<]+)</a>', html)
print("findings on page:", len(rows))
for href, fid, name in rows[:12]:
    print(f"  #{fid} {name.strip()[:70]}")

if rows:
    fid = rows[0][1]
    detail = opener.open(BASE + "/findings/" + fid).read().decode("utf-8")
    csrf = re.search(r'name="csrf" value="([^"]+)"', detail).group(1)
    body = urllib.parse.urlencode({"csrf": csrf, "status": "in_progress", "note": "проверено Альтером"}).encode()
    r = opener.open(urllib.request.Request(BASE + f"/findings/{fid}/status", data=body))
    print("status update:", r.status, r.geturl())
    detail = opener.open(BASE + "/findings/" + fid).read().decode("utf-8")
    print("has in_progress:", "В работе" in detail, "| has note:", "проверено Альтером" in detail)
    print("event rows:", detail.count("timeline"))

csv_data = opener.open(BASE + "/export/findings.csv").read().decode("utf-8-sig")
lines = csv_data.splitlines()
print("csv lines:", len(lines))
print("csv header:", lines[0][:120])

dash = opener.open(BASE + "/").read().decode("utf-8")
print("dashboard ok:", "Обзор" in dash, "| open findings block:", "Открытых уязвимостей" in dash)
