import glob
import os
import sqlite3

DB = "/opt/asm-sentinel/data/asm.db"
con = sqlite3.connect(DB)
con.row_factory = sqlite3.Row

print("== targets ==")
for row in con.execute("SELECT * FROM targets"):
    print(dict(row))
print("== scans ==")
for row in con.execute("SELECT id,target_id,status,stage,progress,started_at,finished_at,error,stats FROM scans ORDER BY id DESC LIMIT 10"):
    print(dict(row))
print("== findings ==", con.execute("SELECT COUNT(*) FROM findings").fetchone()[0])
print("== ports ==", con.execute("SELECT COUNT(*) FROM scan_ports").fetchone()[0])
print("== events ==", con.execute("SELECT COUNT(*) FROM finding_events").fetchone()[0])

print("== logs ==")
for path in sorted(glob.glob("/opt/asm-sentinel/data/logs/*.log"))[-3:]:
    print("----", path, os.path.getsize(path))
    print(open(path, encoding="utf-8", errors="replace").read()[-3000:])

print("== templates ==")
for path in ("/root/nuclei-templates", "/root/.local/nuclei-templates"):
    print(path, os.path.isdir(path))
print("== disk ==")
os.system("df -h / | tail -1")
