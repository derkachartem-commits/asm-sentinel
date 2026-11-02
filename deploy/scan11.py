import sqlite3

con = sqlite3.connect("/opt/asm-sentinel/data/asm.db")
con.row_factory = sqlite3.Row
print("== scan 11 ==")
for r in con.execute("SELECT id,status,stage,progress,started_at,finished_at,stats FROM scans WHERE id=11"):
    print(dict(r))
print("== findings ==")
for r in con.execute("SELECT id,name,severity,source,url,status FROM findings WHERE last_scan_id=11 ORDER BY id"):
    print(dict(r))
print("total findings:", con.execute("SELECT COUNT(*) FROM findings").fetchone()[0])
print("ports:", con.execute("SELECT COUNT(*) FROM scan_ports").fetchone()[0])
