import sqlite3

con = sqlite3.connect("/opt/asm-sentinel/data/asm.db")
con.row_factory = sqlite3.Row
print("== scan 8 ports ==")
for r in con.execute("SELECT host,port,proto,service,product,version,is_web,url,http_title FROM scan_ports WHERE scan_id=8"):
    print(dict(r))
print("== scan 8 findings ==")
for r in con.execute("SELECT id,name,severity,source FROM findings WHERE last_scan_id=8"):
    print(dict(r))
print("total findings:", con.execute("SELECT COUNT(*) FROM findings").fetchone()[0])
print("total ports rows:", con.execute("SELECT COUNT(*) FROM scan_ports").fetchone()[0])
