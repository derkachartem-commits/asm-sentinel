import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import threading
import time
import traceback
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from . import db

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
WEB_PORTS = {
    80, 81, 443, 591, 3000, 3128, 4443, 5000, 5601, 7001, 8000, 8008, 8080,
    8081, 8088, 8090, 8181, 8443, 8880, 8888, 9000, 9090, 9200, 9443, 10000, 10443,
}
COMMON_PORTS = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521,
    1723, 2049, 2375, 3000, 3306, 3389, 5432, 5900, 6379, 7001, 8000, 8008, 8080, 8081,
    8443, 8888, 9000, 9090, 9200, 9443, 10000, 27017,
}
MAX_PORTS_PER_HOST = int(os.environ.get("ASM_MAX_PORTS_PER_HOST", "300"))
SERVICE_CHUNK = 200
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get("ASM_DATA_DIR", os.path.join(BASE_DIR, "data"))
LOG_DIR = os.path.join(DATA_DIR, "logs")
REPORT_DIR = os.path.join(DATA_DIR, "reports")


# ---------------------------------------------------------------- utils

def _ensure_dirs():
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(REPORT_DIR, exist_ok=True)


def _log(path, message):
    text = str(message)
    if len(text) > 4000:
        text = text[:4000] + f"... [{len(text)} chars]"
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {text}"
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def _run(cmd, log_path, timeout):
    _log(log_path, "$ " + " ".join(cmd))
    started = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        _log(log_path, f"!! timeout after {timeout}s")
        return None, None, None
    except Exception as exc:
        _log(log_path, f"!! failed to start: {exc}")
        return None, None, None
    if proc.stderr.strip():
        tail = "\n".join(proc.stderr.strip().splitlines()[-40:])
        _log(log_path, "stderr:\n" + tail)
    _log(log_path, f"exit={proc.returncode} duration={int(time.time() - started)}s")
    return proc.stdout, proc.stderr, proc.returncode


def _nmap_failed(stderr):
    markers = ("Failed to resolve", "Unable to split netmask", "No targets were specified", "Invalid target")
    return any(m in (stderr or "") for m in markers)


def _last_line(text):
    lines = [line for line in (text or "").strip().splitlines() if line.strip()]
    return lines[-1] if lines else ""


def _zap_home():
    env = os.environ.get("ASM_ZAP_HOME")
    candidates = [env] if env else []
    candidates += ["/usr/share/zaproxy", "/opt/ZAP_2.17.0", "/opt/zaproxy"]
    for path in candidates:
        if path and os.path.exists(os.path.join(path, "zap.sh")):
            return path
    return None


def _zap_api_key():
    """Ключ API: из env или из config.xml существующей установки ZAP."""
    env = os.environ.get("ASM_ZAP_KEY")
    if env:
        return env
    path = os.path.join(os.path.expanduser("~"), ".ZAP", "config.xml")
    try:
        root = ET.parse(path).getroot()
        el = root.find(".//api/key")
        if el is not None and (el.text or "").strip():
            return el.text.strip()
    except Exception:
        pass
    return ""


def _is_root():
    return getattr(os, "geteuid", lambda: 1)() == 0


def _url_for(host, port, scheme):
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    return f"{scheme}://{host}/" if default else f"{scheme}://{host}:{port}/"


def _fingerprint(parts):
    return hashlib.sha1("|".join(str(p) for p in parts).encode("utf-8", "replace")).hexdigest()


def _title(html):
    m = TITLE_RE.search(html or "")
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200]


# ---------------------------------------------------------------- nmap

def nmap_discovery(address, ports, log_path):
    cmd = ["nmap", "-Pn", "-n", "-sS" if _is_root() else "-sT", "-p", ports,
           "--min-rate", "1200", "--max-retries", "2", "-T4", "-oX", "-", address]
    out, err, rc = _run(cmd, log_path, timeout=3600)
    if not out:
        return []
    if _nmap_failed(err):
        raise RuntimeError("nmap: " + _last_line(err))
    return _parse_nmap(out, log_path)


def nmap_services(address, ports, log_path):
    if not ports:
        return []
    results = []
    ordered = sorted(ports)
    for i in range(0, len(ordered), SERVICE_CHUNK):
        chunk = ordered[i:i + SERVICE_CHUNK]
        port_arg = ",".join(str(p) for p in chunk)
        cmd = ["nmap", "-Pn", "-n", "-sV", "--version-light", "--version-intensity", "2",
               "--max-retries", "1", "--host-timeout", "180s", "-p", port_arg,
               "-T4", "-oX", "-", address]
        out, err, rc = _run(cmd, log_path, timeout=600)
        if not out:
            continue
        results.extend(_parse_nmap(out, log_path))
    return results


def _parse_nmap(xml_text, log_path):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        _log(log_path, f"!! nmap xml parse error: {exc}")
        return []
    results = []
    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        if addr_el is None:
            continue
        host = addr_el.get("addr")
        status = host_el.find("status")
        if status is not None and status.get("state") not in (None, "up"):
            continue
        for port_el in host_el.findall("./ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            svc = port_el.find("service")
            item = {
                "host": host,
                "port": int(port_el.get("portid")),
                "proto": port_el.get("protocol") or "tcp",
                "service": svc.get("name") if svc is not None else "",
                "product": svc.get("product") if svc is not None else "",
                "version": svc.get("version") if svc is not None else "",
                "extrainfo": svc.get("extrainfo") if svc is not None else "",
                "title": "",
            }
            for script in port_el.findall("script"):
                if script.get("id") == "http-title":
                    item["title"] = (script.get("output") or "").strip()[:200]
            results.append(item)
    return results


# ---------------------------------------------------------------- web probe

def probe_http(host, port, timeout=8):
    schemes = ("https", "http") if port in (443, 8443, 9443, 10443) else ("http", "https")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for scheme in schemes:
        url = _url_for(host, port, scheme)
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (compatible; ASM-Sentinel/1.0)",
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            })
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(131072).decode("utf-8", "replace")
                server = resp.headers.get("Server", "")
                return {
                    "url": resp.geturl() or url,
                    "status": getattr(resp, "status", 0),
                    "title": _title(body),
                    "server": server,
                }
        except Exception:
            continue
    return None


def _looks_web(port, service, product, title):
    blob = f"{service or ''} {product or ''}".lower()
    if any(k in blob for k in ("http", "www", "ssl")):
        return True
    if port in WEB_PORTS:
        return True
    return bool(title)


# ---------------------------------------------------------------- nuclei

def run_nuclei(urls, severity, log_path, timeout=2400):
    if not urls:
        return []
    _ensure_dirs()
    list_path = os.path.join(REPORT_DIR, f"nuclei-targets-{os.getpid()}-{int(time.time())}.txt")
    out_path = list_path.replace("-targets-", "-out-").replace(".txt", ".jsonl")
    with open(list_path, "w", encoding="utf-8") as f:
        f.write("\n".join(urls) + "\n")
    cmd = ["nuclei", "-l", list_path, "-jsonl", "-o", out_path,
           "-severity", severity or "critical,high,medium,low",
           "-rate-limit", "150", "-bulk-size", "25", "-concurrency", "25",
           "-timeout", "10", "-retries", "1", "-etags", "dos,fuzz,bruteforce,intrusive,payloads",
           "-ni", "-duc", "-silent", "-nc"]
    _run(cmd, log_path, timeout=timeout)
    findings = []
    if os.path.exists(out_path):
        with open(out_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                findings.append(_nuclei_to_finding(data))
    return findings


def _nuclei_to_finding(data):
    info = data.get("info") or {}
    classification = info.get("classification") or {}
    cve = classification.get("cve-id") or classification.get("cve_id") or ""
    if isinstance(cve, list):
        cve = ",".join(str(c) for c in cve)
    cvss = classification.get("cvss-score") or classification.get("cvss_score")
    try:
        cvss = float(cvss) if cvss is not None else None
    except (TypeError, ValueError):
        cvss = None
    matched = data.get("matched-at") or data.get("host") or ""
    parsed = urllib.parse.urlsplit(matched if "://" in matched else "http://" + matched)
    template_id = data.get("template-id") or info.get("template-id") or ""
    clean_url = ""
    if parsed.scheme and parsed.netloc:
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return {
        "source": "nuclei",
        "template_id": template_id,
        "name": info.get("name") or template_id or "nuclei finding",
        "severity": (info.get("severity") or "info").lower(),
        "host": data.get("host") or parsed.hostname or "",
        "port": parsed.port,
        "url": clean_url or matched,
        "matched_at": matched,
        "description": info.get("description") or "",
        "solution": info.get("remediation") or "",
        "reference": "\n".join(info.get("reference") or []) if isinstance(info.get("reference"), list) else (info.get("reference") or ""),
        "cve": cve if isinstance(cve, str) else "",
        "cvss": cvss,
        "raw": data,
    }


# ---------------------------------------------------------------- ZAP

def _free_port():
    import socket
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _zap_request(port, key, path, params=None, timeout=30):
    query = dict(params or {})
    query["apikey"] = key
    url = f"http://127.0.0.1:{port}{path}?{urllib.parse.urlencode(query)}"
    req = urllib.request.Request(url, headers={"X-ZAP-API-Key": key})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", "replace")
    return json.loads(body) if body else {}


def _zap_wait(port, key, path, field, target, timeout, log_path, interval=3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data = _zap_request(port, key, path, timeout=20)
            value = data.get(field)
            if value is not None and str(value) == str(target):
                return True
        except Exception:
            pass
        time.sleep(interval)
    _log(log_path, f"!! ZAP timeout waiting {path} -> {target}")
    return False


def run_zap_urls(urls, mode, scan_id, log_path):
    """Сканирует список URL через ZAP API (daemon), возвращает находки."""
    home = _zap_home()
    if not home:
        _log(log_path, "!! ZAP not found (set ASM_ZAP_HOME)")
        return []
    if not urls:
        return []
    import secrets as _secrets
    port = _free_port()
    key = _zap_api_key() or _secrets.token_hex(16)
    session_dir = os.path.join(DATA_DIR, "zap")
    os.makedirs(session_dir, exist_ok=True)
    session_path = os.path.join(session_dir, f"scan-{scan_id}-{port}")
    env = dict(os.environ)
    env.setdefault("JAVA_TOOL_OPTIONS", f"-Xmx{os.environ.get('ASM_ZAP_HEAP', '512')}m")
    cmd = [os.path.join(home, "zap.sh"), "-daemon", "-silent", "-host", "127.0.0.1",
           "-port", str(port), "-config", f"api.key={key}",
           "-config", "api.addrs.addr.name=.*", "-config", "api.addrs.addr.regex=true",
           "-newsession", session_path]
    _log(log_path, "$ " + " ".join(cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    findings = []
    try:
        ready = False
        deadline = time.time() + int(os.environ.get("ASM_ZAP_START_TIMEOUT", "480"))
        while time.time() < deadline:
            if proc.poll() is not None:
                _log(log_path, f"!! ZAP exited with code {proc.returncode}")
                return []
            try:
                _zap_request(port, key, "/JSON/core/view/version/", timeout=5)
                ready = True
                break
            except Exception:
                time.sleep(2)
        if not ready:
            _log(log_path, "!! ZAP did not start in time")
            return []
        _log(log_path, f"ZAP started on 127.0.0.1:{port}")

        for url in urls:
            _log(log_path, f"ZAP spider: {url}")
            try:
                _zap_request(port, key, "/JSON/spider/action/scan/", {"url": url, "recurse": "true"})
                _zap_wait(port, key, "/JSON/spider/view/status/", "status", "100",
                          int(os.environ.get("ASM_ZAP_SPIDER_TIMEOUT", "600")), log_path)
                _zap_wait(port, key, "/JSON/pscan/view/recordsToScan/", "recordsToScan", "0", 240, log_path)
                if mode == "full":
                    _log(log_path, f"ZAP active scan: {url}")
                    _zap_request(port, key, "/JSON/ascan/action/scan/", {"url": url, "recurse": "true"})
                    _zap_wait(port, key, "/JSON/ascan/view/status/", "status", "100",
                              int(os.environ.get("ASM_ZAP_ACTIVE_TIMEOUT", "1800")), log_path)
            except Exception as exc:
                _log(log_path, f"!! ZAP scan error for {url}: {exc}")
            try:
                data = _zap_request(port, key, "/JSON/core/view/alerts/",
                                    {"baseurl": url, "start": "0", "count": "10000"}, timeout=60)
                alerts = data.get("alerts") or []
                _log(log_path, f"ZAP alerts for {url}: {len(alerts)}")
                findings.extend(_zap_alerts_to_findings(alerts, url))
            except Exception as exc:
                _log(log_path, f"!! ZAP alerts error: {exc}")
    finally:
        try:
            _zap_request(port, key, "/JSON/core/action/shutdown/", timeout=10)
        except Exception:
            pass
        try:
            proc.wait(timeout=20)
        except Exception:
            proc.kill()
    return findings


def _zap_alerts_to_findings(alerts, target_url):
    risk_map = {"high": "high", "medium": "medium", "low": "low", "informational": "info", "information": "info"}
    site = f"{urllib.parse.urlsplit(target_url).scheme}://{urllib.parse.urlsplit(target_url).netloc}"
    grouped = {}
    for alert in alerts:
        severity = risk_map.get(str(alert.get("risk", "")).lower(), "info")
        plugin = str(alert.get("pluginId") or alert.get("id") or "")
        key = (plugin, severity)
        if key not in grouped:
            grouped[key] = {
                "source": "zap",
                "template_id": plugin,
                "name": alert.get("alert") or "ZAP alert",
                "severity": severity,
                "host": urllib.parse.urlsplit(site).hostname or "",
                "port": urllib.parse.urlsplit(site).port,
                "url": site,
                "matched_at": alert.get("url") or target_url,
                "description": alert.get("description") or "",
                "solution": alert.get("solution") or "",
                "reference": alert.get("reference") or "",
                "cve": "",
                "cvss": None,
                "raw": {"pluginId": plugin, "alert": alert.get("alert"), "instances": []},
            }
        instance = {
            "url": alert.get("url"), "param": alert.get("param"), "evidence": alert.get("evidence"),
            "confidence": alert.get("confidence"), "attack": alert.get("attack"),
        }
        if instance not in grouped[key]["raw"]["instances"]:
            grouped[key]["raw"]["instances"].append(instance)
    result = list(grouped.values())
    for item in result:
        item["raw"]["instanceCount"] = len(item["raw"]["instances"])
    return result


# ---------------------------------------------------------------- persistence

def upsert_finding(target_id, scan_id, item):
    src = item["source"]
    key_host = item.get("host") or ""
    key_url = item.get("url") or ""
    fp = _fingerprint([src, target_id, item.get("template_id"), key_host, item.get("port"), key_url or item.get("matched_at")])
    now = db.now()
    raw = json.dumps(item.get("raw"), ensure_ascii=False)[:200000]
    with db.connect() as con:
        row = con.execute("SELECT id, status FROM findings WHERE fingerprint=?", (fp,)).fetchone()
        if row:
            old_status = row["status"]
            new_status = old_status
            if old_status == "fixed":
                new_status = "new"
                con.execute(
                    "INSERT INTO finding_events (finding_id, ts, actor, type, old_status, new_status, note) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (row["id"], now, "scanner", "reopened", old_status, new_status, "Уязвимость обнаружена повторно"),
                )
            con.execute(
                "UPDATE findings SET last_seen=?, occurrences=occurrences+1, last_scan_id=?, name=?, severity=?, "
                "description=?, solution=?, reference=?, cve=?, cvss=?, raw=?, status=?, url=?, matched_at=? WHERE id=?",
                (now, scan_id, item["name"], item["severity"], item.get("description") or "",
                 item.get("solution") or "", item.get("reference") or "", item.get("cve") or "",
                 item.get("cvss"), raw, new_status, item.get("url") or "", item.get("matched_at") or "", row["id"]),
            )
            finding_id = row["id"]
        else:
            cur = con.execute(
                "INSERT INTO findings (target_id, fingerprint, source, template_id, name, severity, host, port, url, "
                "matched_at, description, solution, reference, cve, cvss, status, first_seen, last_seen, "
                "occurrences, last_scan_id, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'new',?,?,1,?,?)",
                (target_id, fp, src, item.get("template_id") or "", item["name"], item["severity"],
                 key_host, item.get("port"), item.get("url") or "", item.get("matched_at") or "",
                 item.get("description") or "", item.get("solution") or "", item.get("reference") or "",
                 item.get("cve") or "", item.get("cvss"), now, now, scan_id, raw),
            )
            finding_id = cur.lastrowid
            con.execute(
                "INSERT INTO finding_events (finding_id, ts, actor, type, old_status, new_status, note) "
                "VALUES (?,?,?,?,?,?,?)",
                (finding_id, now, "scanner", "created", None, "new", "Обнаружено впервые"),
            )
        con.execute("INSERT OR IGNORE INTO scan_findings (scan_id, finding_id) VALUES (?,?)", (scan_id, finding_id))
    return finding_id


# ---------------------------------------------------------------- pipeline

def _set_scan(scan_id, **fields):
    if not fields:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    db.execute(f"UPDATE scans SET {cols} WHERE id=?", (*fields.values(), scan_id))


def run_pipeline(scan_id):
    _ensure_dirs()
    log_path = os.path.join(LOG_DIR, f"scan-{scan_id}.log")
    scan = db.query_one(
        "SELECT s.id AS scan_id, s.target_id, t.name AS target_name, t.address, t.scan_ports, "
        "t.zap_mode, t.nuclei_severity FROM scans s JOIN targets t ON t.id = s.target_id WHERE s.id=?",
        (scan_id,),
    )
    if not scan:
        return
    target_id = scan["target_id"]
    _set_scan(scan_id, status="running", stage="Сканирование портов (nmap)", progress=5, started_at=db.now())
    _log(log_path, f"=== scan #{scan_id} target={scan['target_name']} ({scan['address']}) ===")
    stats = {"open_ports": 0, "web_urls": 0, "nuclei": 0, "zap": 0, "findings": 0, "hosts": 0}
    try:
        ports = nmap_discovery(scan["address"], scan["scan_ports"] or "1-65535", log_path)
        stats["open_ports_raw"] = len(ports)
        _log(log_path, f"open ports: {len(ports)}")

        by_host = {}
        for p in ports:
            by_host.setdefault(p["host"], []).append(p)
        limited = []
        for host, items in by_host.items():
            if len(items) > MAX_PORTS_PER_HOST:
                _log(log_path, f"!! {host}: {len(items)} open ports reported, limiting to {MAX_PORTS_PER_HOST}")
                stats["ports_truncated"] = True
                items = sorted(items, key=lambda x: (x["port"] not in COMMON_PORTS, x["port"]))[:MAX_PORTS_PER_HOST]
            limited.extend(items)
        ports = limited
        stats["open_ports"] = len(ports)
        stats["hosts"] = len({p["host"] for p in ports})
        _set_scan(scan_id, stage="Определение сервисов (nmap -sV)", progress=25)
        services = []
        for host, host_items in by_host.items():
            services.extend(nmap_services(host, [p["port"] for p in host_items], log_path))
        svc_index = {(s["host"], s["port"]): s for s in services}
        for p in ports:
            svc = svc_index.get((p["host"], p["port"]))
            if svc:
                p.update({k: svc[k] for k in ("service", "product", "version", "extrainfo", "title") if svc.get(k)})
        _set_scan(scan_id, stage="Поиск веб-интерфейсов", progress=35)

        urls = []
        probe_budget = int(os.environ.get("ASM_MAX_WEB_PROBES", "80"))
        with db.connect() as con:
            con.execute("DELETE FROM scan_ports WHERE scan_id=?", (scan_id,))
            for p in ports:
                is_web = 0
                url = ""
                title = p.get("title") or ""
                if _looks_web(p["port"], p.get("service"), p.get("product"), title) and probe_budget > 0:
                    probe_budget -= 1
                    probe = probe_http(p["host"], p["port"])
                    if probe:
                        is_web = 1
                        url = probe["url"]
                        title = title or probe.get("title") or ""
                        if url not in urls:
                            urls.append(url)
                con.execute(
                    "INSERT INTO scan_ports (scan_id, host, port, proto, service, product, version, extrainfo, "
                    "is_web, url, http_title) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (scan_id, p["host"], p["port"], p.get("proto") or "tcp", p.get("service") or "",
                     p.get("product") or "", p.get("version") or "", p.get("extrainfo") or "", is_web, url, title),
                )
        stats["web_urls"] = len(urls)
        _log(log_path, f"web urls: {urls}")

        _set_scan(scan_id, stage="Сканирование уязвимостей (nuclei)", progress=50)
        nuclei_findings = run_nuclei(urls, scan["nuclei_severity"], log_path)
        stats["nuclei"] = len(nuclei_findings)

        zap_findings = []
        if scan["zap_mode"] in ("baseline", "full") and urls:
            limit = int(os.environ.get("ASM_ZAP_MAX_URLS", "5"))
            _set_scan(scan_id, stage=f"Сканирование ZAP ({scan['zap_mode']})", progress=65)
            zap_findings = run_zap_urls(urls[:limit], scan["zap_mode"], scan_id, log_path)
        stats["zap"] = len(zap_findings)

        _set_scan(scan_id, stage="Сохранение результатов", progress=90)
        seen = set()
        for item in nuclei_findings + zap_findings:
            fp_key = (item["source"], item.get("template_id"), item.get("url"))
            if fp_key in seen:
                continue
            seen.add(fp_key)
            upsert_finding(target_id, scan_id, item)
        stats["findings"] = len(seen)

        _set_scan(scan_id, status="done", stage="Завершено", progress=100, finished_at=db.now(),
                  stats=json.dumps(stats, ensure_ascii=False))
        db.execute("UPDATE targets SET last_scan_at=?, next_scan_at=? WHERE id=?",
                   (db.now(), _next_run(scan["target_id"]), target_id))
        _log(log_path, f"=== done: {stats} ===")
    except Exception as exc:
        tb = traceback.format_exc()
        _log(log_path, "!! pipeline failed:\n" + tb)
        _set_scan(scan_id, status="failed", stage="Ошибка", error=str(exc)[:2000], finished_at=db.now())
        db.execute("UPDATE targets SET last_scan_at=?, next_scan_at=? WHERE id=?",
                   (db.now(), _next_run(target_id), target_id))


def _next_run(target_id):
    from datetime import datetime, timedelta, timezone
    row = db.query_one("SELECT interval_hours FROM targets WHERE id=?", (target_id,))
    hours = row["interval_hours"] if row else 24
    return (datetime.now(timezone.utc) + timedelta(hours=max(1, int(hours or 24)))).isoformat(timespec="seconds")


# ---------------------------------------------------------------- queue / scheduler

_queue: "queue.Queue[int]" = None
_worker_thread = None
_scheduler_thread = None
_stop = threading.Event()


def enqueue(target_id):
    import queue as _q
    global _queue
    if _queue is None:
        _queue = _q.Queue()
    existing = db.query_one(
        "SELECT id FROM scans WHERE target_id=? AND status IN ('queued','running') ORDER BY id DESC LIMIT 1",
        (target_id,),
    )
    if existing:
        return existing["id"], False
    scan_id = db.execute(
        "INSERT INTO scans (target_id, status, stage, progress, created_at) VALUES (?,?,?,?,?)",
        (target_id, "queued", "В очереди", 0, db.now()),
    )
    _queue.put(scan_id)
    return scan_id, True


def _worker():
    while not _stop.is_set():
        try:
            scan_id = _queue.get(timeout=1)
        except Exception:
            continue
        try:
            run_pipeline(scan_id)
        except Exception:
            traceback.print_exc()
        finally:
            _queue.task_done()


def _scheduler():
    while not _stop.is_set():
        try:
            due = db.query(
                "SELECT id FROM targets WHERE enabled=1 AND (next_scan_at IS NULL OR next_scan_at<=?)",
                (db.now(),),
            )
            for row in due:
                enqueue(row["id"])
                db.execute("UPDATE targets SET next_scan_at=? WHERE id=?", (_next_run(row["id"]), row["id"]))
        except Exception:
            traceback.print_exc()
        _stop.wait(30)


def start_workers():
    import queue as _q
    global _queue, _worker_thread, _scheduler_thread
    if _queue is None:
        _queue = _q.Queue()
    if _worker_thread is None or not _worker_thread.is_alive():
        _stop.clear()
        _worker_thread = threading.Thread(target=_worker, name="asm-scan-worker", daemon=True)
        _worker_thread.start()
    if _scheduler_thread is None or not _scheduler_thread.is_alive():
        _scheduler_thread = threading.Thread(target=_scheduler, name="asm-scheduler", daemon=True)
        _scheduler_thread.start()
