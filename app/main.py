import csv
import hmac
import html
import io
import json
import os
import re
import urllib.parse
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import auth, bruter, db, scanner

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

SEVERITY_LABEL = {"critical": "Критическая", "high": "Высокая", "medium": "Средняя", "low": "Низкая", "info": "Инфо"}
STATUS_LABEL = {
    "new": "Новая",
    "in_progress": "В работе",
    "fixed": "Исправлена",
    "false_positive": "Ложное срабатывание",
    "accepted": "Принятый риск",
}
STATUS_ORDER = ["new", "in_progress", "fixed", "false_positive", "accepted"]
SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SCAN_OPTION_KEYS = ("nmap", "brute", "nuclei", "zap")
BRUTE_LIST_KEYS = tuple(bruter.DEFAULT_LISTS.keys())


PORT_SPEC_RE = re.compile(r"^\d{1,5}(-\d{1,5})?$")


def normalize_ports(value):
    """Проверяет и нормализует список портов вида 22,445,8000-8100."""
    raw = str(value or "").strip()
    if not raw:
        return "1-65535"
    parts = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if not PORT_SPEC_RE.match(item):
            raise ValueError("bad port: " + item)
        if "-" in item:
            start, end = (int(x) for x in item.split("-", 1))
            if start < 1 or end > 65535 or start > end:
                raise ValueError("bad range: " + item)
        else:
            port = int(item)
            if port < 1 or port > 65535:
                raise ValueError("bad port: " + item)
        parts.append(item)
    return ",".join(parts) or "1-65535"


def _scan_params_from_form(form):
    scan_ports = normalize_ports(str(form.get("scan_ports") or "1-65535"))
    zap_mode = str(form.get("zap_mode") or "baseline")
    if zap_mode not in ("baseline", "full", "off"):
        zap_mode = "baseline"
    nuclei_severity = str(form.get("nuclei_severity") or "critical,high,medium,low,info").strip()
    return scan_ports, zap_mode, (nuclei_severity or "critical,high,medium,low,info")


def _schedule_interval(form):
    try:
        return max(1, int(form.get("interval_hours") or 24))
    except (TypeError, ValueError):
        return 24

app = FastAPI(title="ASM Sentinel", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATE_DIR)


def _fmt_dt(value):
    if not value:
        return "—"
    return str(value).replace("T", " ").replace("+00:00", "")


def normalize_address(value: str) -> str:
    """Принимает URL, host:port, домен, IP или CIDR — возвращает то, что понимает nmap."""
    raw = (value or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urllib.parse.urlsplit(raw)
        raw = parsed.hostname or ""
    elif re.match(r"^[A-Za-z0-9_.\-]+:\d+$", raw):
        raw = raw.rsplit(":", 1)[0]
    return raw.strip().strip("[]")


templates.env.filters["dt"] = _fmt_dt


def _from_json(value):
    if not value:
        return {}
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return {}


templates.env.filters["from_json"] = _from_json
templates.env.globals["SEVERITY_LABEL"] = SEVERITY_LABEL
templates.env.globals["STATUS_LABEL"] = STATUS_LABEL
templates.env.globals["STATUS_ORDER"] = STATUS_ORDER
templates.env.globals["SEV_ORDER"] = SEV_ORDER


@app.on_event("startup")
def startup():
    db.init_db()
    db.execute(
        "UPDATE scans SET status='failed', stage='Прервано', error=?, finished_at=? "
        "WHERE status IN ('queued','running')",
        ("Сканирование прервано перезапуском сервиса", db.now()),
    )
    scanner.start_workers()


def render(request: Request, name: str, **ctx):
    session = getattr(request.state, "session", None) or {}
    ctx.setdefault("csrf", session.get("csrf", ""))
    ctx.setdefault("msg", request.query_params.get("msg", ""))
    ctx.setdefault("path", request.url.path)
    return templates.TemplateResponse(request, name, ctx)


def redirect(url: str, msg: str | None = None):
    if msg:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}msg={urllib.parse.quote(msg)}"
    return RedirectResponse(url, status_code=303)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith("/static") or path in ("/login", "/healthz", "/favicon.ico"):
        return await call_next(request)
    session = auth.read_session(request.cookies.get(auth.COOKIE_NAME))
    if not session:
        if path.startswith("/api/"):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return RedirectResponse(f"/login?next={urllib.parse.quote(path)}", status_code=303)
    request.state.session = session
    return await call_next(request)


def csrf_ok(request: Request, token: str) -> bool:
    session = getattr(request.state, "session", None) or {}
    return bool(token) and hmac.compare_digest(token, session.get("csrf", ""))


# ---------------------------------------------------------------- auth

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"err": request.query_params.get("err"), "next": request.query_params.get("next", "/")})


@app.post("/login")
async def login_submit(request: Request):
    form = await request.form()
    ip = request.client.host if request.client else "?"
    if not auth.login_allowed(ip):
        return redirect("/login", "Слишком много попыток. Подождите 5 минут.")
    if not auth.password_ok(str(form.get("password", ""))):
        auth.note_failure(ip)
        return redirect("/login", "Неверный пароль")
    auth.clear_failures(ip)
    target = str(form.get("next") or "/")
    if not target.startswith("/"):
        target = "/"
    response = RedirectResponse(target, status_code=303)
    response.set_cookie(
        auth.COOKIE_NAME, auth.make_session(), max_age=auth.SESSION_MAX_AGE,
        httponly=True, samesite="lax", secure=os.environ.get("ASM_COOKIE_SECURE") == "1",
    )
    return response


@app.get("/logout")
def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(auth.COOKIE_NAME)
    return response


# ---------------------------------------------------------------- dashboard

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    sev_rows = db.query(
        "SELECT severity, COUNT(*) AS c FROM findings WHERE status NOT IN ('fixed','false_positive') GROUP BY severity"
    )
    sev = {r["severity"]: r["c"] for r in sev_rows}
    open_total = sum(sev.values())
    targets_count = db.query_one("SELECT COUNT(*) AS c FROM targets")["c"]
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds")
    scans_24h = db.query_one("SELECT COUNT(*) AS c FROM scans WHERE created_at >= ?", (since,))["c"]
    ports_total = db.query_one("SELECT COUNT(*) AS c FROM scan_ports WHERE scan_id IN (SELECT MAX(id) FROM scans WHERE status='done' GROUP BY target_id)")["c"]
    recent = db.query(
        "SELECT f.*, t.name AS target_name FROM findings f JOIN targets t ON t.id=f.target_id "
        "ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, "
        "f.last_seen DESC LIMIT 12"
    )
    active = db.query(
        "SELECT s.*, t.name AS target_name FROM scans s JOIN targets t ON t.id=s.target_id "
        "WHERE s.status IN ('queued','running') ORDER BY s.id LIMIT 5"
    )
    return render(request, "dashboard.html", sev=sev, open_total=open_total, targets_count=targets_count,
                  scans_24h=scans_24h, ports_total=ports_total, recent=recent, active=active)


# ---------------------------------------------------------------- targets

@app.get("/targets", response_class=HTMLResponse)
def targets_page(request: Request):
    rows = db.query(
        "SELECT t.*, (SELECT COUNT(*) FROM findings f WHERE f.target_id=t.id AND f.status NOT IN ('fixed','false_positive')) AS open_findings, "
        "(SELECT COUNT(*) FROM findings f WHERE f.target_id=t.id AND f.severity IN ('critical','high') AND f.status NOT IN ('fixed','false_positive')) AS risky "
        "FROM targets t ORDER BY t.id"
    )
    return render(request, "targets.html", targets=rows)


@app.get("/targets/new", response_class=HTMLResponse)
def target_new(request: Request):
    return render(request, "target_form.html", target=None, action="/targets/new")


@app.post("/targets/new")
async def target_create(request: Request):
    form = await request.form()
    if not csrf_ok(request, str(form.get("csrf", ""))):
        return redirect("/targets", "Ошибка CSRF, повторите")
    name = str(form.get("name", "")).strip()
    address = normalize_address(str(form.get("address", "")))
    if not name or not address:
        return redirect("/targets/new", "Заполните название и корректный адрес")
    target_id = db.execute(
        "INSERT INTO targets (name, address, enabled, interval_hours, scan_ports, zap_mode, nuclei_severity, created_at, next_scan_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (name, address, 0, 24, "1-65535", "baseline", "critical,high,medium,low,info", db.now(), None),
    )
    return redirect(f"/targets/{target_id}", "Цель добавлена. Регулярность и параметры сканов — в «Сканированиях»")


@app.get("/targets/{target_id}", response_class=HTMLResponse)
def target_detail(request: Request, target_id: int):
    target = db.query_one("SELECT * FROM targets WHERE id=?", (target_id,))
    if not target:
        return redirect("/targets", "Цель не найдена")
    scans = db.query("SELECT * FROM scans WHERE target_id=? ORDER BY id DESC LIMIT 50", (target_id,))
    findings = db.query(
        "SELECT * FROM findings WHERE target_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, last_seen DESC LIMIT 200",
        (target_id,),
    )
    latest = scans[0]["id"] if scans else None
    ports = db.query("SELECT * FROM scan_ports WHERE scan_id=? ORDER BY port", (latest,)) if latest else []
    schedule_count = db.query_one("SELECT COUNT(*) AS c FROM schedules WHERE target_id=?", (target_id,))["c"]
    return render(request, "target_detail.html", target=target, scans=scans, findings=findings, ports=ports,
                  latest_scan=latest, schedule_count=schedule_count)


@app.get("/targets/{target_id}/edit", response_class=HTMLResponse)
def target_edit(request: Request, target_id: int):
    target = db.query_one("SELECT * FROM targets WHERE id=?", (target_id,))
    if not target:
        return redirect("/targets", "Цель не найдена")
    return render(request, "target_form.html", target=target, action=f"/targets/{target_id}/edit")


@app.post("/targets/{target_id}/edit")
async def target_update(request: Request, target_id: int):
    form = await request.form()
    if not csrf_ok(request, str(form.get("csrf", ""))):
        return redirect(f"/targets/{target_id}", "Ошибка CSRF, повторите")
    address = normalize_address(str(form.get("address", "")))
    if not address:
        return redirect(f"/targets/{target_id}/edit", "Некорректный адрес")
    db.execute(
        "UPDATE targets SET name=?, address=? WHERE id=?",
        (str(form.get("name", "")).strip(), address, target_id),
    )
    return redirect(f"/targets/{target_id}", "Сохранено")


@app.post("/targets/{target_id}/delete")
async def target_delete(request: Request, target_id: int):
    form = await request.form()
    if not csrf_ok(request, str(form.get("csrf", ""))):
        return redirect("/targets", "Ошибка CSRF")
    db.execute("DELETE FROM targets WHERE id=?", (target_id,))
    return redirect("/targets", "Цель удалена")


@app.post("/targets/{target_id}/scan")
async def target_scan(request: Request, target_id: int):
    target = db.query_one("SELECT id FROM targets WHERE id=?", (target_id,))
    if not target:
        return redirect("/targets", "Цель не найдена")
    form = await request.form()
    if form.get("csrf") and not csrf_ok(request, str(form.get("csrf", ""))):
        return redirect(f"/targets/{target_id}", "Ошибка CSRF, повторите")
    options = {key: bool(form.get(key)) for key in SCAN_OPTION_KEYS} if form else None
    if options is not None and not any(options.values()):
        return redirect(f"/scans/new?target={target_id}", "Выберите хотя бы один модуль")
    scan_id, created = scanner.enqueue(target_id, options)
    return redirect(f"/scans/{scan_id}", "Сканирование поставлено в очередь" if created else "Сканирование уже выполняется")


# ---------------------------------------------------------------- config

@app.get("/config", response_class=HTMLResponse)
def config_page(request: Request):
    rows = db.query("SELECT key, value FROM brute_config")
    data = {}
    for row in rows:
        try:
            values = json.loads(row["value"])
        except (TypeError, ValueError):
            values = []
        data[row["key"]] = "\n".join(str(v) for v in values) if isinstance(values, list) else ""
    for key in BRUTE_LIST_KEYS:
        data.setdefault(key, "\n".join(bruter.DEFAULT_LISTS[key]))
    return render(request, "config.html", lists=data)


@app.post("/config")
async def config_save(request: Request):
    form = await request.form()
    if not csrf_ok(request, str(form.get("csrf", ""))):
        return redirect("/config", "Ошибка CSRF, повторите")
    for key in BRUTE_LIST_KEYS:
        raw = str(form.get(key) or "")
        values = [line.strip() for line in raw.splitlines() if line.strip()]
        db.execute(
            "INSERT OR REPLACE INTO brute_config (key, value) VALUES (?,?)",
            (key, json.dumps(values, ensure_ascii=False)),
        )
    return redirect("/config", "Словари сохранены")


# ---------------------------------------------------------------- scans

@app.get("/scans", response_class=HTMLResponse)
def scans_page(request: Request, target: int | None = None, status: str = "", page: int = 1):
    page = max(1, page)
    per = 25
    where, args = [], []
    if target:
        where.append("s.target_id=?")
        args.append(target)
    if status in ("queued", "running", "done", "failed"):
        where.append("s.status=?")
        args.append(status)
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    total = db.query_one(f"SELECT COUNT(*) AS c FROM scans s {clause}", tuple(args))["c"]
    rows = db.query(
        f"SELECT s.*, t.name AS target_name, t.address FROM scans s JOIN targets t ON t.id=s.target_id {clause} "
        "ORDER BY s.id DESC LIMIT ? OFFSET ?", (*args, per, (page - 1) * per),
    )
    qs = urllib.parse.urlencode({k: v for k, v in {"target": target or "", "status": status}.items() if v})
    targets = db.query("SELECT id, name FROM targets ORDER BY name")
    schedules = db.query(
        "SELECT s.*, t.name AS target_name, t.address FROM schedules s JOIN targets t ON t.id=s.target_id "
        "ORDER BY s.id"
    )
    return render(request, "scans.html", scans=rows, page=page, pages=max(1, (total + per - 1) // per),
                  total=total, qs=qs, target_id=target, status=status, targets=targets, schedules=schedules)


@app.get("/scans/new", response_class=HTMLResponse)
def scan_new(request: Request, target: int | None = None):
    targets = db.query(
        "SELECT id, name, address, scan_ports, zap_mode, nuclei_severity FROM targets ORDER BY name"
    )
    selected_id = target if any(t["id"] == target for t in targets) else (targets[0]["id"] if targets else None)
    selected = next((t for t in targets if t["id"] == selected_id), None)
    return render(request, "scan_form.html", targets=targets, target_id=selected_id, selected=selected)


@app.post("/scans/new")
async def scan_create(request: Request):
    form = await request.form()
    if not csrf_ok(request, str(form.get("csrf", ""))):
        return redirect("/scans/new", "Ошибка CSRF, повторите")
    raw_target = str(form.get("target", ""))
    target_id = int(raw_target) if raw_target.isdigit() else 0
    if not db.query_one("SELECT id FROM targets WHERE id=?", (target_id,)):
        return redirect("/scans/new", "Выберите цель")
    options = {key: bool(form.get(key)) for key in SCAN_OPTION_KEYS}
    if not any(options.values()):
        return redirect(f"/scans/new?target={target_id}", "Выберите хотя бы один модуль")
    try:
        scan_ports, zap_mode, nuclei_severity = _scan_params_from_form(form)
    except ValueError:
        return redirect(f"/scans/new?target={target_id}", "Некорректный список портов. Пример: 22,445,8000-8100")
    params = {"scan_ports": scan_ports, "zap_mode": zap_mode, "nuclei_severity": nuclei_severity}
    scan_id, created = scanner.enqueue(target_id, options, params)
    return redirect(f"/scans/{scan_id}", "Сканирование поставлено в очередь" if created else "Сканирование уже выполняется")


# ---------------------------------------------------------------- schedules

def _schedule_form_context(schedule=None, target=None):
    targets = db.query("SELECT id, name, address, scan_ports, zap_mode, nuclei_severity FROM targets ORDER BY name")
    selected_id = None
    if schedule is not None:
        selected_id = schedule["target_id"]
    elif target is not None:
        selected_id = target
    if selected_id is None and targets:
        selected_id = targets[0]["id"]
    selected = next((t for t in targets if t["id"] == selected_id), None)
    if schedule is not None:
        opts = scanner._scan_options(schedule["options"])
    else:
        opts = {"nmap": True, "brute": True, "nuclei": True, "zap": True}
    return {"targets": targets, "target_id": selected_id, "selected": selected, "schedule": schedule, "opts": opts}


@app.get("/schedules/new", response_class=HTMLResponse)
def schedule_new(request: Request, target: int | None = None):
    return render(request, "schedule_form.html", action="/schedules/new", **_schedule_form_context(target=target))


@app.post("/schedules/new")
async def schedule_create(request: Request):
    form = await request.form()
    if not csrf_ok(request, str(form.get("csrf", ""))):
        return redirect("/schedules/new", "Ошибка CSRF, повторите")
    raw_target = str(form.get("target", ""))
    target_id = int(raw_target) if raw_target.isdigit() else 0
    if not db.query_one("SELECT id FROM targets WHERE id=?", (target_id,)):
        return redirect("/schedules/new", "Выберите цель")
    options = {key: bool(form.get(key)) for key in SCAN_OPTION_KEYS}
    if not any(options.values()):
        return redirect(f"/schedules/new?target={target_id}", "Выберите хотя бы один модуль")
    try:
        scan_ports, zap_mode, nuclei_severity = _scan_params_from_form(form)
    except ValueError:
        return redirect(f"/schedules/new?target={target_id}", "Некорректный список портов")
    interval = _schedule_interval(form)
    next_run = (datetime.now(timezone.utc) + timedelta(hours=interval)).isoformat(timespec="seconds")
    db.execute(
        "INSERT INTO schedules (target_id, interval_hours, scan_ports, zap_mode, nuclei_severity, options, enabled, "
        "next_run_at, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (target_id, interval, scan_ports, zap_mode, nuclei_severity,
         json.dumps(options, ensure_ascii=False), 1, next_run, db.now()),
    )
    return redirect("/scans", "Регулярное сканирование добавлено")


@app.get("/schedules/{schedule_id}/edit", response_class=HTMLResponse)
def schedule_edit(request: Request, schedule_id: int):
    schedule = db.query_one("SELECT * FROM schedules WHERE id=?", (schedule_id,))
    if not schedule:
        return redirect("/scans", "Регулярное сканирование не найдено")
    return render(request, "schedule_form.html", action=f"/schedules/{schedule_id}/edit",
                  **_schedule_form_context(schedule=schedule))


@app.post("/schedules/{schedule_id}/edit")
async def schedule_update(request: Request, schedule_id: int):
    form = await request.form()
    if not csrf_ok(request, str(form.get("csrf", ""))):
        return redirect("/scans", "Ошибка CSRF, повторите")
    schedule = db.query_one("SELECT * FROM schedules WHERE id=?", (schedule_id,))
    if not schedule:
        return redirect("/scans", "Регулярное сканирование не найдено")
    raw_target = str(form.get("target", ""))
    target_id = int(raw_target) if raw_target.isdigit() else 0
    if not db.query_one("SELECT id FROM targets WHERE id=?", (target_id,)):
        return redirect(f"/schedules/{schedule_id}/edit", "Выберите цель")
    options = {key: bool(form.get(key)) for key in SCAN_OPTION_KEYS}
    if not any(options.values()):
        return redirect(f"/schedules/{schedule_id}/edit", "Выберите хотя бы один модуль")
    try:
        scan_ports, zap_mode, nuclei_severity = _scan_params_from_form(form)
    except ValueError:
        return redirect(f"/schedules/{schedule_id}/edit", "Некорректный список портов")
    interval = _schedule_interval(form)
    next_run = (datetime.now(timezone.utc) + timedelta(hours=interval)).isoformat(timespec="seconds")
    db.execute(
        "UPDATE schedules SET target_id=?, interval_hours=?, scan_ports=?, zap_mode=?, nuclei_severity=?, options=?, "
        "next_run_at=? WHERE id=?",
        (target_id, interval, scan_ports, zap_mode, nuclei_severity,
         json.dumps(options, ensure_ascii=False), next_run, schedule_id),
    )
    return redirect("/scans", "Регулярное сканирование обновлено")


@app.post("/schedules/{schedule_id}/delete")
async def schedule_delete(request: Request, schedule_id: int):
    form = await request.form()
    if not csrf_ok(request, str(form.get("csrf", ""))):
        return redirect("/scans", "Ошибка CSRF, повторите")
    db.execute("DELETE FROM schedules WHERE id=?", (schedule_id,))
    return redirect("/scans", "Регулярное сканирование удалено")


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(request: Request, scan_id: int):
    scan = db.query_one("SELECT s.*, t.name AS target_name, t.address FROM scans s JOIN targets t ON t.id=s.target_id WHERE s.id=?", (scan_id,))
    if not scan:
        return redirect("/scans", "Скан не найден")
    ports = db.query("SELECT * FROM scan_ports WHERE scan_id=? ORDER BY port", (scan_id,))
    findings = db.query(
        "SELECT f.* FROM findings f JOIN scan_findings sf ON sf.finding_id=f.id WHERE sf.scan_id=? "
        "ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",
        (scan_id,),
    )
    stats = {}
    if scan["stats"]:
        try:
            stats = json.loads(scan["stats"])
        except json.JSONDecodeError:
            stats = {}
    return render(request, "scan_detail.html", scan=scan, ports=ports, findings=findings, stats=stats)


@app.get("/scans/{scan_id}/log", response_class=PlainTextResponse)
def scan_log(scan_id: int):
    path = os.path.join(scanner.LOG_DIR, f"scan-{scan_id}.log")
    if not os.path.exists(path):
        return PlainTextResponse("Лог пока пуст", status_code=404)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = f.read()
    return PlainTextResponse(data[-300000:])


# ---------------------------------------------------------------- findings

def _findings_query(args):
    where, params = [], []
    if args.get("target"):
        where.append("f.target_id=?")
        params.append(args["target"])
    if args.get("severity") in SEVERITY_LABEL:
        where.append("f.severity=?")
        params.append(args["severity"])
    if args.get("status") in STATUS_LABEL:
        where.append("f.status=?")
        params.append(args["status"])
    if args.get("source") in ("nuclei", "zap", "brute"):
        where.append("f.source=?")
        params.append(args["source"])
    if args.get("q"):
        where.append("(f.name LIKE ? OR f.url LIKE ? OR f.host LIKE ? OR f.cve LIKE ? OR f.template_id LIKE ?)")
        like = f"%{args['q']}%"
        params.extend([like] * 5)
    return ("WHERE " + " AND ".join(where)) if where else "", params


@app.get("/findings", response_class=HTMLResponse)
def findings_page(request: Request, target: int | None = None, severity: str = "", status: str = "",
                  source: str = "", q: str = "", page: int = 1):
    page = max(1, page)
    per = 50
    clause, params = _findings_query({"target": target, "severity": severity, "status": status, "source": source, "q": q})
    total = db.query_one(f"SELECT COUNT(*) AS c FROM findings f {clause}", tuple(params))["c"]
    rows = db.query(
        f"SELECT f.*, t.name AS target_name FROM findings f JOIN targets t ON t.id=f.target_id {clause} "
        "ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, "
        "f.last_seen DESC LIMIT ? OFFSET ?", (*params, per, (page - 1) * per),
    )
    qs = urllib.parse.urlencode({k: v for k, v in {"target": target or "", "severity": severity, "status": status,
                                                    "source": source, "q": q}.items() if v})
    targets = db.query("SELECT id, name FROM targets ORDER BY name")
    return render(request, "findings.html", findings=rows, page=page, pages=max(1, (total + per - 1) // per),
                  total=total, qs=qs, targets=targets, f_target=target, f_severity=severity,
                  f_status=status, f_source=source, f_q=q)


@app.get("/findings/{finding_id}", response_class=HTMLResponse)
def finding_detail(request: Request, finding_id: int):
    finding = db.query_one("SELECT f.*, t.name AS target_name, t.address FROM findings f JOIN targets t ON t.id=f.target_id WHERE f.id=?", (finding_id,))
    if not finding:
        return redirect("/findings", "Уязвимость не найдена")
    events = db.query("SELECT * FROM finding_events WHERE finding_id=? ORDER BY id DESC", (finding_id,))
    return render(request, "finding_detail.html", finding=finding, events=events)


@app.post("/findings/{finding_id}/status")
async def finding_status(request: Request, finding_id: int):
    form = await request.form()
    if not csrf_ok(request, str(form.get("csrf", ""))):
        return redirect("/findings", "Ошибка CSRF, повторите")
    new_status = str(form.get("status", ""))
    note = str(form.get("note", "")).strip()
    if new_status not in STATUS_LABEL:
        return redirect(f"/findings/{finding_id}", "Недопустимый статус")
    row = db.query_one("SELECT status FROM findings WHERE id=?", (finding_id,))
    if not row:
        return redirect("/findings", "Уязвимость не найдена")
    old_status = row["status"]
    db.execute("UPDATE findings SET status=?, note=? WHERE id=?", (new_status, note or None, finding_id))
    if old_status != new_status:
        db.execute(
            "INSERT INTO finding_events (finding_id, ts, actor, type, old_status, new_status, note) VALUES (?,?,?,?,?,?,?)",
            (finding_id, db.now(), "admin", "status_change", old_status, new_status, note or None),
        )
    return redirect(f"/findings/{finding_id}", "Статус обновлён")


@app.post("/findings/bulk")
async def findings_bulk(request: Request):
    form = await request.form()
    if not csrf_ok(request, str(form.get("csrf", ""))):
        return redirect("/findings", "Ошибка CSRF, повторите")
    ids = [int(v) for v in form.getlist("ids") if str(v).isdigit()]
    new_status = str(form.get("status", ""))
    note = str(form.get("note", "")).strip()
    if new_status not in STATUS_LABEL or not ids:
        return redirect("/findings", "Выберите уязвимости и статус")
    now = db.now()
    with db.connect() as con:
        for fid in ids:
            row = con.execute("SELECT status FROM findings WHERE id=?", (fid,)).fetchone()
            if not row:
                continue
            old_status = row["status"]
            con.execute("UPDATE findings SET status=? WHERE id=?", (new_status, fid))
            if old_status != new_status:
                con.execute(
                    "INSERT INTO finding_events (finding_id, ts, actor, type, old_status, new_status, note) VALUES (?,?,?,?,?,?,?)",
                    (fid, now, "admin", "status_change", old_status, new_status, note or "Массовое изменение"),
                )
    return redirect("/findings", f"Обновлено: {len(ids)}")


@app.get("/export/findings.csv")
def export_csv(target: int | None = None, severity: str = "", status: str = "", source: str = "", q: str = ""):
    clause, params = _findings_query({"target": target, "severity": severity, "status": status, "source": source, "q": q})
    rows = db.query(
        f"SELECT f.*, t.name AS target_name FROM findings f JOIN targets t ON t.id=f.target_id {clause} "
        "ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.last_seen DESC",
        tuple(params),
    )
    buf = io.StringIO()
    buf.write("\ufeff")
    writer = csv.writer(buf, delimiter=";")
    writer.writerow(["ID", "Цель", "Уязвимость", "Критичность", "Статус", "Источник", "Хост", "Порт", "URL", "CVE", "CVSS",
                     "Обнаружена", "Последняя проверка", "Повторений", "Решение", "Ссылки"])
    for r in rows:
        writer.writerow([r["id"], r["target_name"], r["name"], SEVERITY_LABEL.get(r["severity"], r["severity"]),
                         STATUS_LABEL.get(r["status"], r["status"]), r["source"], r["host"], r["port"], r["url"],
                         r["cve"], r["cvss"], _fmt_dt(r["first_seen"]), _fmt_dt(r["last_seen"]), r["occurrences"],
                         (r["solution"] or "").replace("\n", " "), (r["reference"] or "").replace("\n", " ")])
    return Response(content=buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="findings.csv"'})


# ---------------------------------------------------------------- api

@app.post("/api/targets/{target_id}/scan")
async def api_scan(target_id: int, request: Request):
    if not db.query_one("SELECT id FROM targets WHERE id=?", (target_id,)):
        return JSONResponse({"error": "not found"}, status_code=404)
    options = None
    params = None
    try:
        body = await request.json()
    except Exception:
        body = None
    if isinstance(body, dict):
        options = {key: bool(body.get(key, True)) for key in SCAN_OPTION_KEYS}
        if not any(options.values()):
            return JSONResponse({"error": "no modules selected"}, status_code=400)
        params = {}
        if body.get("scan_ports"):
            try:
                params["scan_ports"] = normalize_ports(body["scan_ports"])
            except ValueError:
                return JSONResponse({"error": "bad ports"}, status_code=400)
        if body.get("zap_mode") in ("baseline", "full", "off"):
            params["zap_mode"] = body["zap_mode"]
        if body.get("nuclei_severity"):
            params["nuclei_severity"] = str(body["nuclei_severity"]).strip()
        params = params or None
    scan_id, created = scanner.enqueue(target_id, options, params)
    return JSONResponse({"scan_id": scan_id, "created": created})


@app.get("/api/scans/active")
def api_active():
    rows = db.query(
        "SELECT s.id, s.status, s.stage, s.progress, s.started_at, t.name AS target_name FROM scans s "
        "JOIN targets t ON t.id=s.target_id WHERE s.status IN ('queued','running') ORDER BY s.id"
    )
    return JSONResponse([dict(r) for r in rows])


@app.get("/healthz")
def healthz():
    return {"status": "ok", "time": db.now()}
