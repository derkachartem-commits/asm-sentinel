"""Проверка слабых паролей для ASM Sentinel.

Адаптация bruter_final.py (последняя версия от 18.10.2026): те же словари и
сервисы (SMB, SSH, MSSQL, PostgreSQL), но без записи CSV и отправки отчётов
почтой — результаты возвращаются списком словарей для scanner.py.

Модули импортируются опционально: если библиотеки нет, соответствующая
проверка просто пропускается, а скан продолжает работать.
"""

from __future__ import annotations

import json
import os
import socket
import time

from . import db

try:
    import paramiko
except Exception:  # pragma: no cover - зависит от окружения
    paramiko = None

try:
    from impacket.smbconnection import SMBConnection
except Exception:  # pragma: no cover
    SMBConnection = None

try:
    import pymssql
except Exception:  # pragma: no cover
    pymssql = None

try:
    import psycopg2
except Exception:  # pragma: no cover
    psycopg2 = None


DEFAULT_PORTS = [445, 22, 1433, 1434, 1435, 5432]
PORT_SERVICE = {445: "SMB", 22: "SSH", 1433: "MSSQL", 1434: "MSSQL", 1435: "MSSQL", 5432: "POSTGRES"}

DEFAULT_LISTS = {
    "smb_logins": ["Administrator", "Администратор", "localadmin", "admin", "vbrradmin"],
    "unix_logins": ["root", "admin", "test", "vbrradmin"],
    "common_passwords": [
        "1qaz@WSX", "P@ssw0rd", "1qaz!QAZ", "!QAZ2wsx", "!qaz2wsx",
        "12345678", "admin", "password", "123qweASD",
    ],
    "mssql_logins": ["sa"],
    "mssql_passwords": ["qweasdzxc", "1qaz!QAZ", "123qweASD"],
    "pg_logins": ["postgres", "admin", "vbrradmin"],
    "pg_passwords": [
        "postgres", "1qaz!QAZ", "123qweASD", "qweasdzxc", "P@ssw0rd",
        "1qaz@WSX", "!QAZ2wsx", "admin", "password", "12345678",
    ],
    "pg_databases": ["postgres", "template1"],
}


def load_lists():
    """Словари из вкладки «Конфигурация» с откатом на дефолты."""
    data = {key: list(values) for key, values in DEFAULT_LISTS.items()}
    try:
        rows = db.query("SELECT key, value FROM brute_config")
    except Exception:
        return data
    for row in rows:
        key = row["key"]
        if key not in data:
            continue
        try:
            values = json.loads(row["value"])
        except (TypeError, ValueError):
            continue
        if isinstance(values, list):
            data[key] = [str(value).strip() for value in values if str(value).strip()]
    return data

MAX_ATTEMPTS = int(os.environ.get("ASM_BRUTE_MAX_ATTEMPTS", "200"))
MAX_HOSTS = int(os.environ.get("ASM_BRUTE_MAX_HOSTS", "16"))
HOST_TIMEOUT = int(os.environ.get("ASM_BRUTE_HOST_TIMEOUT", "600"))
CONNECT_TIMEOUT = int(os.environ.get("ASM_BRUTE_CONNECT_TIMEOUT", "5"))


def modules_available():
    return {
        "smb": SMBConnection is not None,
        "ssh": paramiko is not None,
        "mssql": pymssql is not None,
        "postgres": psycopg2 is not None,
    }


def _log(log_path, message):
    if not log_path:
        return
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [brute] {message}\n")
    except OSError:
        pass


def _port_open(host, port, timeout=1.0):
    sock = socket.socket()
    sock.settimeout(timeout)
    try:
        sock.connect((host, int(port)))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _result(service, host, port, login, password, info, db=""):
    return {
        "service": service,
        "host": host,
        "port": int(port),
        "login": login,
        "password": password,
        "db": db,
        "info": info,
    }


def _smb_brute(host, port, log_path, lists):
    if SMBConnection is None:
        return []
    results = []
    attempts = 0
    for user in lists["smb_logins"]:
        candidates = [user] + [p for p in lists["common_passwords"] if p != user]
        for password in candidates:
            if attempts >= MAX_ATTEMPTS:
                return results
            attempts += 1
            conn = None
            try:
                conn = SMBConnection(host, host, sess_port=port, timeout=CONNECT_TIMEOUT)
                conn.login(user, password, "localhost")
                results.append(_result("SMB", host, port, user, password, "Windows Account Active"))
                _log(log_path, f"SMB {host}:{port} — подобраны учётные данные {user}")
                break
            except Exception:
                continue
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
    return results


def _ssh_brute(host, port, log_path, lists):
    if paramiko is None:
        return []
    results = []
    attempts = 0
    retry_delay = float(os.environ.get("ASM_BRUTE_SSH_RETRY_DELAY", "2"))
    for user in lists["unix_logins"]:
        found_for_user = False
        for password in lists["common_passwords"]:
            if attempts >= MAX_ATTEMPTS:
                return results
            attempts += 1
            for attempt in range(3):
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    client.connect(
                        host,
                        port=port,
                        username=user,
                        password=password,
                        timeout=CONNECT_TIMEOUT,
                        banner_timeout=CONNECT_TIMEOUT,
                        auth_timeout=CONNECT_TIMEOUT,
                        allow_agent=False,
                        look_for_keys=False,
                    )
                    results.append(_result("SSH", host, port, user, password, "UNIX Account Active"))
                    _log(log_path, f"SSH {host}:{port} — подобраны учётные данные {user}")
                    found_for_user = True
                    break
                except paramiko.AuthenticationException:
                    # Обычный неверный пароль: пауза, чтобы sshd не включал
                    # штраф за частые неудачные попытки.
                    time.sleep(0.4)
                    break
                except Exception as exc:
                    msg = str(exc).lower()
                    transient = any(marker in msg for marker in ("banner", "timed out", "reset", "aborted", "eof"))
                    if transient and attempt < 2:
                        delay = retry_delay * (attempt + 1)
                        _log(log_path, f"SSH {host}:{port} — временная ошибка ({exc}), повтор через {delay:.0f}s")
                        time.sleep(delay)
                        continue
                    _log(log_path, f"SSH {host}:{port} — проверка {user} пропущена: {exc}")
                    time.sleep(retry_delay)
                    break
                finally:
                    try:
                        client.close()
                    except Exception:
                        pass
            if found_for_user:
                break
        if found_for_user:
            break
        time.sleep(0.3)
    return results


def _mssql_brute(host, port, log_path, lists):
    if pymssql is None:
        return []
    results = []
    for user in lists["mssql_logins"]:
        for password in lists["mssql_passwords"]:
            conn = None
            try:
                conn = pymssql.connect(
                    server=host, user=user, password=password, port=port,
                    login_timeout=CONNECT_TIMEOUT, timeout=CONNECT_TIMEOUT,
                )
                results.append(_result("MSSQL", host, port, user, password, "MSSQL Account Active"))
                _log(log_path, f"MSSQL {host}:{port} — подобраны учётные данные {user}")
                return results
            except Exception:
                continue
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
    return results


def _pg_brute(host, port, log_path, lists):
    if psycopg2 is None:
        return []
    results = []
    attempts = 0
    for user in lists["pg_logins"]:
        for password in lists["pg_passwords"]:
            for db in lists["pg_databases"]:
                if attempts >= MAX_ATTEMPTS:
                    return results
                attempts += 1
                conn = None
                try:
                    conn = psycopg2.connect(
                        host=host, port=port, user=user, password=password,
                        dbname=db, connect_timeout=CONNECT_TIMEOUT,
                        application_name="asm-sentinel",
                    )
                    version = ""
                    try:
                        cur = conn.cursor()
                        cur.execute("select version()")
                        row = cur.fetchone()
                        version = str((row or [""])[0])[:80]
                        cur.close()
                    except Exception:
                        pass
                    results.append(_result("POSTGRES", host, port, user, password, version, db=db))
                    _log(log_path, f"POSTGRES {host}:{port}/{db} — подобраны учётные данные {user}")
                    return results
                except Exception:
                    continue
                finally:
                    if conn is not None:
                        try:
                            conn.close()
                        except Exception:
                            pass
    return results


def check_host(host, ports=None, log_path=None):
    """Проверяет один хост по указанным портам. Возвращает список находок."""
    wanted = sorted({int(p) for p in (ports or DEFAULT_PORTS) if int(p) in PORT_SERVICE})
    if not wanted:
        wanted = list(DEFAULT_PORTS)
    lists = load_lists()
    available = modules_available()
    deadline = time.time() + HOST_TIMEOUT
    results = []
    for port in wanted:
        if time.time() > deadline:
            _log(log_path, f"{host}: превышен лимит времени на хост ({HOST_TIMEOUT}s)")
            break
        service = PORT_SERVICE[port]
        if not _port_open(host, port):
            continue
        key = {"SMB": "smb", "SSH": "ssh", "MSSQL": "mssql", "POSTGRES": "postgres"}[service]
        if not available[key]:
            _log(log_path, f"{host}:{port} {service} — python-модуль не установлен, пропуск")
            continue
        _log(log_path, f"{host}:{port} {service} — проверка учётных данных")
        try:
            if service == "SMB":
                results.extend(_smb_brute(host, port, log_path, lists))
            elif service == "SSH":
                results.extend(_ssh_brute(host, port, log_path, lists))
            elif service == "MSSQL":
                results.extend(_mssql_brute(host, port, log_path, lists))
            else:
                results.extend(_pg_brute(host, port, log_path, lists))
        except Exception as exc:
            _log(log_path, f"{host}:{port} {service} — ошибка проверки: {exc}")
    return results
