# Офлайн-установка ASM Sentinel

Версия: **1.1.0**

В репозитории уже лежат Python-зависимости для офлайн-установки:

- `vendor/wheels/` — 46 wheel-пакетов для **Linux x86_64, CPython 3.12**;
- исходный код приложения;
- `install-offline.sh` — установщик без обращения к сети.

## Что должно быть на офлайн-хосте

Установщик не скачивает системные пакеты. Заранее подготовьте:

- Debian / Ubuntu / Kali Linux, x86_64;
- `python3.12`, `python3.12-venv` (или пакет `python3-venv`);
- `nmap`;
- `nuclei` и шаблоны — если нужен модуль nuclei;
- Java + OWASP ZAP (`zap.sh`) — если нужен модуль ZAP.

`nuclei` и ZAP не входят в репозиторий из-за размера. Их бинарники/архивы
можно перенести на офлайн-хост отдельно (флешка, внутренний файл-сервер).

## Установка из скачанного репозитория

```bash
tar xzf asm-sentinel-1.1.0.tar.gz
cd asm-sentinel-1.1.0

# вариант 1: сервис от пользователя asm
sudo ./install-offline.sh

# вариант 2: сервис от root (нужен для nmap SYN-скана)
sudo ./install-offline.sh --root
```

Полезные флаги:

```bash
sudo ./install-offline.sh --root --port 8000
sudo ./install-offline.sh --no-zap
sudo ./install-offline.sh --no-nuclei
```

Установщик:

1. проверит `python3`, `nmap`, наличие `vendor/wheels`;
2. создаст venv и поставит Python-зависимости с `--no-index`;
3. создаст `/etc/asm-sentinel/asm-sentinel.env`;
4. зарегистрирует и запустит systemd-сервис `asm-sentinel`;
5. выведет логин, пароль и адрес интерфейса.

## Если nuclei-шаблонов нет

Скопируйте каталог `nuclei-templates` на сервер:

```bash
sudo mkdir -p /opt/asm-sentinel/data/nuclei-templates
sudo cp -a /path/to/nuclei-templates/. /opt/asm-sentinel/data/nuclei-templates/
sudo systemctl restart asm-sentinel
```

Либо задайте путь в `asm-sentinel.env`:

```ini
ASM_NUCLEI_TEMPLATES=/path/to/nuclei-templates
```

## Если ZAP установлен в нестандартный каталог

Добавьте в `/etc/asm-sentinel/asm-sentinel.env`:

```ini
ASM_ZAP_HOME=/path/to/zaproxy
```

и перезапустите сервис:

```bash
sudo systemctl restart asm-sentinel
```

## Ручная установка без systemd

```bash
python3.12 -m venv .venv
.venv/bin/pip install --no-index --find-links vendor/wheels -r requirements.txt

ASM_DATA_DIR="$PWD/data" \
ASM_ADMIN_PASSWORD='change-me' \
ASM_ZAP_HOME=/usr/share/zaproxy \
.venv/bin/python run.py
```

Интерфейс: `http://127.0.0.1:8000`.

## Другая версия Python или архитектура

Колёса в `vendor/wheels` собраны под CPython 3.12 / Linux x86_64. Для другой
платформы скачайте колёса на машине с интернетом, где установлена нужная
версия Python:

```bash
pip download -r requirements.txt -d vendor/wheels --only-binary=:all:
```

Затем перенесите обновлённый `vendor/wheels` на офлайн-хост.

## Проверка после установки

```bash
systemctl status asm-sentinel
curl http://127.0.0.1:8000/healthz
journalctl -u asm-sentinel -n 50 --no-pager
```
