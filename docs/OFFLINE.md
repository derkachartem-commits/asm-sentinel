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

## Как скачать и установить системные зависимости

Все команды ниже выполняются на машине с интернетом и той же архитектурой
(`uname -m`), затем файлы переносятся на офлайн-хост. Для x86_64 используйте
`amd64`, для ARM — `arm64`.

### nmap (Debian / Ubuntu / Kali)

На онлайн-машине с той же версией ОС:

```bash
sudo apt-get update
sudo apt-get install -y nmap
nmap --version
```

Если на офлайн-хосте nmap ещё нет, скачайте пакеты на онлайн-машине:

```bash
mkdir -p ~/asm-offline/nmap-deb
cd ~/asm-offline/nmap-deb
sudo apt-get install -y --download-only nmap
sudo cp /var/cache/apt/archives/*.deb ./
```

Перенесите каталог `nmap-deb` на офлайн-хост и установите:

```bash
sudo dpkg -i /media/usb/nmap-deb/*.deb
sudo apt-get -f install   # если есть локальные зависимости в том же каталоге
nmap --version
```

### nuclei + шаблоны

Скачайте бинарник с GitHub Releases (подставьте нужную версию и архитектуру):

```bash
NUCLEI_VERSION=3.11.0
curl -fsSL -o nuclei.zip \
  "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
unzip nuclei.zip nuclei
sudo install -m 0755 nuclei /usr/local/bin/nuclei
nuclei -version
```

Шаблоны проще обновить на онлайн-машине и перенести архивом:

```bash
nuclei -update-templates
tar czf nuclei-templates.tgz -C "$HOME" nuclei-templates
```

На офлайн-хосте:

```bash
sudo mkdir -p /opt/asm-sentinel/data/nuclei-templates
sudo tar xzf /media/usb/nuclei-templates.tgz \
  -C /opt/asm-sentinel/data/nuclei-templates --strip-components=1
sudo systemctl restart asm-sentinel
```

Либо укажите свой путь в `/etc/asm-sentinel/asm-sentinel.env`:

```ini
ASM_NUCLEI_TEMPLATES=/path/to/nuclei-templates
```

### Java (для ZAP)

```bash
sudo apt-get install -y default-jre-headless
java -version
```

Для офлайна скачайте пакеты так же, как для nmap:

```bash
mkdir -p ~/asm-offline/java-deb
cd ~/asm-offline/java-deb
sudo apt-get install -y --download-only default-jre-headless
sudo cp /var/cache/apt/archives/*.deb ./
```

На офлайн-хосте: `sudo dpkg -i /media/usb/java-deb/*.deb`.

### OWASP ZAP

Скачайте Linux-архив ZAP (версия должна совпадать с `ZAP_VERSION` в
`install.sh`, по умолчанию 2.17.0):

```bash
ZAP_VERSION=2.17.0
curl -fsSL -o ZAP.tar.gz \
  "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz"
tar -xzf ZAP.tar.gz -C /opt
/opt/ZAP_${ZAP_VERSION}/zap.sh -version
```

Перенесите `ZAP.tar.gz` на офлайн-хост и распакуйте:

```bash
sudo tar -xzf /media/usb/ZAP.tar.gz -C /opt
sudo /opt/ZAP_2.17.0/zap.sh -version
```

Если ZAP установлен в другой каталог, укажите путь в конфиге:

```ini
ASM_ZAP_HOME=/opt/ZAP_2.17.0
```

Если ZAP или nuclei не нужны, запускайте установщик с флагами
`--no-zap` / `--no-nuclei`.

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
