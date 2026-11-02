FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    ASM_DATA_DIR=/data \
    ASM_ZAP_HOME=/opt/ZAP_2.17.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap default-jre-headless curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG NUCLEI_VERSION=3.11.0
RUN curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
        -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -f /tmp/nuclei.zip

ARG ZAP_VERSION=2.17.0
RUN curl -fsSL "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
        -o /tmp/zap.tgz \
    && tar xzf /tmp/zap.tgz -C /opt \
    && rm -f /tmp/zap.tgz

RUN nuclei -update-templates -duc

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

VOLUME ["/data"]
EXPOSE 8000
CMD ["python3", "run.py"]
