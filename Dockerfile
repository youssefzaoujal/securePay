# =============================================================================
# Multi-stage Dockerfile — SecurePay (non-root, least privilege)
# =============================================================================

FROM python:3.14-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    APP_ENV=lab

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -g 1000 securepay && \
    useradd -m -u 1000 -g 1000 securepay

COPY pyproject.toml ./
COPY shared ./shared
COPY gateway ./gateway
COPY payment ./payment
COPY tokenization ./tokenization
COPY fraud ./fraud
COPY detection ./detection
COPY legacy_core ./legacy_core
COPY atm ./atm
COPY three_ds ./three_ds
COPY directory_server ./directory_server
COPY acs_simulator ./acs_simulator
COPY legacy_3ds1 ./legacy_3ds1
COPY network_token ./network_token
COPY openbanking ./openbanking
COPY iso20022 ./iso20022
COPY hsm ./hsm
COPY config.py logging_config.py models.py database.py ./

RUN pip install --no-cache-dir . && \
    pip install --no-cache-dir scikit-learn joblib numpy pyyaml

RUN mkdir -p /app/logs /tmp/securepay && chown -R securepay:securepay /app
USER 1000:1000

# --- Gateway ---
FROM base AS gateway
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s CMD curl -f http://127.0.0.1:8000/health || exit 1
CMD ["uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM base AS payment
EXPOSE 8001
CMD ["uvicorn", "payment.main:app", "--host", "0.0.0.0", "--port", "8001"]

FROM base AS tokenization
EXPOSE 8002
CMD ["uvicorn", "tokenization.main:app", "--host", "0.0.0.0", "--port", "8002"]

FROM base AS fraud
EXPOSE 8003
CMD ["uvicorn", "fraud.main:app", "--host", "0.0.0.0", "--port", "8003"]

FROM base AS three-ds-server
EXPOSE 8020
CMD ["uvicorn", "three_ds.main:app", "--host", "0.0.0.0", "--port", "8020"]

FROM base AS directory-server
EXPOSE 8021
CMD ["uvicorn", "directory_server.main:app", "--host", "0.0.0.0", "--port", "8021"]

FROM base AS acs-simulator
EXPOSE 8022
CMD ["uvicorn", "acs_simulator.main:app", "--host", "0.0.0.0", "--port", "8022"]

FROM base AS legacy-3ds1
EXPOSE 8023
CMD ["uvicorn", "legacy_3ds1.main:app", "--host", "0.0.0.0", "--port", "8023"]

FROM base AS detection
EXPOSE 8010
CMD ["uvicorn", "detection.engine.main:app", "--host", "0.0.0.0", "--port", "8010"]

FROM base AS atm-adapter
EXPOSE 8016
HEALTHCHECK --interval=15s --timeout=3s CMD curl -f http://127.0.0.1:8016/health || exit 1
CMD ["uvicorn", "atm.adapter:app", "--host", "0.0.0.0", "--port", "8016"]

FROM base AS commandcenter
COPY dashboard.py ./
EXPOSE 9000
CMD ["uvicorn", "dashboard:app", "--host", "0.0.0.0", "--port", "9000"]

# --- Core banking simulator (GnuCOBOL) ---
FROM python:3.14-slim-bookworm AS legacy-core
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    APP_ENV=lab \
    LEGACY_COBOL_BIN=/app/legacy_core/bin/validate \
    LEGACY_CERTS_DIR=/certs \
    LEGACY_CORE_TLS=1
WORKDIR /app
RUN apt-get update && \
    apt-get install -y --no-install-recommends gnucobol gcc curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -g 1000 securepay && \
    useradd -m -u 1000 -g 1000 securepay
COPY pyproject.toml ./
COPY shared ./shared
COPY gateway ./gateway
COPY payment ./payment
COPY tokenization ./tokenization
COPY fraud ./fraud
COPY detection ./detection
COPY config.py logging_config.py models.py database.py ./
COPY legacy_core ./legacy_core
RUN pip install --no-cache-dir . && \
    mkdir -p /app/legacy_core/bin /certs /app/logs && \
    cobc -x -free -o /app/legacy_core/bin/validate /app/legacy_core/cobol/VALIDATE.cob && \
    chmod +x /app/legacy_core/start.sh && \
    chown -R securepay:securepay /app /certs
USER root
EXPOSE 8004
HEALTHCHECK --interval=10s --timeout=5s --retries=8 CMD python -c "import os,ssl,urllib.request; d=os.environ.get('LEGACY_CERTS_DIR','/certs'); ctx=ssl.create_default_context(cafile=d+'/ca.crt'); ctx.load_cert_chain(d+'/payment-client.crt', d+'/payment-client.key'); urllib.request.urlopen('https://127.0.0.1:8004/health', context=ctx, timeout=3)"
CMD ["/app/legacy_core/start.sh"]

