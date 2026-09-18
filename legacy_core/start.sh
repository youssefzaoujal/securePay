#!/bin/sh
set -e
python -m legacy_core.certs
CERTS="${LEGACY_CERTS_DIR:-/certs}"
if [ "$(id -u)" = "0" ]; then
  chown -R 1000:1000 "$CERTS" 2>/dev/null || true
fi
export LEGACY_COBOL_BIN="${LEGACY_COBOL_BIN:-/app/legacy_core/bin/validate}"
if [ "${LEGACY_CORE_TLS:-1}" = "1" ]; then
  UVICORN_SSL="--ssl-certfile ${CERTS}/server.crt --ssl-keyfile ${CERTS}/server.key --ssl-ca-certs ${CERTS}/ca.crt --ssl-cert-reqs 2"
else
  UVICORN_SSL=""
fi
# shellcheck disable=SC2086
if [ "$(id -u)" = "0" ] && command -v setpriv >/dev/null 2>&1; then
  exec setpriv --reuid=1000 --regid=1000 --init-groups \
    uvicorn legacy_core.wrapper:app --host 0.0.0.0 --port 8004 $UVICORN_SSL
fi
# shellcheck disable=SC2086
exec uvicorn legacy_core.wrapper:app --host 0.0.0.0 --port 8004 $UVICORN_SSL
