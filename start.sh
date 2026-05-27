#!/usr/bin/env bash
# ZIoCHub - Gunicorn launcher with automatic SSL detection
# If SSL cert+key exist in data/ssl/, gunicorn serves HTTPS.
# Otherwise falls back to plain HTTP.

set -euo pipefail

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT="${APP_DIR}/data/ssl/cert.pem"
KEY="${APP_DIR}/data/ssl/key.pem"
CA="${APP_DIR}/data/ssl/ca.pem"
PORT="${ZIOCHUB_PORT:-8443}"
WORKERS="${ZIOCHUB_WORKERS:-3}"
# Cortex/integration tests can block up to REQUEST_TIMEOUT_TEST_SEC (15s) per outbound call;
# default gunicorn worker timeout is 30s — too low and the UI sees HTML 500 instead of JSON.
TIMEOUT="${GUNICORN_TIMEOUT:-120}"

SSL_ARGS=""
if [[ -f "$CERT" && -f "$KEY" ]]; then
    SSL_ARGS="--certfile ${CERT} --keyfile ${KEY}"
    echo "[start] SSL certificates found - serving HTTPS on port ${PORT}"
else
    echo "[start] No SSL certificates - serving HTTP on port ${PORT}"
    echo "[start] Upload a certificate via Admin > Certificate to enable HTTPS"
fi

exec "${APP_DIR}/venv/bin/gunicorn" \
    --workers "${WORKERS}" \
    --bind "0.0.0.0:${PORT}" \
    --timeout "${TIMEOUT}" \
    ${SSL_ARGS} \
    --access-logfile - \
    --error-logfile - \
    app:app
