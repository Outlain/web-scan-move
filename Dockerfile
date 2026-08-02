FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ARG CLAMAV_PACKAGE_VERSION=1.4.5-r0

RUN apk upgrade --no-cache \
    && apk add --no-cache "clamav=${CLAMAV_PACKAGE_VERSION}" python3 \
    && clamscan --version | grep -Eq '^ClamAV 1\.4\.5($|/)' \
    && addgroup -S -g 10001 clamav-helper \
    && adduser -S -D -u 10001 -G clamav-helper -h /home/clamav-helper clamav-helper \
    && install -d -o 10001 -g 10001 -m 0750 /home/clamav-helper /watch /dest /quarantine

COPY web_scan_move.py /usr/local/bin/web_scan_move.py
RUN chmod 0555 /usr/local/bin/web_scan_move.py

ENV WATCH_DIR=/watch \
    DEST_DIR=/dest \
    QUARANTINE_DIR=/quarantine \
    DEFINITIONS_DIR=/var/lib/clamav \
    POLL_SECONDS=5 \
    SETTLE_SECONDS=30 \
    MAX_SCAN_WORKERS=1 \
    MAX_DEFINITION_AGE_SECONDS=172800 \
    SCAN_TIMEOUT_SECONDS=7200 \
    HOME=/home/clamav-helper \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=1m --timeout=15s --start-period=5m --retries=3 \
    CMD ["python3", "/usr/local/bin/web_scan_move.py", "--healthcheck"]

CMD ["python3", "/usr/local/bin/web_scan_move.py"]
