FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ARG PYTHON_PACKAGE_VERSION=3.14.5-r0

RUN apk upgrade --no-cache \
    && apk add --no-cache "python3=${PYTHON_PACKAGE_VERSION}" \
    && addgroup -S -g 10001 web-scan-move \
    && adduser -S -D -u 10001 -G web-scan-move -h /home/web-scan-move web-scan-move \
    && install -d -o 10001 -g 10001 -m 0750 \
        /home/web-scan-move /watch /dest /quarantine /events /state /run/clamav

COPY web_scan_move.py clamd_client.py event_writer.py safe_move.py /usr/local/bin/
RUN chmod 0555 /usr/local/bin/web_scan_move.py \
    /usr/local/bin/clamd_client.py \
    /usr/local/bin/event_writer.py \
    /usr/local/bin/safe_move.py

ENV WATCH_DIR=/watch \
    DEST_DIR=/dest \
    QUARANTINE_DIR=/quarantine \
    EVENT_DIR=/events \
    STATE_DIR=/state \
    CLAMD_SOCKET=/run/clamav/clamd.sock \
    POLL_SECONDS=5 \
    SETTLE_SECONDS=30 \
    MAX_SCAN_WORKERS=1 \
    DISCOVERY_WORKERS=4 \
    DISCOVERY_QUEUE=64 \
    MAX_DEFINITION_AGE_SECONDS=172800 \
    SCAN_TIMEOUT_SECONDS=7200 \
    MAX_STREAM_MIB=2000 \
    HOME=/home/web-scan-move \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=1m --timeout=15s --start-period=5m --retries=3 \
    CMD ["python3", "/usr/local/bin/web_scan_move.py", "--healthcheck"]

CMD ["python3", "/usr/local/bin/web_scan_move.py"]
