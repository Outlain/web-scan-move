FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ARG PYTHON_PACKAGE_VERSION=3.14.5-r0

RUN apk upgrade --no-cache \
    && apk add --no-cache "python3=${PYTHON_PACKAGE_VERSION}" ffmpeg \
    && ffprobe -version >/dev/null \
    && addgroup -S -g 10001 web-scan-move \
    && adduser -S -D -u 10001 -G web-scan-move -h /home/web-scan-move web-scan-move \
    && install -d -o 10001 -g 10001 -m 0750 \
        /home/web-scan-move /watch /dest /quarantine /events /state /run/clamav

COPY web_scan_move.py clamd_client.py content_scanner.py event_writer.py safe_move.py /usr/local/bin/
RUN chmod 0555 /usr/local/bin/web_scan_move.py \
    /usr/local/bin/clamd_client.py \
    /usr/local/bin/content_scanner.py \
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
    MOVE_FAILURE_RETRY_SECONDS=300 \
    MAX_SCAN_WORKERS=1 \
    DISCOVERY_WORKERS=4 \
    DISCOVERY_QUEUE=64 \
    MAX_DEFINITION_AGE_SECONDS=172800 \
    SCAN_TIMEOUT_SECONDS=7200 \
    MAX_STREAM_MIB=2000 \
    LARGE_MEDIA_ENABLED=true \
    LARGE_MEDIA_MAX_FILE_GIB=100 \
    LARGE_MEDIA_CHUNK_MIB=1024 \
    LARGE_MEDIA_OVERLAP_KIB=1024 \
    LARGE_MEDIA_PROBE_TIMEOUT_SECONDS=120 \
    LARGE_MEDIA_SCAN_TIMEOUT_SECONDS=21600 \
    ARCHIVE_SCAN_ENABLED=true \
    ARCHIVE_MAX_SOURCE_GIB=100 \
    ARCHIVE_MAX_TOTAL_GIB=50 \
    ARCHIVE_MAX_ENTRIES=10000 \
    ARCHIVE_MAX_COMPRESSION_RATIO=200 \
    ARCHIVE_SCAN_TIMEOUT_SECONDS=21600 \
    HOME=/home/web-scan-move \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=1m --timeout=15s --start-period=5m --retries=3 \
    CMD ["python3", "/usr/local/bin/web_scan_move.py", "--healthcheck"]

CMD ["python3", "/usr/local/bin/web_scan_move.py"]
