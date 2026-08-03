# web-scan-move

Dockerized intake for completed web downloads. It polls `/watch`, waits for a
stable top-level file or folder, scans every regular file through a persistent
private ClamD socket, then moves the whole clean item to `/dest` or the whole
infected item to `/quarantine`.

## Containers

The repository publishes two images:

- `web-scan-move`: standard-library Python discovery, event, and safe-move logic;
  it has no ClamAV package and no network access.
- `web-scan-move-clamd`: resident ClamD with read-only shared definitions, no
  content mount, and `network_mode: none`.

They share only a Compose-managed Unix-socket volume. The socket is mode `0600`
and both processes use the same numeric UID/GID. There is no TCP scanner listener,
Docker socket, or FreshClam process. ClamD checks the shared read-only definition
directory every 300 seconds. It writes to container stderr, so Docker's configured
log rotation covers daemon messages.

## Workflow and safety

Polling deliberately recovers items already present after a restart and does not
trust one inotify event. Fingerprint discovery uses a separate bounded pool with
at least two workers, so walking one long download does not stop observation of
other top-level items. A scan starts only after two matching fingerprints have
remained unchanged for `SETTLE_SECONDS`.

The service:

- rejects symlinks, FIFOs, devices, sockets, and incomplete-file suffixes;
- opens files with `O_NOFOLLOW`, streams the opened descriptor with ClamD
  `INSTREAM`, and verifies device, inode, size, mtime, and ctime afterward;
- treats malformed replies, parser errors, engine errors, and scan/stream limits
  as failures, never as clean;
- re-fingerprints the complete item and verifies watch/destination/quarantine
  mount identities and optional marker identities before moving;
- sends infected folders to quarantine, not the clean destination;
- uses Linux `renameat2(RENAME_NOREPLACE)` and chooses a suffix on collision, so
  an existing clean or quarantine item is never overwritten;
- copies cross-filesystem content to a hidden exclusive temporary path, securely
  rejects tree changes, verifies the portable tree fingerprint, then atomically
  publishes it;
- journals cross-filesystem publication under `/state`, allowing a restart to
  remove an unpublished partial or finish deletion only when inode ownership
  proves that the completed destination belongs to that move;
- leaves scan and promotion failures in `/watch` for retry.

Detections are durably spooled before quarantine. Events include
`threat_detected`, `infected_content_quarantined`, `quarantine_failed`,
`scan_failed`, `promotion_failed`, `mount_unavailable`, and
`service_recovered`. `/events` is consumed by `clamav-notifier`; this service
does not send Telegram directly.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `POLL_SECONDS` | `5` | directory poll interval |
| `SETTLE_SECONDS` | `30` | unchanged time before scan |
| `MAX_SCAN_WORKERS` | `1` | simultaneous item scans (hard cap: 8) |
| `DISCOVERY_WORKERS` | `4` | simultaneous fingerprint walks (hard cap: 16) |
| `DISCOVERY_QUEUE` | `64` | maximum queued fingerprint tasks (hard cap: 4096) |
| `CLAMD_CONNECT_TIMEOUT_SECONDS` | `5` | socket connect timeout |
| `SCAN_TIMEOUT_SECONDS` | `7200` | per-file socket reply timeout |
| `MAX_STREAM_MIB` | `2000` | fail-closed per-file stream bound (hard cap: 2000 MiB) |
| `MAX_DEFINITION_AGE_SECONDS` | `172800` | ClamD freshness gate |
| `INCOMPLETE_SUFFIXES` | browser/download suffix list | names that remain unsettled |
| `*_MOUNT_MARKER` | empty | optional marker name relative to each root |

Internal paths are `/watch`, `/dest`, `/quarantine`, `/events`, `/state`, and
`/run/clamav/clamd.sock`. See `.env.example` and
`docker-compose.example.yml`. The example maps the requested host paths and
stores events/state under `/opt/docker/clamav-shared`.

```sh
cp .env.example .env
docker compose -f docker-compose.example.yml up -d
docker compose -f docker-compose.example.yml ps
```

Both containers run non-root with read-only root filesystems, dropped
capabilities, no-new-privileges, bounded PIDs/CPU/memory/open files, bounded
Docker logs, and tmpfs scratch space. ClamD needs the larger tmpfs and memory
limit for archive extraction and database reload.

## Validation and publishing

```sh
python3 -m unittest discover -s tests -v
python3 -m py_compile web_scan_move.py clamd_client.py event_writer.py safe_move.py clamav/*.py
docker compose -f docker-compose.example.yml config --quiet
docker build -t web-scan-move:test .
docker build -f Dockerfile.clamd -t web-scan-move-clamd:test .
```

Tests cover clean promotion, EICAR threat parsing, definition freshness, malformed
and limit responses, newline names, file replacement, symlink/special rejection,
quarantine collisions, infected folders, target races, durable events, and
cross-filesystem crash recovery. GitHub Actions publishes both images for
`linux/amd64` and `linux/arm64`.
