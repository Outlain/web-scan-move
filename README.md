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

They share only the dedicated host directory configured by
`WEB_CLAMD_SOCKET_HOST_DIR`. The socket is mode `0600`, the directory is mode
`0750`, and both processes use the same numeric UID/GID. A bind mount avoids
Docker initializing a named volume with the image's built-in UID when a different
deployment UID is selected. There is no TCP scanner listener, Docker socket, or
FreshClam process. ClamD checks the shared read-only definition
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
- prefers Linux `renameat2(RENAME_NOREPLACE)` and chooses a suffix on collision;
  when NFS explicitly reports that flag unsupported, directory publication is
  serialized and uses the standard same-filesystem rename supported by NFS;
- copies cross-filesystem content to a hidden exclusive temporary path, securely
  rejects tree changes, verifies the portable tree fingerprint, then atomically
  publishes it;
- journals cross-filesystem publication under `/state`, allowing a restart to
  remove an unpublished partial or finish deletion only when inode ownership
  proves that the completed destination belongs to that move;
- leaves scan and promotion failures in `/watch` for retry.

Files at or below `MAX_STREAM_MIB` keep the normal native ClamD path. Larger
files are never skipped. Genuine video containers are verified by `ffprobe`,
must contain a video stream, and are read completely through overlapping ClamD
windows. The result is labeled `large_media_full_byte_windows` because it is not
equivalent to one native whole-file ClamAV parser invocation.

ZIP is the one archive format with a dedicated policy here because `/watch` is
the deliberate/manual web-download boundary. Every detected ZIP, small or
large, uses this route. It is not unpacked onto disk. Each regular entry is
decompressed directly into ClamD and discarded, with hard
limits on source size, total actual expanded bytes, entry count, per-entry size,
compression ratio, central-directory metadata (fixed at 64 MiB), and elapsed
time. Encrypted entries, symlinks, special files,
nested archives, unsupported compression, CRC/parser failures, and any reached
limit leave the original ZIP untouched in `/watch`. This avoids needing a large
scratch mount and prevents a ZIP bomb from filling local storage. RAR, 7z, ISO,
disk images, unknown oversized content, and oversized individual ZIP entries are
held rather than guessed clean.

Detections are durably spooled before quarantine. Events include
`threat_detected`, `infected_content_quarantined`, `quarantine_failed`,
`scan_failed`, `promotion_failed`, `mount_unavailable`, and
`service_recovered`. `/events` is consumed by `clamav-notifier`; this service
does not send Telegram directly.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `HELPER_UID`, `HELPER_GID` | `10001` | shared numeric identity for the app, sidecar, and writable host paths |
| `POLL_SECONDS` | `5` | directory poll interval |
| `SETTLE_SECONDS` | `30` | unchanged time before scan |
| `MOVE_FAILURE_RETRY_SECONDS` | `300` | delay before rescanning an unchanged item after promotion or quarantine failure |
| `MAX_SCAN_WORKERS` | `1` | simultaneous item scans (hard cap: 8) |
| `DISCOVERY_WORKERS` | `4` | simultaneous fingerprint walks (hard cap: 16) |
| `DISCOVERY_QUEUE` | `64` | maximum queued fingerprint tasks (hard cap: 4096) |
| `CLAMD_CONNECT_TIMEOUT_SECONDS` | `5` | socket connect timeout |
| `SCAN_TIMEOUT_SECONDS` | `7200` | per-file socket reply timeout |
| `MAX_STREAM_MIB` | `2000` | native ClamD routing boundary (hard cap: 2000 MiB) |
| `LARGE_MEDIA_ENABLED` | `true` | enable verified oversized-video routing |
| `LARGE_MEDIA_MAX_FILE_GIB` | `100` | maximum individual video handled by the large-media route |
| `LARGE_MEDIA_CHUNK_MIB` | `1024` | independent ClamD window size |
| `LARGE_MEDIA_OVERLAP_KIB` | `1024` | repeated bytes across neighboring windows |
| `LARGE_MEDIA_PROBE_TIMEOUT_SECONDS` | `120` | ffprobe validation deadline |
| `LARGE_MEDIA_SCAN_TIMEOUT_SECONDS` | `21600` | whole large-video deadline |
| `ARCHIVE_SCAN_ENABLED` | `true` | enable bounded ZIP entry streaming |
| `ARCHIVE_MAX_SOURCE_GIB` | `100` | maximum ZIP file size |
| `ARCHIVE_MAX_TOTAL_GIB` | `50` | maximum actual decompressed bytes across entries |
| `ARCHIVE_MAX_ENTRIES` | `10000` | maximum ZIP entry count |
| `ARCHIVE_MAX_COMPRESSION_RATIO` | `200` | per-entry bomb protection |
| `ARCHIVE_SCAN_TIMEOUT_SECONDS` | `21600` | whole bounded ZIP deadline |
| `MAX_DEFINITION_AGE_SECONDS` | `172800` | ClamD freshness gate |
| `INCOMPLETE_SUFFIXES` | browser/download suffix list | names that remain unsettled |
| `*_MOUNT_MARKER` | empty | optional marker name relative to each root |
| `WEB_CLAMD_SOCKET_HOST_DIR` | `/opt/docker/clamav-shared/sockets/web-scan-move` | private host socket directory shared only with the sidecar |

A file that cannot complete its applicable native, large-media, or bounded-ZIP
policy is a distinct scan-policy failure. The whole top-level item stays in
`/watch`, a `scan_failed` event with `failure_kind=scan_policy_limit` is emitted,
and nothing is promoted or quarantined as malware. Filename extensions never
bypass content validation.

## NFS publication

Cross-filesystem moves are copied to a hidden
`.web-scan-move-partial-<random-id>` entry inside the target root, verified, and
then published under the final name. Filesystems supporting
`RENAME_NOREPLACE` receive the strongest atomic no-overwrite operation. NFS
servers commonly return `EOPNOTSUPP` (errno 95) for that flag even though they
support ordinary rename. In that case the service automatically rechecks the
destination, serializes directory publication between its workers, and uses
the standard NFS-compatible rename. Existing names are preserved and the next
available suffix is selected.

The hidden entry may be visible while a cross-filesystem copy is running. It
should become the final item after verification; the move journal lets restart
recovery distinguish a published item from an incomplete copy. Run one
`web-scan-move` application replica for a given `/watch`, `/dest`, `/quarantine`,
and `/state` set; `MAX_SCAN_WORKERS` provides bounded concurrency inside that
replica.

Internal paths are `/watch`, `/dest`, `/quarantine`, `/events`, `/state`, and
`/run/clamav/clamd.sock`. See `.env.example` and
`docker-compose.example.yml`. The example maps the requested host paths and
stores events/state under `/opt/docker/clamav-shared`.

Prepare the writable operational directories with the same identity configured
by `HELPER_UID`/`HELPER_GID` (default `10001:10001`):

```sh
sudo install -d -m 0750 -o 10001 -g 10001 \
  /opt/docker/clamav-shared/events/web-scan-move \
  /opt/docker/clamav-shared/state/web-scan-move \
  /opt/docker/clamav-shared/sockets/web-scan-move
```

The socket directory is runtime-only. Remove stale `clamd.sock` and `clamd.pid`
files only while both web-scan-move containers are stopped.

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
python3 -m py_compile web_scan_move.py clamd_client.py content_scanner.py event_writer.py safe_move.py clamav/*.py
docker compose -f docker-compose.example.yml config --quiet
docker build -t web-scan-move:test .
docker build -f Dockerfile.clamd -t web-scan-move-clamd:test .
```

Tests cover clean promotion, EICAR threat parsing, definition freshness, malformed
and limit responses, overlapping large-media byte coverage, bounded ZIP entry
streaming, ZIP-bomb and nested-archive rejection, newline names, file replacement,
symlink/special rejection, quarantine collisions, infected folders, target
races, durable events, and cross-filesystem crash recovery. GitHub Actions
publishes both images for `linux/amd64` and `linux/arm64`.
