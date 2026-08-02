# web-scan-move

A standalone Docker intake scanner for completed website downloads.

This repository is intended to be uploaded by itself to a GitHub repository named `web-scan-move`.

## Workflow

1. Poll `/watch` for top-level files and directories.
2. Ignore known incomplete-download suffixes.
3. Require the complete item fingerprint to remain unchanged for the configured settle period.
4. Require complete, sufficiently current ClamAV definitions.
5. Run a fresh `clamscan` process.
6. Verify the item fingerprint is still unchanged after scanning.
7. Move clean content to `/dest`.
8. Move infected content to `/quarantine`.
9. Leave content in place on scanner errors, stale definitions, policy-limit detections, timeouts, unsafe paths, or failed moves.

The service also reconciles items that were already present before a container restart, so it does not depend entirely on receiving a filesystem event.

## Safety properties

- Refuses symbolic links and special files.
- Handles infected directories correctly.
- Never overwrites an existing destination name.
- Uses verified temporary copies for cross-filesystem moves.
- Detects changes during scan and refuses to move changed content.
- Treats ClamAV limit detections as scan-policy errors, not clean results.
- Publishes amd64 and arm64 images to GHCR through GitHub Actions.

## Deploy

1. Upload this entire folder to a new GitHub repository.
2. Keep the default branch named `main`.
3. Enable GitHub Actions and package publishing.
4. Copy `.env.example` to `.env` on the Docker host.
5. Adjust the four host paths and effective UID/GID.
6. Deploy `docker-compose.example.yml`.

The published image will be:

```text
ghcr.io/<github-owner>/web-scan-move:latest
```

## Local validation

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile web_scan_move.py
docker compose -f docker-compose.example.yml config --quiet
docker build -t web-scan-move:test .
```
