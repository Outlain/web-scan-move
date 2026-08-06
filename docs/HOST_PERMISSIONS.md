# Host permissions

The application and its ClamD sidecar default to UID/GID `10001:10001`. The
application needs read/write/search access to the three content roots and its own
event/state directories. The sidecar needs only read/search access to definitions
and write access to its private named socket volume.

```sh
sudo install -d -m 0750 -o 10001 -g 10001 \
  /opt/docker/clamav-shared/events/web-scan-move \
  /opt/docker/clamav-shared/state/web-scan-move \
  /opt/docker/clamav-shared/sockets/web-scan-move
```

The socket directory is bind-mounted at `/run/clamav` in both containers. It
must be writable by the configured UID/GID so ClamD can create `clamd.pid` and
the mode-`0600` `clamd.sock`; using the same identity lets the application open
that private socket. If a different deployment identity is selected, replace
`10001:10001` consistently for both containers and all three directories.

Only remove stale `clamd.pid` or `clamd.sock` while both web-scan-move
containers are stopped.

Use existing ownership or ACL policy to grant that identity access to:

- `/mnt/bulk/webdownloads/complete`
- `/mnt/bulk/webdownloads/quarantine`
- `/mnt/media/WebsiteDownloads`

The sidecar mounts `/opt/docker/clamav-shared/defs` read-only. The application
does not mount definitions, and the sidecar never mounts watch, destination, or
quarantine content. Do not recursively change ownership of the broader media
tree just for this service.
