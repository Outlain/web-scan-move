# Host permissions

The application and its ClamD sidecar default to UID/GID `10001:10001`. The
application needs read/write/search access to the three content roots and its own
event/state directories. The sidecar needs only read/search access to definitions
and write access to its private named socket volume.

```sh
sudo install -d -m 0750 -o 10001 -g 10001 \
  /opt/docker/clamav-shared/events/web-scan-move \
  /opt/docker/clamav-shared/state/web-scan-move
```

Use existing ownership or ACL policy to grant that identity access to:

- `/mnt/bulk/webdownloads/complete`
- `/mnt/bulk/webdownloads/quarantine`
- `/mnt/media/WebsiteDownloads`

The sidecar mounts `/opt/docker/clamav-shared/defs` read-only. The application
does not mount definitions, and the sidecar never mounts watch, destination, or
quarantine content. Do not recursively change ownership of the broader media
tree just for this service.
