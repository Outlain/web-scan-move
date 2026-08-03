# Integration

Deploy `clamav-defs-updater` first. `web-scan-move-clamd` mounts
`/opt/docker/clamav-shared/defs:/var/lib/clamav:ro`, waits for complete fresh
definitions, then creates a mode-`0600` socket in the named
`web-clamav-socket` volume. Compose starts the application after the sidecar is
healthy.

The application writes schema-v1 files to
`/opt/docker/clamav-shared/events/web-scan-move`. `clamav-notifier` mounts the
parent event directory and owns all Telegram delivery. No human log is used as
an event queue.

The host watch, quarantine, and destination mounts intentionally remain:

```yaml
- /mnt/bulk/webdownloads/complete:/watch:rw
- /mnt/bulk/webdownloads/quarantine:/quarantine:rw
- /mnt/media/WebsiteDownloads:/dest:rw
```

Optional marker names can detect a mount that has fallen back to an empty local
directory. Place the configured marker inside its corresponding host root before
enabling it.
