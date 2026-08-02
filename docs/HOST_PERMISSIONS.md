# Host permissions

The image defaults to UID/GID `10001:10001` and needs read/write/search access to:

- `/mnt/bulk/webdownloads/complete`
- `/mnt/bulk/webdownloads/quarantine`
- `/mnt/media/WebsiteDownloads`

It needs read/search access to:

- `/mnt/media/docker/clamav/defs`

Use ACLs when the downloader or SMB service uses another account. The definitions mount should remain read-only in this container.
