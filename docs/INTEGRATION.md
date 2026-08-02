# Integration

The expected host workflow is an incomplete-to-complete download layout:

```text
/mnt/bulk/webdownloads/incomplete
/mnt/bulk/webdownloads/complete
/mnt/bulk/webdownloads/quarantine
```

Only the `complete` directory should be mounted at `/watch`. Your downloader should finish content elsewhere and then rename or move the completed top-level item into `complete`.

The scanner mounts the shared FreshClam database read-only and starts a new `clamscan` for each settled item. Each new process loads the currently available definitions.

Clean content is moved to `/mnt/media/WebsiteDownloads`; infected content is moved to the dedicated web-download quarantine directory.
