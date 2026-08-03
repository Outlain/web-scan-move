#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

from clamd_healthcheck import definitions_ready


def main() -> int:
    log_directory = Path("/tmp/clamav")
    log_directory.mkdir(mode=0o700, exist_ok=True)
    log_path = log_directory / "clamd.log"
    log_path.touch(mode=0o640, exist_ok=True)
    subprocess.Popen(["tail", "-n", "0", "-F", str(log_path)], close_fds=True)
    timeout = max(int(os.environ.get("DEFINITIONS_WAIT_TIMEOUT", "1800")), 1)
    deadline = time.monotonic() + timeout
    last_error = "definitions are not ready"
    while time.monotonic() < deadline:
        try:
            daily, age = definitions_ready()
            print(f"definitions ready: daily={daily.name} age={age}s", flush=True)
            os.execvp("clamd", ["clamd", "--config-file=/etc/clamav/clamd.conf"])
        except (OSError, RuntimeError) as exc:
            last_error = str(exc)
        time.sleep(min(2, max(0.1, deadline - time.monotonic())))
    print(f"definitions did not become ready within {timeout}s: {last_error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
