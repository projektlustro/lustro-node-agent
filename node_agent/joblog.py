"""Append-only job log — radical inspectability.

Every job the agent processes is appended as one JSON line to a local file the
volunteer can read at any time. Nothing is hidden; this is the audit trail the
volunteer owns.
"""

import json
import os
import time
from pathlib import Path

DEFAULT_JOBLOG_PATH = Path.home() / ".lustro-node-agent" / "joblog.jsonl"


class JobLog:
    def __init__(self, path: Path | str = DEFAULT_JOBLOG_PATH) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self._path.parent, 0o700)

    @property
    def path(self) -> Path:
        return self._path

    def append(self, entry: dict) -> None:
        record = {"ts": time.time(), **entry}
        existed = self._path.exists()
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        if not existed:
            os.chmod(self._path, 0o600)

    def read_all(self) -> list[dict]:
        if not self._path.exists():
            return []
        out = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out
