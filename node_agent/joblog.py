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
    def __init__(
        self, path: Path | str = DEFAULT_JOBLOG_PATH, create: bool = True
    ) -> None:
        self._path = Path(path)
        if create:
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
            rec = self._parse_line(line)
            if rec is not None:
                out.append(rec)
        return out

    def iter_lines(
        self,
        follow: bool = False,
        poll_interval: float = 1.0,
        since_end: bool = False,
    ):
        """Yield JSON-decoded records from the log.

        If ``follow`` is True, block and yield new records as they are appended.
        If ``since_end`` is True, skip content that existed before this call and
        only yield records appended after (used by the live SSE tail so a fresh
        connection doesn't replay the entire history). This only skips ahead
        when the file already existed: if the log doesn't exist yet, its first
        line is itself "new" relative to this call and must not be skipped.
        While waiting on an idle log, yields ``None`` on every poll as a
        caller-visible heartbeat. Malformed lines are surfaced as
        ``{"event": "_parse_error", "raw": line}`` so the dashboard never
        silently hides audit-trail corruption.
        """
        file_pre_existed = self._path.exists()
        if not file_pre_existed:
            if not follow:
                return
            while not self._path.exists():
                yield None
                time.sleep(poll_interval)
        with self._path.open("r", encoding="utf-8") as f:
            if since_end and file_pre_existed:
                f.seek(0, 2)
            else:
                for line in f:
                    rec = self._parse_line(line)
                    if rec is not None:
                        yield rec
            if not follow:
                return
            while True:
                line = f.readline()
                if line:
                    rec = self._parse_line(line)
                    if rec is not None:
                        yield rec
                else:
                    yield None
                    time.sleep(poll_interval)

    @staticmethod
    def _parse_line(line: str) -> dict | None:
        line = line.strip()
        if not line:
            return None
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return {"event": "_parse_error", "raw": line}
