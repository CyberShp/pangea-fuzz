from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from .case_generator import FuzzCase
from .mini_yaml import dump_json_yaml


@dataclass(frozen=True)
class PduTraceEntry:
    direction: str
    ordinal: int
    pdu_type: str
    command_id: int | None = None
    queue_id: int | None = None
    data_length: int | None = None
    data_offset: int | None = None
    mutation: dict[str, Any] = field(default_factory=dict)


class ArtifactWriter:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.run_dir: Path | None = None

    def start_run(self, case: FuzzCase) -> Path:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.run_dir = self.root / f"{timestamp}-seed-{case.seed}"
        self.run_dir.mkdir(parents=True, exist_ok=False)
        self.write_yaml("case.yaml", case.to_dict())
        return self.run_dir

    def append_pdu_trace(self, entry: PduTraceEntry) -> None:
        run_dir = self._require_run()
        with (run_dir / "pdu-trace.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(entry), sort_keys=True) + "\n")

    def write_summary(self, summary: dict[str, Any]) -> None:
        self.write_json("summary.json", summary)

    def write_json(self, name: str, data: dict[str, Any]) -> Path:
        run_dir = self._require_run()
        path = run_dir / name
        path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def write_yaml(self, name: str, data: dict[str, Any]) -> Path:
        run_dir = self._require_run()
        path = run_dir / name
        path.write_text(dump_json_yaml(data), encoding="utf-8")
        return path

    def write_text(self, name: str, text: str) -> Path:
        run_dir = self._require_run()
        path = run_dir / name
        path.write_text(text, encoding="utf-8", errors="replace")
        return path

    def _require_run(self) -> Path:
        if self.run_dir is None:
            raise RuntimeError("start_run() must be called before writing artifacts")
        return self.run_dir
