from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from .mini_yaml import dump_json_yaml


@dataclass(frozen=True)
class KvTraceEntry:
    stage: str
    ordinal: int
    operation: str
    field: str
    strategy: str
    detail: dict[str, Any] = field(default_factory=dict)


class ArtifactWriter:
    def __init__(self, root: str | Path, run_id: str | None = None):
        self.root = Path(root)
        self.run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.run_root = self.root / self.run_id
        self.case_dir: Path | None = None

    def start_case(self, case: dict[str, Any]) -> Path:
        index = case.get("campaign_index", "single")
        seed = case.get("seed", "unknown")
        self.case_dir = self.run_root / f"case-{index}-seed-{seed}"
        self.case_dir.mkdir(parents=True, exist_ok=False)
        self.write_yaml("case.yaml", case)
        return self.case_dir

    def append_trace(self, entry: KvTraceEntry) -> None:
        path = self._require_case_dir() / "kv-trace.jsonl"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(entry), ensure_ascii=False, sort_keys=True) + "\n")

    def write_json(self, name: str, data: dict[str, Any]) -> Path:
        path = self._require_case_dir() / name
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        return path

    def write_yaml(self, name: str, data: dict[str, Any]) -> Path:
        path = self._require_case_dir() / name
        path.write_text(dump_json_yaml(data), encoding="utf-8")
        return path

    def write_text(self, name: str, text: str | bytes | None) -> Path:
        if text is None:
            text = ""
        if isinstance(text, bytes):
            text = text.decode("utf-8", errors="replace")
        path = self._require_case_dir() / name
        path.write_text(text, encoding="utf-8", errors="replace")
        return path

    def write_bytes(self, name: str, data: bytes) -> Path:
        path = self._require_case_dir() / name
        path.write_bytes(data)
        return path

    def _require_case_dir(self) -> Path:
        if self.case_dir is None:
            raise RuntimeError("start_case() must be called before writing artifacts")
        return self.case_dir
