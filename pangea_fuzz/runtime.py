from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile


RUN_FILES = {
    "run-manifest.json",
    "run-summary.json",
    "case-ledger.jsonl",
    "events.jsonl",
    "progress.json",
    "index.json",
    "index.partial.json",
}
CORE_NAMES = {"case.yaml", "summary.json", "command.json", "packet.json"}
TRACE_NAMES = {"pdu-trace.jsonl", "kv-trace.jsonl", "packet-trace.jsonl"}
LOG_SUFFIXES = {".log", ".out", ".err"}
PAYLOAD_NAMES = {"payload.bin", "packet.bin"}
PCAP_SUFFIXES = {".pcap", ".pcapng"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def json_dumps(data: Any, *, pretty: bool = True) -> str:
    if pretty:
        return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True)
    return json.dumps(data, ensure_ascii=False, sort_keys=True)


def sha256_file(path: Path) -> str | None:
    if not path or not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


@dataclass
class RuntimeOptions:
    run_id: str | None = None
    artifact_budget_gb: float | None = None
    free_space_floor_gb: float | None = None
    progress_interval_s: float = 5.0
    quiet: bool = False
    no_compress: bool = False
    keep_pass_full: bool = False
    keep_pcap: str | None = None


@dataclass
class ArtifactPolicy:
    max_total_gb: float = 200
    stop_when_free_space_below_gb: float = 20
    compression: dict[str, Any] = field(default_factory=lambda: {"enabled": True, "format": "gzip"})
    pass_policy: dict[str, Any] = field(
        default_factory=lambda: {
            "keep_full": False,
            "keep_stdout_tail_kb": 16,
            "keep_stderr_tail_kb": 16,
            "keep_trace": True,
            "keep_payload": False,
            "keep_pcap": False,
        }
    )
    fail_policy: dict[str, Any] = field(
        default_factory=lambda: {
            "keep_full": True,
            "keep_first_n_per_bucket": 5,
            "keep_every_n_after": 100,
            "keep_pcap": "on_new_bucket",
            "max_pcap_mb": 64,
            "keep_payload": True,
        }
    )
    buckets: dict[str, Any] = field(
        default_factory=lambda: {"key_fields": ["mode", "verdict", "reason", "operation_or_protocol_or_pdu", "field", "strategy"]}
    )
    pruning: dict[str, Any] = field(default_factory=lambda: {"enabled": True, "prune_pass_first": True, "preserve_core": True})

    @classmethod
    def from_config(cls, config: dict[str, Any] | None, options: RuntimeOptions | None = None) -> "ArtifactPolicy":
        policy = cls()
        if config:
            _merge_policy(policy, config)
        options = options or RuntimeOptions()
        if options.artifact_budget_gb is not None:
            policy.max_total_gb = float(options.artifact_budget_gb)
        if options.free_space_floor_gb is not None:
            policy.stop_when_free_space_below_gb = float(options.free_space_floor_gb)
        if options.no_compress:
            policy.compression["enabled"] = False
        if options.keep_pass_full:
            policy.pass_policy["keep_full"] = True
        if options.keep_pcap:
            policy.pass_policy["keep_pcap"] = options.keep_pcap in {"always", "on-fail", "on-new-bucket"}
            policy.fail_policy["keep_pcap"] = options.keep_pcap
        return policy

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_total_gb": self.max_total_gb,
            "stop_when_free_space_below_gb": self.stop_when_free_space_below_gb,
            "compression": dict(self.compression),
            "pass": dict(self.pass_policy),
            "fail": dict(self.fail_policy),
            "buckets": dict(self.buckets),
            "pruning": dict(self.pruning),
        }

    @property
    def budget_bytes(self) -> int:
        return int(self.max_total_gb * 1024**3)

    @property
    def free_space_floor_bytes(self) -> int:
        return int(self.stop_when_free_space_below_gb * 1024**3)


class RunContext:
    def __init__(
        self,
        *,
        mode: str,
        artifacts_dir: Path,
        campaign_path: Path | None = None,
        catalog_path: Path | None = None,
        config_path: Path | None = None,
        artifact_policy_config: dict[str, Any] | None = None,
        options: RuntimeOptions | None = None,
        tool_paths: dict[str, str] | None = None,
        evidence_sources: dict[str, Any] | None = None,
        command_line: list[str] | None = None,
    ):
        self.mode = mode
        self.artifacts_dir = Path(artifacts_dir)
        self.campaign_path = Path(campaign_path) if campaign_path else None
        self.catalog_path = Path(catalog_path) if catalog_path else None
        self.config_path = Path(config_path) if config_path else None
        self.options = options or RuntimeOptions()
        self.policy = ArtifactPolicy.from_config(artifact_policy_config, self.options)
        self.tool_paths = tool_paths or {}
        self.evidence_sources = evidence_sources or {}
        self.command_line = command_line or sys.argv[:]
        self.run_id = self.options.run_id or datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%SZ")
        self.started_at = utc_now()
        self.started_monotonic = time.monotonic()
        self.planned_cases = 0
        self.selected_cases = 0
        self.started_cases = 0
        self.finished_cases = 0
        self.skipped_cases = 0
        self.verdict_counts: Counter[str] = Counter()
        self.skip_reason_counts: Counter[str] = Counter()
        self.missing_evidence_counts: Counter[str] = Counter()
        self.failure_buckets: dict[str, dict[str, Any]] = {}
        self.bucket_seen: Counter[str] = Counter()
        self.current_case: dict[str, Any] | None = None
        self.fatal_stop_reason: str | None = None
        self.last_progress_emit = 0.0
        self.events_count = 0
        self.artifact_stats = {"pruned": 0, "compressed": 0, "truncated": 0}

    def start(self, planned_cases: int | None = None) -> None:
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        if planned_cases is not None:
            self.planned_cases = planned_cases
        manifest = self._manifest()
        self._write_json(self.artifacts_dir / "run-manifest.json", manifest)
        self.event("run_started", detail={"planned_cases": self.planned_cases})
        self.event("manifest_written", detail={"path": "run-manifest.json"})
        self.write_progress(force=True)

    def ledger(
        self,
        case: dict[str, Any] | None,
        stage: str,
        *,
        status: str = "ok",
        detail: dict[str, Any] | None = None,
    ) -> None:
        entry = {
            "ts": utc_now(),
            "run_id": self.run_id,
            "mode": self.mode,
            "case_index": _case_index(case),
            "seed": None if not case else case.get("seed"),
            "stage": stage,
            "status": status,
            "detail": detail or {},
        }
        self._append_jsonl(self.artifacts_dir / "case-ledger.jsonl", entry)

    def event(self, event_type: str, *, case: dict[str, Any] | None = None, detail: dict[str, Any] | None = None) -> None:
        entry = {
            "ts": utc_now(),
            "run_id": self.run_id,
            "mode": self.mode,
            "case_index": _case_index(case),
            "event": event_type,
            "detail": detail or {},
        }
        self.events_count += 1
        self._append_jsonl(self.artifacts_dir / "events.jsonl", entry)

    def case_selected(self, case: dict[str, Any]) -> None:
        self.selected_cases += 1
        self.current_case = _case_brief(case)
        self.ledger(case, "selected")
        self.event("case_selected", case=case, detail=self.current_case)

    def case_started(self, case: dict[str, Any]) -> None:
        self.started_cases += 1
        self.current_case = _case_brief(case)
        self.ledger(case, "started")
        self.event("case_started", case=case, detail=self.current_case)
        self.write_progress()

    def case_skipped(self, case: dict[str, Any], reason: str) -> None:
        self.skipped_cases += 1
        self.skip_reason_counts[reason] += 1
        self.ledger(case, "skipped", status="skipped", detail={"reason": reason})
        self.event("case_finished", case=case, detail={"skipped": True, "reason": reason})
        self.write_progress()

    def case_finished(self, case: dict[str, Any], summary: dict[str, Any]) -> None:
        self.finished_cases += 1
        verdict = str(summary.get("verdict", "<unknown>"))
        self.verdict_counts[verdict] += 1
        missing = list(summary.get("missing_evidence") or default_missing_evidence(self.mode))
        for item in missing:
            self.missing_evidence_counts[str(item)] += 1
        bucket_key = str(summary.get("bucket_key") or build_bucket_key(self.mode, summary, case))
        if verdict.startswith("FAIL_"):
            self._record_failure_bucket(bucket_key, case, summary)
        self.ledger(case, "artifact_finalized", detail={"summary": f"case-{_case_index(case)}/summary.json"})
        self.ledger(case, "verdict_finalized", detail={"verdict": verdict, "bucket_key": bucket_key})
        self.event("verdict", case=case, detail={"verdict": verdict, "bucket_key": bucket_key})
        self.write_progress()

    def should_stop_for_disk(self) -> bool:
        free = shutil.disk_usage(self.artifacts_dir).free if self.artifacts_dir.exists() else shutil.disk_usage(self.artifacts_dir.parent).free
        if free < self.policy.free_space_floor_bytes:
            self.fatal_stop_reason = "disk_budget_exhausted"
            self.event("disk_budget_exhausted", detail={"free_disk_bytes": free})
            return True
        current = dir_size(self.artifacts_dir) if self.artifacts_dir.exists() else 0
        if current > self.policy.budget_bytes:
            self.event("disk_budget_warning", detail={"artifact_bytes": current, "budget_bytes": self.policy.budget_bytes})
        return False

    def finalize(self, *, fatal_stop_reason: str | None = None) -> dict[str, Any]:
        if fatal_stop_reason:
            self.fatal_stop_reason = fatal_stop_reason
        budget_status = self.apply_artifact_policy()
        self.event("run_finished", detail={"fatal_stop_reason": self.fatal_stop_reason})
        self.write_progress(force=True)
        index = build_artifact_index(self.artifacts_dir)
        summary = self._run_summary(index, budget_status)
        self._write_json(self.artifacts_dir / "run-summary.json", summary)
        index = build_artifact_index(self.artifacts_dir)
        self._write_json(self.artifacts_dir / "index.json", index)
        self._write_json(self.artifacts_dir / "index.partial.json", index)
        return summary

    def write_progress(self, *, force: bool = False) -> None:
        now = time.monotonic()
        if not force and self.options.progress_interval_s > 0 and now - self.last_progress_emit < self.options.progress_interval_s:
            return
        self.last_progress_emit = now
        elapsed = max(now - self.started_monotonic, 0.001)
        rate = self.finished_cases / elapsed
        remaining = max(self.selected_cases or self.planned_cases or 0, 0) - self.finished_cases
        eta = int(remaining / rate) if rate > 0 else None
        free = shutil.disk_usage(self.artifacts_dir if self.artifacts_dir.exists() else self.artifacts_dir.parent).free
        progress = {
            "run_id": self.run_id,
            "mode": self.mode,
            "planned": self.planned_cases,
            "selected": self.selected_cases,
            "started": self.started_cases,
            "finished": self.finished_cases,
            "skipped": self.skipped_cases,
            "rate_per_sec": round(rate, 3),
            "eta_sec": eta,
            "verdict_counts": dict(sorted(self.verdict_counts.items())),
            "new_failure_buckets": len(self.failure_buckets),
            "artifact_bytes": dir_size(self.artifacts_dir) if self.artifacts_dir.exists() else 0,
            "artifact_budget_bytes": self.policy.budget_bytes,
            "free_disk_bytes": free,
            "current_case": self.current_case,
            "trust_level": trust_level_for(self.mode),
            "missing_evidence_counts": dict(sorted(self.missing_evidence_counts.items())),
            "last_event_ts": utc_now(),
        }
        self._write_json(self.artifacts_dir / "progress.json", progress)
        if not self.options.quiet and sys.stderr.isatty():
            sys.stderr.write(self._progress_line(progress) + "\n")
            sys.stderr.flush()

    def apply_artifact_policy(self) -> dict[str, Any]:
        if not self.policy.pruning.get("enabled", True):
            return {"status": "disabled", **self.artifact_stats}
        for summary_path in sorted(self.artifacts_dir.glob("**/case-*/summary.json")):
            try:
                summary = read_json(summary_path)
            except (OSError, json.JSONDecodeError):
                continue
            case_dir = summary_path.parent
            verdict = str(summary.get("verdict", ""))
            if verdict.startswith("PASS_") and not self.policy.pass_policy.get("keep_full", False):
                self._trim_pass_case(case_dir)
            elif verdict.startswith("FAIL_"):
                self._apply_fail_bucket_policy(case_dir, summary)
        return {
            "status": "ok" if not self.fatal_stop_reason else self.fatal_stop_reason,
            "pruned": self.artifact_stats["pruned"],
            "compressed": self.artifact_stats["compressed"],
            "truncated": self.artifact_stats["truncated"],
            "budget_bytes": self.policy.budget_bytes,
            "artifact_bytes": dir_size(self.artifacts_dir),
        }

    def _manifest(self) -> dict[str, Any]:
        return {
            "schema": "pangea_run_manifest.v1",
            "run_id": self.run_id,
            "mode": self.mode,
            "command_line": self.command_line,
            "cwd": str(Path.cwd()),
            "git_commit": _git(["rev-parse", "HEAD"]),
            "git_dirty": bool(_git(["status", "--porcelain"])),
            "python_version": sys.version,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "start_time": self.started_at,
            "campaign_path": str(self.campaign_path) if self.campaign_path else None,
            "campaign_sha256": sha256_file(self.campaign_path) if self.campaign_path else None,
            "catalog_path": str(self.catalog_path) if self.catalog_path else None,
            "catalog_sha256": sha256_file(self.catalog_path) if self.catalog_path else None,
            "config_path": str(self.config_path) if self.config_path else None,
            "config_sha256": sha256_file(self.config_path) if self.config_path else None,
            "artifact_policy": self.policy.to_dict(),
            "tool_paths": self.tool_paths,
            "tool_versions": collect_tool_versions(self.tool_paths),
            "evidence_sources": self.evidence_sources,
        }

    def _run_summary(self, index: dict[str, Any], budget_status: dict[str, Any]) -> dict[str, Any]:
        inspection = inspect_run(self.artifacts_dir, require_index=False)
        finished_at = utc_now()
        return {
            "schema": "pangea_run_summary.v1",
            "run_id": self.run_id,
            "mode": self.mode,
            "started_at": self.started_at,
            "finished_at": finished_at,
            "duration_sec": round(time.monotonic() - self.started_monotonic, 3),
            "planned_cases": self.planned_cases,
            "selected_cases": self.selected_cases,
            "started_cases": self.started_cases,
            "finished_cases": self.finished_cases,
            "missing_summary_cases": inspection["missing_summary_cases"],
            "duplicate_case_dirs": inspection["duplicate_case_dirs"],
            "orphan_artifacts": inspection["orphan_artifacts"],
            "verdict_counts": dict(sorted(self.verdict_counts.items())),
            "skip_reason_counts": dict(sorted(self.skip_reason_counts.items())),
            "artifact_bytes": index["total_bytes"],
            "budget_status": budget_status,
            "artifact_stats": dict(self.artifact_stats),
            "trust_level": trust_level_for(self.mode),
            "missing_evidence": default_missing_evidence(self.mode),
            "missing_evidence_counts": dict(sorted(self.missing_evidence_counts.items())),
            "failure_buckets": sorted(self.failure_buckets.values(), key=lambda item: item["first_seen_case"]),
            "fatal_stop_reason": self.fatal_stop_reason,
        }

    def _record_failure_bucket(self, bucket_key: str, case: dict[str, Any], summary: dict[str, Any]) -> None:
        self.bucket_seen[bucket_key] += 1
        case_index = _case_index(case)
        bucket = self.failure_buckets.setdefault(
            bucket_key,
            {
                "bucket_key": bucket_key,
                "seen_count": 0,
                "kept_full_count": 0,
                "first_seen_case": case_index,
                "last_seen_case": case_index,
                "sampled_cases": [],
                "verdict": summary.get("verdict"),
                "reason": (summary.get("reasons") or [summary.get("reason", "")])[0],
            },
        )
        bucket["seen_count"] += 1
        bucket["last_seen_case"] = case_index
        keep_first = int(self.policy.fail_policy.get("keep_first_n_per_bucket", 5))
        keep_every = int(self.policy.fail_policy.get("keep_every_n_after", 100))
        if bucket["seen_count"] <= keep_first or (keep_every > 0 and bucket["seen_count"] % keep_every == 0):
            bucket["kept_full_count"] += 1
            bucket["sampled_cases"].append(case_index)
            if bucket["seen_count"] == 1:
                self.event("new_failure_bucket", case=case, detail={"bucket_key": bucket_key})

    def _trim_pass_case(self, case_dir: Path) -> None:
        for name, tail_key in (("stdout.log", "keep_stdout_tail_kb"), ("stderr.log", "keep_stderr_tail_kb")):
            path = case_dir / name
            if path.exists():
                limit = int(self.policy.pass_policy.get(tail_key, 16)) * 1024
                if path.stat().st_size > limit:
                    keep_tail(path, limit)
                    self.artifact_stats["truncated"] += 1
        if not self.policy.pass_policy.get("keep_payload", False):
            for name in PAYLOAD_NAMES:
                path = case_dir / name
                if path.exists():
                    path.unlink()
                    self.artifact_stats["pruned"] += 1
                    self.event("artifact_pruned", detail={"path": str(path.relative_to(self.artifacts_dir)), "reason": "pruned_pass_payload_by_policy"})
        if not self.policy.pass_policy.get("keep_pcap", False):
            for path in case_dir.glob("*.pcap*"):
                path.unlink()
                self.artifact_stats["pruned"] += 1

    def _apply_fail_bucket_policy(self, case_dir: Path, summary: dict[str, Any]) -> None:
        if not self.policy.compression.get("enabled", True):
            return
        for path in list(case_dir.iterdir()):
            if path.suffix in LOG_SUFFIXES and path.stat().st_size > 64 * 1024:
                gz_path = path.with_suffix(path.suffix + ".gz")
                with path.open("rb") as src, gzip.open(gz_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                path.unlink()
                self.artifact_stats["compressed"] += 1
                self.event("artifact_compressed", detail={"path": str(gz_path.relative_to(self.artifacts_dir))})

    def _write_json(self, path: Path, data: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json_dumps(data) + "\n", encoding="utf-8")

    def _append_jsonl(self, path: Path, data: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json_dumps(data, pretty=False) + "\n")

    def _progress_line(self, progress: dict[str, Any]) -> str:
        current = progress.get("current_case") or {}
        current_text = f"{current.get('case_index')}:{current.get('field')}/{current.get('strategy')}"
        return (
            f"[{datetime.now().strftime('%H:%M:%S')}] mode={self.mode} "
            f"cases={progress['finished']}/{progress['planned']} rate={progress['rate_per_sec']}/s "
            f"eta={format_duration(progress['eta_sec'])} "
            f"FAIL={sum(v for k, v in self.verdict_counts.items() if k.startswith('FAIL_'))} "
            f"buckets={len(self.failure_buckets)} disk={progress['artifact_bytes']}/{progress['artifact_budget_bytes']}B "
            f"current={current_text}"
        )


def default_missing_evidence(mode: str) -> list[str]:
    if mode == "net_protocol":
        return ["target_log", "switch_counter"]
    if mode == "nvme_kv":
        return ["target_log", "switch_counter", "pcap"]
    return ["target_log", "switch_counter", "pcap"]


def trust_level_for(mode: str, evidence: dict[str, Any] | None = None) -> str:
    evidence = evidence or {}
    has_network = bool(evidence.get("pcap") or evidence.get("packet_trace") or evidence.get("nic_counters"))
    has_target = bool(evidence.get("target_log"))
    if has_network and has_target:
        return "full"
    if has_network:
        return "host_network"
    if has_target:
        return "host_target"
    return "host_only"


def evidence_record(record_type: str, source: str, file: str, pattern: str, result: str) -> dict[str, str]:
    return {"type": record_type, "source": source, "file": file, "pattern": pattern, "result": result}


def build_bucket_key(mode: str, summary: dict[str, Any], case: dict[str, Any] | None) -> str:
    mutation = (case or {}).get("mutation") or {}
    reason = (summary.get("reasons") or [summary.get("reason", "")])[0]
    semantic = summary.get("operation") or summary.get("protocol") or (case or {}).get("pdu_type") or (case or {}).get("command") or "<unknown>"
    field_name = summary.get("field") or mutation.get("field") or "<unknown>"
    strategy = summary.get("strategy") or mutation.get("strategy") or "<unknown>"
    status = summary.get("nvme_status") or summary.get("returncode") or "<none>"
    return "|".join([mode, str(summary.get("verdict", "<unknown>")), str(reason), str(semantic), str(field_name), str(strategy), str(status)])


def collect_tool_versions(tool_paths: dict[str, str]) -> list[dict[str, Any]]:
    versions = [{"tool": "python", "path": sys.executable, "available": True, "version": sys.version.split()[0]}]
    for tool, path in sorted(tool_paths.items()):
        versions.append(probe_tool(tool, path))
    return versions


def probe_tool(tool: str, path: str) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            [path, "--version"],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=3,
            check=False,
        )
        return {
            "tool": tool,
            "path": path,
            "available": completed.returncode == 0,
            "returncode": completed.returncode,
            "version": (completed.stdout or completed.stderr).splitlines()[:3],
        }
    except Exception as exc:  # noqa: BLE001 - manifest must be best effort.
        return {"tool": tool, "path": path, "available": False, "error": str(exc)}


def build_artifact_index(root: Path) -> dict[str, Any]:
    artifacts: list[dict[str, Any]] = []
    total = 0
    if root.exists():
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            rel = path.relative_to(root).as_posix()
            size = path.stat().st_size
            total += size
            artifacts.append(
                {
                    "path": rel,
                    "size": size,
                    "sha256": sha256_file(path),
                    "artifact_class": artifact_class(path),
                    "kept": True,
                    "truncated": path.name.endswith(".truncated"),
                    "compressed": path.suffix == ".gz",
                    "deleted_by_budget": False,
                    "reason": None,
                }
            )
    return {"schema": "pangea_artifact_index.v1", "root": str(root), "total_bytes": total, "artifacts": artifacts}


def inspect_run(artifacts_dir: Path, *, require_index: bool = True) -> dict[str, Any]:
    artifacts_dir = Path(artifacts_dir)
    manifest = artifacts_dir / "run-manifest.json"
    index = artifacts_dir / "index.json"
    case_dirs = sorted(path for path in artifacts_dir.glob("**/case-*") if path.is_dir())
    missing = [path.name for path in case_dirs if (path / "case.yaml").exists() and not (path / "summary.json").exists()]
    duplicate_case_dirs = _duplicate_case_dirs(case_dirs)
    known_files = set(RUN_FILES)
    orphan: list[str] = []
    for path in artifacts_dir.iterdir() if artifacts_dir.exists() else []:
        if path.is_file() and path.name not in known_files:
            orphan.append(path.name)
    ledger_missing = []
    ledger_path = artifacts_dir / "case-ledger.jsonl"
    if ledger_path.exists():
        by_case: dict[str, set[str]] = defaultdict(set)
        for line in ledger_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            by_case[str(entry.get("case_index"))].add(str(entry.get("stage")))
        for case, stages in sorted(by_case.items()):
            if "started" in stages and "verdict_finalized" not in stages and "skipped" not in stages:
                ledger_missing.append({"case_index": case, "missing": ["verdict_finalized"]})
    summary_path = artifacts_dir / "run-summary.json"
    trust = "host_only"
    budget = {}
    if summary_path.exists():
        try:
            summary = read_json(summary_path)
            trust = summary.get("trust_level", trust)
            budget = summary.get("budget_status", {})
        except (OSError, json.JSONDecodeError):
            pass
    return {
        "schema": "pangea_run_inspection.v1",
        "artifacts_dir": str(artifacts_dir),
        "complete": manifest.exists() and (index.exists() or not require_index) and not missing and not ledger_missing,
        "manifest_exists": manifest.exists(),
        "index_exists": index.exists(),
        "ledger_exists": ledger_path.exists(),
        "ledger_missing_stages": ledger_missing,
        "missing_summary_cases": missing,
        "duplicate_case_dirs": duplicate_case_dirs,
        "orphan_artifacts": orphan,
        "budget_status": budget,
        "trust_level": trust,
        "suspicious_failure_buckets": _failure_buckets(artifacts_dir)[:20],
    }


def pack_repro(case_dir: Path, output: Path) -> dict[str, Any]:
    case_dir = Path(case_dir)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    root = _find_run_root(case_dir)
    include = []
    for name in ("case.yaml", "summary.json", "command.json", "packet.json", "pdu-trace.jsonl", "kv-trace.jsonl", "packet-trace.jsonl", "stdout.log", "stderr.log"):
        path = case_dir / name
        if path.exists():
            include.append(path)
    manifest = root / "run-manifest.json" if root else None
    if manifest and manifest.exists():
        include.append(manifest)
    run_sh = output.parent / "run.sh"
    run_sh.write_text("#!/bin/sh\nset -eu\npython -m pangea_fuzz.cli --help\n", encoding="utf-8")
    include.append(run_sh)
    with ZipFile(output, "w", ZIP_DEFLATED) as zipf:
        for path in include:
            if root and path.is_relative_to(root):
                arcname = path.relative_to(root).as_posix()
            else:
                arcname = path.name
            zipf.write(path, arcname)
    run_sh.unlink(missing_ok=True)
    return {"schema": "pangea_repro_pack.v1", "output": str(output), "files": len(include)}


def keep_tail(path: Path, limit: int) -> None:
    if limit <= 0:
        path.write_text("", encoding="utf-8")
        return
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        handle.seek(max(size - limit, 0))
        data = handle.read()
    path.write_bytes(data)


def dir_size(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def artifact_class(path: Path) -> str:
    name = path.name
    if name in CORE_NAMES:
        return "core"
    if name in TRACE_NAMES:
        return "trace"
    if name in PAYLOAD_NAMES:
        return "payload"
    if path.suffix in PCAP_SUFFIXES:
        return "pcap"
    if path.suffix in LOG_SUFFIXES or path.suffix == ".gz":
        return "log"
    if name.startswith(("nvme-", "dmesg", "journal", "ip-", "ethtool", "keyring")):
        return "state"
    if name in {"run.sh", "repro.zip"}:
        return "repro"
    return "other"


def format_duration(seconds: int | None) -> str:
    if seconds is None:
        return "unknown"
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m{sec}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes}m"


def _merge_policy(policy: ArtifactPolicy, data: dict[str, Any]) -> None:
    if "max_total_gb" in data:
        policy.max_total_gb = float(data["max_total_gb"])
    if "stop_when_free_space_below_gb" in data:
        policy.stop_when_free_space_below_gb = float(data["stop_when_free_space_below_gb"])
    for attr, key in (("compression", "compression"), ("pass_policy", "pass"), ("fail_policy", "fail"), ("buckets", "buckets"), ("pruning", "pruning")):
        value = data.get(key)
        if isinstance(value, dict):
            getattr(policy, attr).update(value)


def _git(args: list[str]) -> str | None:
    try:
        completed = subprocess.run(["git", *args], text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=3, check=False)
        if completed.returncode == 0:
            return completed.stdout.strip()
    except Exception:
        return None
    return None


def _case_index(case: dict[str, Any] | None) -> Any:
    if not case:
        return None
    return case.get("campaign_index", case.get("seed", "unknown"))


def _case_brief(case: dict[str, Any]) -> dict[str, Any]:
    mutation = case.get("mutation") or {}
    return {
        "case_index": _case_index(case),
        "seed": case.get("seed"),
        "pdu_type": case.get("pdu_type"),
        "operation": case.get("operation"),
        "protocol": case.get("protocol"),
        "field": mutation.get("field"),
        "strategy": mutation.get("strategy"),
    }


def _duplicate_case_dirs(case_dirs: list[Path]) -> list[str]:
    counts: Counter[str] = Counter(path.name.split("-seed-")[0] for path in case_dirs)
    return sorted(name for name, count in counts.items() if count > 1)


def _failure_buckets(root: Path) -> list[dict[str, Any]]:
    buckets: Counter[str] = Counter()
    for summary_path in root.glob("**/case-*/summary.json"):
        try:
            summary = read_json(summary_path)
        except (OSError, json.JSONDecodeError):
            continue
        verdict = str(summary.get("verdict", ""))
        if verdict.startswith("FAIL_"):
            key = str(summary.get("bucket_key") or "|".join([verdict, (summary.get("reasons") or [summary.get("reason", "")])[0]]))
            buckets[key] += 1
    return [{"bucket_key": key, "count": count} for key, count in buckets.most_common()]


def _find_run_root(case_dir: Path) -> Path | None:
    current = case_dir.resolve()
    for parent in [current, *current.parents]:
        if (parent / "run-manifest.json").exists():
            return parent
    return case_dir.parent
