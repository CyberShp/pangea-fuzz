from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, Future, ProcessPoolExecutor, wait
from dataclasses import dataclass
import json
from pathlib import Path
import shlex
import subprocess
import sys
from typing import Any, Iterator

from pangea_fuzz.runtime import (
    RunContext,
    RuntimeOptions,
    build_bucket_key,
    default_missing_evidence,
    evidence_record,
    trust_level_for,
)


WRITE_COMMANDS = {"write", "randwrite", "rw", "randrw"}


@dataclass(frozen=True)
class RunConfig:
    campaign_path: Path
    artifacts_dir: Path
    engine: str = "fio"
    device: str = ""
    workers: int = 1
    shard_index: int = 0
    shard_count: int = 1
    runtime_s: int = 5
    dry_run: bool = False
    allow_write: bool = False
    limit: int | None = None
    timeout_s: int = 120
    fio_template: str | None = None
    fio_bin: str = "fio"
    vdbench_bin: str = "vdbench"
    nvme_bin: str = "nvme"
    transport: str = "tcp"
    traddr: str = ""
    trsvcid: str = ""
    subsysnqn: str = ""
    hostnqn: str = ""
    connect_extra_args: tuple[str, ...] = ()
    disconnect_extra_args: tuple[str, ...] = ()
    connection_lifecycle: str = "none"
    discover_before_connect: bool = False
    disconnect_after_case: bool = True
    run_id: str | None = None
    artifact_policy: dict[str, Any] | None = None
    artifact_budget_gb: float | None = None
    free_space_floor_gb: float | None = None
    progress_interval_s: float = 5.0
    quiet: bool = False
    no_compress: bool = False
    keep_pass_full: bool = False
    keep_pcap: str | None = None

    def __post_init__(self) -> None:
        if self.engine not in {"fio", "vdbench"}:
            raise ValueError("engine must be fio or vdbench")
        if self.connection_lifecycle not in {"none", "per-case"}:
            raise ValueError("connection_lifecycle must be none or per-case")
        if self.workers < 1:
            raise ValueError("workers must be >= 1")
        if self.shard_count < 1:
            raise ValueError("shard_count must be >= 1")
        if not 0 <= self.shard_index < self.shard_count:
            raise ValueError("shard_index must be in [0, shard_count)")
        if self.runtime_s < 1:
            raise ValueError("runtime_s must be >= 1")
        if self.timeout_s < 1:
            raise ValueError("timeout_s must be >= 1")
        if not self.device:
            raise ValueError("device is required")
        if self.connection_lifecycle != "none":
            missing = [name for name, value in (("traddr", self.traddr), ("trsvcid", self.trsvcid), ("subsysnqn", self.subsysnqn)) if not value]
            if missing:
                raise ValueError(f"connection lifecycle missing required fields: {', '.join(missing)}")


class WorkloadBuilder:
    def __init__(
        self,
        *,
        engine: str,
        device: str,
        runtime_s: int,
        output_dir: str | Path | None = None,
        fio_template: str | None = None,
        fio_bin: str = "fio",
        vdbench_bin: str = "vdbench",
    ):
        self.engine = engine
        self.device = device
        self.runtime_s = runtime_s
        self.output_dir = Path(output_dir) if output_dir else None
        self.fio_template = fio_template
        self.fio_bin = fio_bin
        self.vdbench_bin = vdbench_bin

    def build(self, case: dict[str, Any]) -> list[str]:
        if self.engine == "fio":
            return self._build_fio(case)
        if self.engine == "vdbench":
            return self._build_vdbench(case)
        raise ValueError("engine must be fio or vdbench")

    def _build_fio(self, case: dict[str, Any]) -> list[str]:
        context = self._context(case)
        template = self.fio_template or (
            "--name={case_id} --filename={device} --rw={rw} "
            "--direct=1 --ioengine=libaio --bs=4k --iodepth=16 "
            "--time_based --runtime={runtime}"
        )
        command = [self.fio_bin, *shlex.split(template.format(**context))]
        if "--output-format=json" not in command:
            command.append("--output-format=json")
        return command

    def _build_vdbench(self, case: dict[str, Any]) -> list[str]:
        if self.output_dir is None:
            raise ValueError("output_dir is required for vdbench")
        context = self._context(case)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        parameter_file = self.output_dir / "vdbench.parm"
        read_percent = 0 if context["rw"] == "write" else 100
        parameter_file.write_text(
            "\n".join(
                [
                    f"sd=sd1,lun={self.device},openflags=o_direct",
                    f"wd=wd1,sd=sd1,xfersize=4k,rdpct={read_percent}",
                    f"rd=rd1,wd=wd1,iorate=max,elapsed={self.runtime_s},interval=1",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return [self.vdbench_bin, "-f", str(parameter_file)]

    def _context(self, case: dict[str, Any]) -> dict[str, Any]:
        mutation = case.get("mutation", {})
        if not isinstance(mutation, dict):
            mutation = {}
        case_index = case.get("campaign_index", case.get("seed", 0))
        rw = _rw_for_case(case)
        return {
            "case_id": f"case-{case_index}",
            "device": self.device,
            "rw": rw,
            "runtime": self.runtime_s,
            "seed": case.get("seed", ""),
            "field": mutation.get("field", ""),
            "strategy": mutation.get("strategy", ""),
        }


class RunOrchestrator:
    def __init__(self, config: RunConfig):
        self.config = config

    def run(self) -> dict[str, Any]:
        self.config.artifacts_dir.mkdir(parents=True, exist_ok=True)
        context = RunContext(
            mode="nvmetcp_tls",
            artifacts_dir=self.config.artifacts_dir,
            campaign_path=self.config.campaign_path,
            catalog_path=Path("field_catalog.yaml"),
            artifact_policy_config=self.config.artifact_policy,
            options=RuntimeOptions(
                run_id=self.config.run_id,
                artifact_budget_gb=self.config.artifact_budget_gb,
                free_space_floor_gb=self.config.free_space_floor_gb,
                progress_interval_s=self.config.progress_interval_s,
                quiet=self.config.quiet,
                no_compress=self.config.no_compress,
                keep_pass_full=self.config.keep_pass_full,
                keep_pcap=self.config.keep_pcap,
            ),
            tool_paths={
                "nvme": self.config.nvme_bin,
                "fio": self.config.fio_bin,
                "vdbench": self.config.vdbench_bin,
                "keyctl": "keyctl",
                "tcpdump": "tcpdump",
            },
            command_line=sys.argv[:],
        )
        context.start()
        planned = 0
        selected_count = 0
        executed_count = 0
        verdict_counts: dict[str, int] = {}
        selected_limit_reached = False

        worker_config = _WorkerConfig.from_run_config(self.config)
        try:
            if self.config.workers == 1:
                for ordinal, case in enumerate(_read_campaign(self.config.campaign_path)):
                    planned += 1
                    context.planned_cases = planned
                    context.ledger(case, "planned")
                    if not self._case_selected(case, ordinal) or selected_limit_reached:
                        if selected_limit_reached:
                            context.case_skipped(case, "limit reached")
                        continue
                    if context.should_stop_for_disk():
                        context.case_skipped(case, "disk budget exhausted")
                        selected_limit_reached = True
                        continue
                    selected_count += 1
                    context.case_selected(case)
                    context.case_started(case)
                    context.ledger(case, "command_built", detail={"engine": self.config.engine, "connection_lifecycle": self.config.connection_lifecycle})
                    summary = _run_one_case(worker_config, case)
                    context.case_finished(case, summary)
                    _record_verdict(verdict_counts, summary)
                    executed_count += 1
                    if self.config.limit is not None and selected_count >= self.config.limit:
                        selected_limit_reached = True
            else:
                inflight: dict[Future, dict[str, Any]] = {}
                max_inflight = max(self.config.workers * 4, 1)
                with ProcessPoolExecutor(max_workers=self.config.workers) as executor:
                    for ordinal, case in enumerate(_read_campaign(self.config.campaign_path)):
                        planned += 1
                        context.planned_cases = planned
                        context.ledger(case, "planned")
                        if not self._case_selected(case, ordinal) or selected_limit_reached:
                            if selected_limit_reached:
                                context.case_skipped(case, "limit reached")
                            continue
                        if context.should_stop_for_disk():
                            context.case_skipped(case, "disk budget exhausted")
                            selected_limit_reached = True
                            continue
                        selected_count += 1
                        context.case_selected(case)
                        context.case_started(case)
                        context.ledger(case, "command_built", detail={"engine": self.config.engine, "connection_lifecycle": self.config.connection_lifecycle})
                        future = executor.submit(_run_one_case, worker_config, case)
                        inflight[future] = case
                        if self.config.limit is not None and selected_count >= self.config.limit:
                            selected_limit_reached = True
                        if len(inflight) >= max_inflight:
                            done, _ = wait(set(inflight), return_when=FIRST_COMPLETED)
                            for future in done:
                                case_for_future = inflight.pop(future)
                                summary = future.result()
                                context.case_finished(case_for_future, summary)
                                _record_verdict(verdict_counts, summary)
                                executed_count += 1

                    while inflight:
                        done, _ = wait(set(inflight), return_when=FIRST_COMPLETED)
                        for future in done:
                            case_for_future = inflight.pop(future)
                            summary = future.result()
                            context.case_finished(case_for_future, summary)
                            _record_verdict(verdict_counts, summary)
                            executed_count += 1
        finally:
            context.planned_cases = planned
            context.selected_cases = selected_count
            context.finished_cases = executed_count
            run_summary = context.finalize()

        return {
            "run_schema": "nvmetcp_tls_fuzz_run.v1",
            "run_id": context.run_id,
            "campaign_path": str(self.config.campaign_path),
            "artifacts_dir": str(self.config.artifacts_dir),
            "engine": self.config.engine,
            "planned_cases": planned,
            "selected_cases": selected_count,
            "executed_cases": executed_count,
            "workers": self.config.workers,
            "shard_index": self.config.shard_index,
            "shard_count": self.config.shard_count,
            "dry_run": self.config.dry_run,
            "verdict_counts": dict(sorted(verdict_counts.items())),
            "trust_level": run_summary.get("trust_level"),
            "artifact_bytes": run_summary.get("artifact_bytes"),
        }

    def _case_selected(self, case: dict[str, Any], ordinal: int) -> bool:
        case_index = int(case.get("campaign_index", ordinal))
        return case_index % self.config.shard_count == self.config.shard_index


@dataclass(frozen=True)
class _WorkerConfig:
    artifacts_dir: Path
    engine: str
    device: str
    runtime_s: int
    dry_run: bool
    allow_write: bool
    timeout_s: int
    fio_template: str | None
    fio_bin: str
    vdbench_bin: str
    nvme_bin: str
    transport: str
    traddr: str
    trsvcid: str
    subsysnqn: str
    hostnqn: str
    connect_extra_args: tuple[str, ...]
    disconnect_extra_args: tuple[str, ...]
    connection_lifecycle: str
    discover_before_connect: bool
    disconnect_after_case: bool

    @classmethod
    def from_run_config(cls, config: RunConfig) -> "_WorkerConfig":
        return cls(
            artifacts_dir=config.artifacts_dir,
            engine=config.engine,
            device=config.device,
            runtime_s=config.runtime_s,
            dry_run=config.dry_run,
            allow_write=config.allow_write,
            timeout_s=config.timeout_s,
            fio_template=config.fio_template,
            fio_bin=config.fio_bin,
            vdbench_bin=config.vdbench_bin,
            nvme_bin=config.nvme_bin,
            transport=config.transport,
            traddr=config.traddr,
            trsvcid=config.trsvcid,
            subsysnqn=config.subsysnqn,
            hostnqn=config.hostnqn,
            connect_extra_args=tuple(config.connect_extra_args),
            disconnect_extra_args=tuple(config.disconnect_extra_args),
            connection_lifecycle=config.connection_lifecycle,
            discover_before_connect=config.discover_before_connect,
            disconnect_after_case=config.disconnect_after_case,
        )


def _run_one_case(config: _WorkerConfig, case: dict[str, Any]) -> dict[str, Any]:
    case_index = case.get("campaign_index", case.get("seed", "unknown"))
    run_dir = config.artifacts_dir / f"case-{case_index}"
    run_dir.mkdir(parents=True, exist_ok=True)
    _write_json(run_dir / "case.yaml", case)

    builder = WorkloadBuilder(
        engine=config.engine,
        device=config.device,
        runtime_s=config.runtime_s,
        output_dir=run_dir,
        fio_template=config.fio_template,
        fio_bin=config.fio_bin,
        vdbench_bin=config.vdbench_bin,
    )
    command = builder.build(case)
    connection_plan = _build_connection_plan(config)
    _write_json(run_dir / "command.json", {"argv": command, "workload": command, "connection": connection_plan})

    if _is_write_case(case) and not config.allow_write:
        summary = {
            "verdict": "FAIL_INFRA",
            "reasons": ["write workload requires --allow-write"],
            "returncode": None,
            "engine": config.engine,
            "dry_run": config.dry_run,
            "evidence": [evidence_record("safety_gate", "runner", "summary.json", "--allow-write", "matched")],
        }
        _finalize_summary(summary, case)
        _write_json(run_dir / "summary.json", summary)
        return summary

    if config.dry_run:
        summary = {
            "verdict": "PASS_VALID",
            "reasons": ["dry-run command planned"],
            "returncode": 0,
            "engine": config.engine,
            "dry_run": True,
            "connection_lifecycle": config.connection_lifecycle,
            "evidence": [
                evidence_record("command_planned", config.engine, "command.json", "dry-run", "matched"),
                *(
                    [evidence_record("nvme_connect", "nvme-cli", "command.json", config.subsysnqn, "planned")]
                    if config.connection_lifecycle != "none"
                    else []
                ),
            ],
        }
        _finalize_summary(summary, case)
        _write_json(run_dir / "summary.json", summary)
        return summary

    connection_started = False
    if config.connection_lifecycle == "per-case":
        connect_result = _run_connection_setup(config, run_dir)
        connection_started = connect_result["connected"]
        if not connect_result["connected"]:
            summary = {
                "verdict": "PASS_REJECTED",
                "reasons": [connect_result["reason"]],
                "returncode": connect_result["returncode"],
                "engine": config.engine,
                "dry_run": False,
                "connection_lifecycle": config.connection_lifecycle,
                "evidence": [
                    evidence_record("nvme_connect", "nvme-cli", "connection-stderr.log", str(connect_result["returncode"]), "matched"),
                ],
            }
            _finalize_summary(summary, case)
            _write_json(run_dir / "summary.json", summary)
            return summary

    try:
        completed = subprocess.run(
            command,
            cwd=run_dir,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=config.timeout_s,
            check=False,
        )
    except FileNotFoundError as exc:
        summary = {
            "verdict": "FAIL_INFRA",
            "reasons": [f"workload tool not found: {command[0]}"],
            "returncode": None,
            "engine": config.engine,
            "dry_run": False,
            "evidence": [evidence_record("tool_missing", config.engine, "stderr.log", command[0], "matched")],
        }
        _write_text(run_dir / "stderr.log", str(exc))
        _finalize_summary(summary, case)
        _write_json(run_dir / "summary.json", summary)
        return summary
    except subprocess.TimeoutExpired as exc:
        _write_text(run_dir / "stdout.log", exc.stdout or "")
        _write_text(run_dir / "stderr.log", exc.stderr or "")
        summary = {
            "verdict": "FAIL_HANG",
            "reasons": [f"workload timed out after {config.timeout_s}s"],
            "returncode": None,
            "engine": config.engine,
            "dry_run": False,
            "evidence": [evidence_record("timeout", config.engine, "stderr.log", "timeout", "matched")],
        }
        _finalize_summary(summary, case)
        _write_json(run_dir / "summary.json", summary)
        return summary
    finally:
        if connection_started and config.disconnect_after_case:
            _run_disconnect(config, run_dir)

    _write_text(run_dir / "stdout.log", completed.stdout)
    _write_text(run_dir / "stderr.log", completed.stderr)
    if config.engine == "fio" and completed.stdout.strip().startswith("{"):
        _write_text(run_dir / "fio.json", completed.stdout)

    verdict = "PASS_VALID" if completed.returncode == 0 else "PASS_REJECTED"
    reason = "workload completed" if completed.returncode == 0 else f"workload exited {completed.returncode}"
    summary = {
        "verdict": verdict,
        "reasons": [reason],
        "returncode": completed.returncode,
        "engine": config.engine,
        "dry_run": False,
        "connection_lifecycle": config.connection_lifecycle,
        "evidence": [
            evidence_record(f"{config.engine}_returncode", config.engine, "stdout.log", str(completed.returncode), "matched"),
            evidence_record(
                "stderr_pattern",
                config.engine,
                "stderr.log",
                "error|timeout|reset",
                "not_matched" if completed.returncode == 0 else "matched",
            ),
        ],
    }
    _finalize_summary(summary, case)
    _write_json(run_dir / "summary.json", summary)
    return summary


def _build_connection_plan(config: _WorkerConfig) -> dict[str, Any]:
    if config.connection_lifecycle == "none":
        return {"enabled": False, "lifecycle": "none"}
    connect = [
        config.nvme_bin,
        "connect",
        "-t",
        config.transport,
        "-a",
        config.traddr,
        "-s",
        config.trsvcid,
        "-n",
        config.subsysnqn,
    ]
    if config.hostnqn:
        connect.extend(["--hostnqn", config.hostnqn])
    connect.extend(config.connect_extra_args)
    discover = [
        config.nvme_bin,
        "discover",
        "-t",
        config.transport,
        "-a",
        config.traddr,
        "-s",
        config.trsvcid,
    ]
    disconnect = [config.nvme_bin, "disconnect", "-n", config.subsysnqn, *config.disconnect_extra_args]
    return {
        "enabled": True,
        "lifecycle": config.connection_lifecycle,
        "discover": discover if config.discover_before_connect else None,
        "connect": connect,
        "disconnect": disconnect if config.disconnect_after_case else None,
    }


def _run_connection_setup(config: _WorkerConfig, run_dir: Path) -> dict[str, Any]:
    plan = _build_connection_plan(config)
    if config.discover_before_connect and plan["discover"]:
        _run_nvme_step(plan["discover"], run_dir, "discover", config.timeout_s)
    completed = _run_nvme_step(plan["connect"], run_dir, "connection", config.timeout_s)
    if completed.returncode != 0:
        return {
            "connected": False,
            "returncode": completed.returncode,
            "reason": f"nvme connect exited {completed.returncode}",
        }
    return {"connected": True, "returncode": 0, "reason": "nvme connect completed"}


def _run_disconnect(config: _WorkerConfig, run_dir: Path) -> None:
    plan = _build_connection_plan(config)
    if plan["disconnect"]:
        _run_nvme_step(plan["disconnect"], run_dir, "disconnect", config.timeout_s)


def _run_nvme_step(argv: list[str], run_dir: Path, prefix: str, timeout_s: int) -> subprocess.CompletedProcess:
    try:
        completed = subprocess.run(
            argv,
            cwd=run_dir,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout_s,
            check=False,
        )
    except FileNotFoundError as exc:
        _write_text(run_dir / f"{prefix}-stdout.log", "")
        _write_text(run_dir / f"{prefix}-stderr.log", str(exc))
        return subprocess.CompletedProcess(argv, 127, "", str(exc))
    except subprocess.TimeoutExpired as exc:
        _write_text(run_dir / f"{prefix}-stdout.log", exc.stdout or "")
        _write_text(run_dir / f"{prefix}-stderr.log", exc.stderr or "timeout")
        return subprocess.CompletedProcess(argv, 124, exc.stdout or "", exc.stderr or "timeout")
    _write_text(run_dir / f"{prefix}-stdout.log", completed.stdout)
    _write_text(run_dir / f"{prefix}-stderr.log", completed.stderr)
    return completed


def _read_campaign(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                yield json.loads(stripped.lstrip("\ufeff"))


def _rw_for_case(case: dict[str, Any]) -> str:
    command = str(case.get("command", "read")).lower()
    if command == "write":
        return "write"
    if command in {"rw", "randrw"}:
        return "randrw"
    return "read"


def _is_write_case(case: dict[str, Any]) -> bool:
    return _rw_for_case(case) in WRITE_COMMANDS


def _count_verdicts(summaries: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for summary in summaries:
        _record_verdict(counts, summary)
    return dict(sorted(counts.items()))


def _record_verdict(counts: dict[str, int], summary: dict[str, Any]) -> None:
    verdict = str(summary.get("verdict", "<unknown>"))
    counts[verdict] = counts.get(verdict, 0) + 1


def _finalize_summary(summary: dict[str, Any], case: dict[str, Any]) -> None:
    mutation = case.get("mutation", {})
    if not isinstance(mutation, dict):
        mutation = {}
    summary.setdefault("mode", "nvmetcp_tls")
    summary.setdefault("pdu_type", case.get("pdu_type"))
    summary.setdefault("command", case.get("command"))
    summary.setdefault("field", mutation.get("field"))
    summary.setdefault("strategy", mutation.get("strategy"))
    summary.setdefault("bucket_key", build_bucket_key("nvmetcp_tls", summary, case))
    summary.setdefault("trust_level", trust_level_for("nvmetcp_tls"))
    summary.setdefault("missing_evidence", default_missing_evidence("nvmetcp_tls"))
    summary.setdefault("artifact_policy", "managed-by-run-context")


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")


def _write_text(path: Path, text: str | bytes | None) -> None:
    if text is None:
        text = ""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    path.write_text(text, encoding="utf-8", errors="replace")
