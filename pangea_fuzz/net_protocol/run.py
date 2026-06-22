from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import socket
import subprocess
import sys
import time
from typing import Any, Iterator

from pangea_fuzz.runtime import (
    RunContext,
    RuntimeOptions,
    default_missing_evidence,
    evidence_record,
    trust_level_for,
)

from .packets import build_packet
from .pcap import PcapWriter


@dataclass(frozen=True)
class NetRunConfig:
    campaign_path: Path
    artifacts_dir: Path
    iface: str = ""
    limit: int | None = None
    dry_run: bool = False
    allow_send: bool = False
    allow_disruptive: bool = False
    iface_allowlist: tuple[str, ...] = ()
    forbid_default_route_iface: bool = True
    tcpreplay_bin: str = "tcpreplay"
    tcpdump_bin: str = "tcpdump"
    max_pps: int = 100
    shard_index: int = 0
    shard_count: int = 1
    run_id: str | None = None
    artifact_policy: dict[str, Any] | None = None
    artifact_budget_gb: float | None = None
    free_space_floor_gb: float | None = None
    progress_interval_s: float = 5.0
    quiet: bool = False
    no_compress: bool = False
    keep_pass_full: bool = False
    keep_pcap: str | None = None


class NetProtocolRunner:
    def __init__(self, config: NetRunConfig):
        self.config = config

    def generate_pcap(self) -> dict[str, Any]:
        self.config.artifacts_dir.mkdir(parents=True, exist_ok=True)
        context = self._context()
        context.start()
        pcap_path = self.config.artifacts_dir / "packets.pcap"
        trace_path = self.config.artifacts_dir / "packet-trace.jsonl"
        planned = selected = 0
        try:
            with PcapWriter(pcap_path) as writer, trace_path.open("w", encoding="utf-8") as trace:
                for ordinal, case in enumerate(_read_campaign(self.config.campaign_path)):
                    planned += 1
                    context.planned_cases = planned
                    context.ledger(case, "planned")
                    if not self._selected(case, ordinal):
                        continue
                    if self.config.limit is not None and selected >= self.config.limit:
                        context.case_skipped(case, "limit reached")
                        continue
                    if context.should_stop_for_disk():
                        context.case_skipped(case, "disk budget exhausted")
                        continue
                    context.case_selected(case)
                    context.case_started(case)
                    packet = build_packet(case)
                    context.ledger(case, "packet_built", detail={"length": len(packet)})
                    writer.write_packet(packet)
                    context.ledger(case, "pcap_written", detail={"path": "packets.pcap", "length": len(packet)})
                    summary_case = _write_case_artifact(self.config.artifacts_dir, case, packet, "PASS_VALID", "pcap packet generated")
                    trace.write(json.dumps(_trace(case, selected, len(packet), "pcap"), ensure_ascii=False, sort_keys=True) + "\n")
                    context.case_finished(case, summary_case)
                    selected += 1
        finally:
            context.planned_cases = planned
            context.selected_cases = selected
            context.finished_cases = selected
            run_summary = context.finalize()
        summary = {
            "run_schema": "net_protocol_fuzz_run.v1",
            "mode": "net_protocol",
            "planned_cases": planned,
            "selected_cases": selected,
            "executed_cases": selected,
            "pcap_path": str(pcap_path),
            "verdict": "PASS_VALID",
            "reasons": ["pcap generated"],
            "trust_level": run_summary.get("trust_level"),
            "artifact_bytes": run_summary.get("artifact_bytes"),
        }
        (self.config.artifacts_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        return summary

    def send(self) -> dict[str, Any]:
        if not self.config.dry_run and not self.config.allow_send:
            raise PermissionError("net-protocol send requires --allow-send")
        if not self.config.iface:
            raise ValueError("send requires --iface")
        if not self.config.dry_run:
            self._precheck_send_safety()
        self.config.artifacts_dir.mkdir(parents=True, exist_ok=True)
        context = self._context()
        context.start()
        selected = 0
        verdict_counts: dict[str, int] = {}
        raw_socket = None
        if not self.config.dry_run:
            raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            raw_socket.bind((self.config.iface, 0))
        try:
            for ordinal, case in enumerate(_read_campaign(self.config.campaign_path)):
                context.planned_cases += 1
                context.ledger(case, "planned")
                if not self._selected(case, ordinal):
                    continue
                if self.config.limit is not None and selected >= self.config.limit:
                    context.case_skipped(case, "limit reached")
                    continue
                if not self.config.dry_run and _is_disruptive(case) and not self.config.allow_disruptive:
                    raise PermissionError("disruptive ARP/ICMPv6/TCP reset-style cases require --allow-disruptive")
                context.case_selected(case)
                context.case_started(case)
                packet = build_packet(case)
                context.ledger(case, "packet_built", detail={"length": len(packet)})
                if raw_socket is not None:
                    context.ledger(case, "send_started", detail={"iface": self.config.iface})
                    raw_socket.send(packet)
                    time.sleep(1.0 / max(self.config.max_pps, 1))
                    context.ledger(case, "send_finished", detail={"bytes": len(packet)})
                verdict = "PASS_VALID"
                reason = "dry-run packet planned" if self.config.dry_run else "packet sent"
                summary_case = _write_case_artifact(self.config.artifacts_dir, case, packet, verdict, reason)
                context.case_finished(case, summary_case)
                verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
                selected += 1
        finally:
            if raw_socket is not None:
                raw_socket.close()
            run_summary = context.finalize()
        summary = {
            "run_schema": "net_protocol_fuzz_run.v1",
            "mode": "net_protocol",
            "selected_cases": selected,
            "executed_cases": selected,
            "dry_run": self.config.dry_run,
            "allow_send": self.config.allow_send,
            "verdict_counts": verdict_counts,
            "verdict": "PASS_VALID",
            "reasons": ["send completed" if not self.config.dry_run else "dry-run send planned"],
            "trust_level": run_summary.get("trust_level"),
            "artifact_bytes": run_summary.get("artifact_bytes"),
        }
        (self.config.artifacts_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        return summary

    def replay(self, pcap_path: Path) -> dict[str, Any]:
        if not self.config.dry_run and not self.config.allow_send:
            raise PermissionError("net-protocol replay requires --allow-send")
        self.config.artifacts_dir.mkdir(parents=True, exist_ok=True)
        context = self._context(campaign_path=pcap_path)
        context.start(planned_cases=1)
        argv = [self.config.tcpreplay_bin, "-i", self.config.iface, str(pcap_path)]
        pseudo_case = {"campaign_index": 0, "seed": 0, "protocol": "pcap_replay", "mutation": {"field": "pcap", "strategy": "replay"}}
        context.case_selected(pseudo_case)
        context.case_started(pseudo_case)
        context.ledger(pseudo_case, "replay_started", detail={"argv": argv})
        if self.config.dry_run:
            rc, stdout, stderr = 0, "dry-run replay planned\n", ""
        else:
            completed = subprocess.run(argv, text=True, encoding="utf-8", errors="replace", capture_output=True, check=False)
            rc, stdout, stderr = completed.returncode, completed.stdout, completed.stderr
        summary = {
            "run_schema": "net_protocol_fuzz_run.v1",
            "mode": "net_protocol",
            "command": argv,
            "returncode": rc,
            "stdout": stdout,
            "stderr": stderr,
            "verdict": "PASS_VALID" if rc == 0 else "PASS_REJECTED",
            "reasons": ["replay completed" if rc == 0 else f"{self.config.tcpreplay_bin} exited {rc}"],
            "trust_level": trust_level_for("net_protocol"),
            "missing_evidence": default_missing_evidence("net_protocol"),
            "evidence": [
                evidence_record("tcpreplay_return", "tcpreplay", "summary.json", str(rc), "matched"),
            ],
        }
        case_dir = self.config.artifacts_dir / "case-0"
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "case.yaml").write_text(json.dumps(pseudo_case, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        (case_dir / "command.json").write_text(json.dumps({"argv": argv}, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        (case_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        context.ledger(pseudo_case, "replay_finished", detail={"returncode": rc})
        context.case_finished(pseudo_case, summary)
        (self.config.artifacts_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        context.finalize()
        return summary

    def _context(self, *, campaign_path: Path | None = None) -> RunContext:
        return RunContext(
            mode="net_protocol",
            artifacts_dir=self.config.artifacts_dir,
            campaign_path=campaign_path or self.config.campaign_path,
            catalog_path=Path("net_field_catalog.yaml"),
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
            tool_paths={"tcpdump": self.config.tcpdump_bin, "tcpreplay": self.config.tcpreplay_bin},
            command_line=sys.argv[:],
        )

    def _selected(self, case: dict[str, Any], ordinal: int) -> bool:
        index = int(case.get("campaign_index", ordinal))
        return index % self.config.shard_count == self.config.shard_index

    def _precheck_send_safety(self) -> None:
        if self.config.iface_allowlist and self.config.iface not in self.config.iface_allowlist:
            raise PermissionError(f"iface {self.config.iface!r} is not in iface allowlist")
        if self.config.forbid_default_route_iface and self.config.iface in _default_route_ifaces():
            raise PermissionError(f"iface {self.config.iface!r} owns a default route; pass an explicit override in config before sending")


def _read_campaign(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                yield json.loads(stripped)


def _write_case_artifact(root: Path, case: dict[str, Any], packet: bytes, verdict: str, reason: str) -> dict[str, Any]:
    index = case.get("campaign_index", "single")
    run_dir = root / f"case-{index}"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "case.yaml").write_text(json.dumps(case, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    (run_dir / "packet.bin").write_bytes(packet)
    (run_dir / "packet.json").write_text(
        json.dumps(
            {"protocol": case.get("protocol"), "length": len(packet), "mutation": case.get("mutation", {})},
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    summary = {
        "run_schema": "net_protocol_fuzz_case.v1",
        "mode": "net_protocol",
        "verdict": verdict,
        "reasons": [reason],
        "protocol": case.get("protocol"),
        "field": (case.get("mutation") or {}).get("field"),
        "strategy": (case.get("mutation") or {}).get("strategy"),
        "trust_level": trust_level_for("net_protocol", {"packet_trace": True}),
        "missing_evidence": default_missing_evidence("net_protocol"),
        "evidence": [
            evidence_record("packet_built", "packet-builder", "packet.json", str(len(packet)), "matched"),
            evidence_record("packet_trace", "runner", "packet-trace.jsonl", str(case.get("protocol")), "matched"),
        ],
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return summary


def _trace(case: dict[str, Any], ordinal: int, packet_length: int, stage: str) -> dict[str, Any]:
    return {
        "ordinal": ordinal,
        "stage": stage,
        "protocol": case.get("protocol"),
        "packet_length": packet_length,
        "mutation": case.get("mutation", {}),
    }


def _default_route_ifaces() -> set[str]:
    try:
        completed = subprocess.run(
            ["ip", "route", "show", "default"],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=2,
            check=False,
        )
    except Exception:
        return set()
    ifaces: set[str] = set()
    words = completed.stdout.split()
    for index, word in enumerate(words[:-1]):
        if word == "dev":
            ifaces.add(words[index + 1])
    return ifaces


def _is_disruptive(case: dict[str, Any]) -> bool:
    protocol = str(case.get("protocol", ""))
    mutation = case.get("mutation", {}) or {}
    field = str(mutation.get("field", ""))
    strategy = str(mutation.get("strategy", ""))
    if protocol in {"arp", "icmpv6"}:
        return True
    if field in {"tcp.flags", "icmpv6.nd_ra_ns_na"}:
        return True
    return strategy in {"sequence_error", "conflict_mapping"}
