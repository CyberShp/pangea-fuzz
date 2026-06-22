from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any, Iterator


def write_multi_mode_report(data: dict[str, Any], output_json: Path | None, output_md: Path | None) -> None:
    if output_json:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    if output_md:
        output_md.parent.mkdir(parents=True, exist_ok=True)
        output_md.write_text(MultiModeReportGenerator.render_markdown(data), encoding="utf-8")


class MultiModeReportGenerator:
    def __init__(self, artifacts_root: Path):
        self.artifacts_root = artifacts_root

    def build(self) -> dict[str, Any]:
        summaries = list(self._read_case_summaries())
        run_summaries = list(self._read_run_summaries())
        modes = Counter(summary.get("mode", _infer_mode(summary, path)) for path, summary in summaries)
        verdicts = Counter(str(summary.get("verdict", "<unknown>")) for _, summary in summaries)
        trust = Counter(str(summary.get("trust_level", "host_only")) for _, summary in run_summaries)
        missing_evidence = Counter()
        artifact_bytes = 0
        pruning = Counter()
        failure_buckets = Counter()
        incomplete_runs = 0
        for path, summary in run_summaries:
            artifact_bytes += int(summary.get("artifact_bytes") or 0)
            if summary.get("missing_summary_cases") or summary.get("fatal_stop_reason"):
                incomplete_runs += 1
            for item in summary.get("missing_evidence") or []:
                missing_evidence[str(item)] += 1
            stats = summary.get("artifact_stats") or {}
            for key in ("pruned", "compressed", "truncated"):
                pruning[key] += int(stats.get(key) or 0)
            for bucket in summary.get("failure_buckets") or []:
                failure_buckets[str(bucket.get("bucket_key", "<unknown>"))] += int(bucket.get("seen_count") or 0)
        failures = [
            {
                "case_dir": str(path.parent),
                "mode": summary.get("mode", _infer_mode(summary, path)),
                "verdict": summary.get("verdict", "<unknown>"),
                "reason": (summary.get("reasons") or [summary.get("reason", "<无原因>")])[0],
                "trust_level": summary.get("trust_level", "host_only"),
                "bucket_key": summary.get("bucket_key"),
            }
            for path, summary in summaries
            if str(summary.get("verdict", "")).startswith("FAIL_")
        ]
        return {
            "report_schema": "pangea_fuzz_multi_mode_report.v2",
            "artifacts_root": str(self.artifacts_root),
            "execution": {
                "executed_cases": len(summaries),
                "mode_counts": dict(sorted(modes.items())),
                "verdict_counts": dict(sorted(verdicts.items())),
                "failed_cases": len(failures),
                "run_count": len(run_summaries),
                "incomplete_runs": incomplete_runs,
            },
            "trust": {
                "trust_level_counts": dict(sorted(trust.items())),
                "missing_evidence_counts": dict(sorted(missing_evidence.items())),
            },
            "artifacts": {
                "artifact_bytes": artifact_bytes,
                "pruning_counts": dict(sorted(pruning.items())),
            },
            "failure_buckets": [
                {"bucket_key": key, "count": count}
                for key, count in failure_buckets.most_common(100)
            ],
            "failures": failures[:200],
        }

    @staticmethod
    def render_markdown(data: dict[str, Any]) -> str:
        lines = [
            "# Pangea Fuzz 多模式总览报告",
            "",
            "## 1. 执行摘要",
            "",
            f"- Run 数：{data['execution']['run_count']}",
            f"- 执行用例数：{data['execution']['executed_cases']}",
            f"- 失败用例数：{data['execution']['failed_cases']}",
            f"- 不完整 run 数：{data['execution']['incomplete_runs']}",
            f"- 产物总量：{_fmt_bytes(data['artifacts']['artifact_bytes'])}",
            "",
            "## 2. Mode 分布",
            "",
            "| Mode | 数量 |",
            "|---|---:|",
        ]
        for mode, count in data["execution"]["mode_counts"].items():
            lines.append(f"| `{mode}` | {count} |")
        lines.extend(["", "## 3. Verdict 分布", "", "| Verdict | 数量 |", "|---|---:|"])
        for verdict, count in data["execution"]["verdict_counts"].items():
            lines.append(f"| `{verdict}` | {count} |")
        lines.extend(["", "## 4. 可信度与缺失证据", "", "| Trust Level | Run 数 |", "|---|---:|"])
        for trust, count in data["trust"]["trust_level_counts"].items():
            lines.append(f"| `{trust}` | {count} |")
        lines.extend(["", "| 缺失证据 | 次数 |", "|---|---:|"])
        if data["trust"]["missing_evidence_counts"]:
            for item, count in data["trust"]["missing_evidence_counts"].items():
                lines.append(f"| `{item}` | {count} |")
        else:
            lines.append("| 无 | 0 |")
        lines.extend(["", "## 5. 产物预算与裁剪", "", "| 项目 | 数量 |", "|---|---:|"])
        lines.append(f"| 产物字节数 | {data['artifacts']['artifact_bytes']} |")
        for key, count in data["artifacts"]["pruning_counts"].items():
            lines.append(f"| `{key}` | {count} |")
        lines.extend(["", "## 6. Failure Bucket", "", "| Bucket | 数量 |", "|---|---:|"])
        if data["failure_buckets"]:
            for bucket in data["failure_buckets"][:50]:
                lines.append(f"| `{bucket['bucket_key']}` | {bucket['count']} |")
        else:
            lines.append("| 无 | 0 |")
        lines.extend(["", "## 7. 失败样本", ""])
        if not data["failures"]:
            lines.append("未发现失败用例。")
        else:
            lines.extend(["| Mode | Verdict | Trust | 原因 | 路径 |", "|---|---|---|---|---|"])
            for failure in data["failures"]:
                lines.append(
                    f"| `{failure['mode']}` | `{failure['verdict']}` | `{failure['trust_level']}` | "
                    f"{failure['reason']} | `{failure['case_dir']}` |"
                )
        return "\n".join(lines) + "\n"

    def _read_case_summaries(self) -> Iterator[tuple[Path, dict[str, Any]]]:
        if not self.artifacts_root.exists():
            return
        for path in sorted(self.artifacts_root.glob("**/case-*/summary.json")):
            try:
                yield path, json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue

    def _read_run_summaries(self) -> Iterator[tuple[Path, dict[str, Any]]]:
        if not self.artifacts_root.exists():
            return
        for path in sorted(self.artifacts_root.glob("**/run-summary.json")):
            try:
                yield path, json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue


def _infer_mode(summary: dict[str, Any], path: Path) -> str:
    schema = str(summary.get("run_schema") or summary.get("report_schema") or "")
    if "kv" in schema:
        return "nvme_kv"
    if "net_protocol" in schema:
        return "net_protocol"
    if "nvmetcp" in schema:
        return "nvmetcp_tls"
    if "operation" in summary or "nvme_status" in summary:
        return "nvme_kv"
    if "protocol" in summary:
        return "net_protocol"
    if "engine" in summary:
        return "nvmetcp_tls"
    return "<unknown>"


def _fmt_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    number = float(value)
    for unit in units:
        if number < 1024 or unit == units[-1]:
            return f"{number:.1f}{unit}"
        number /= 1024
    return f"{value}B"

