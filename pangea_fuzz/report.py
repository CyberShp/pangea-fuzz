from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any


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
        summaries = list(self._read_summaries())
        modes = Counter(summary.get("mode", _infer_mode(summary, path)) for path, summary in summaries)
        verdicts = Counter(str(summary.get("verdict", "<unknown>")) for _, summary in summaries)
        failures = [
            {
                "run_dir": str(path.parent),
                "mode": summary.get("mode", _infer_mode(summary, path)),
                "verdict": summary.get("verdict", "<unknown>"),
                "reason": (summary.get("reasons") or [summary.get("reason", "<no reason>")])[0],
            }
            for path, summary in summaries
            if str(summary.get("verdict", "")).startswith("FAIL_")
        ]
        return {
            "report_schema": "pangea_fuzz_multi_mode_report.v1",
            "artifacts_root": str(self.artifacts_root),
            "execution": {
                "executed_cases": len(summaries),
                "mode_counts": dict(sorted(modes.items())),
                "verdict_counts": dict(sorted(verdicts.items())),
                "failed_cases": len(failures),
            },
            "failures": failures,
        }

    @staticmethod
    def render_markdown(data: dict[str, Any]) -> str:
        lines = [
            "# Pangea Fuzz 多模式总览报告",
            "",
            "## 1. 执行摘要",
            "",
            f"- 执行用例数：{data['execution']['executed_cases']}",
            f"- 失败用例数：{data['execution']['failed_cases']}",
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
        lines.extend(["", "## 4. 失败桶", ""])
        if not data["failures"]:
            lines.append("未发现失败用例。")
        else:
            lines.extend(["| Mode | Verdict | 原因 | 路径 |", "|---|---|---|---|"])
            for failure in data["failures"][:100]:
                lines.append(f"| `{failure['mode']}` | `{failure['verdict']}` | {failure['reason']} | `{failure['run_dir']}` |")
        return "\n".join(lines) + "\n"

    def _read_summaries(self):
        if not self.artifacts_root.exists():
            return
        for path in sorted(self.artifacts_root.glob("**/case-*/summary.json")):
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
