from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any, Iterable


class NetReportGenerator:
    def __init__(self, campaign_path: Path | None, artifacts_dir: Path | None):
        self.campaign_path = campaign_path
        self.artifacts_dir = artifacts_dir

    def build(self) -> dict[str, Any]:
        cases = list(self._read_campaign())
        runs = list(self._read_runs())
        protocol_counter = Counter(str(case.get("protocol", "<unknown>")) for case in cases)
        field_counter = Counter(str((case.get("mutation") or {}).get("field", "<unknown>")) for case in cases)
        strategy_counter = Counter(str((case.get("mutation") or {}).get("strategy", "<unknown>")) for case in cases)
        verdict_counter = Counter(str(run.get("verdict", "<unknown>")) for run in runs)
        return {
            "report_schema": "net_protocol_fuzz_report.v1",
            "campaign": {
                "planned_cases": len(cases),
                "random_mutation_cases": sum(1 for case in cases if case.get("random_mutation")),
                "grammar_mutation_cases": sum(1 for case in cases if not case.get("random_mutation")),
            },
            "coverage": {
                "protocols": _coverage(protocol_counter),
                "fields": _coverage(field_counter),
                "strategies": _coverage(strategy_counter),
            },
            "execution": {
                "executed_cases": len(runs),
                "verdict_counts": dict(sorted(verdict_counter.items())),
                "failed_cases": sum(count for verdict, count in verdict_counter.items() if verdict.startswith("FAIL_")),
            },
            "environment": {
                "checklist": [
                    {"item": "网卡状态", "command": "ip -d link; ethtool -k <iface>", "reason": "确认 MTU、offload 和链路状态。"},
                    {"item": "路由和邻居表", "command": "ip route; ip neigh", "reason": "避免 ARP/ND 测试污染环境后无法复现。"},
                    {"item": "抓包", "command": "<tcpdump-bin> -i <iface> -w net-protocol.pcap", "reason": "保存真实发包证据；ARM 环境可替换为 tcpdump_aarch64。"},
                ]
            },
        }

    @staticmethod
    def render_markdown(report: dict[str, Any]) -> str:
        lines = [
            "# 网络协议 Fuzz 报告",
            "",
            "## 1. 执行摘要",
            "",
            f"- 计划用例数：{report['campaign']['planned_cases']}",
            f"- 已执行用例数：{report['execution']['executed_cases']}",
            f"- 失败用例数：{report['execution']['failed_cases']}",
            "",
            "## 2. 协议覆盖",
            "",
            "| 协议 | 数量 |",
            "|---|---:|",
        ]
        for item, count in report["coverage"]["protocols"]["counts"].items():
            lines.append(f"| `{item}` | {count} |")
        lines.extend(["", "## 3. 字段覆盖", "", "| 字段 | 数量 |", "|---|---:|"])
        for item, count in report["coverage"]["fields"]["counts"].items():
            lines.append(f"| `{item}` | {count} |")
        lines.extend(["", "## 4. Verdict 分布", "", "| Verdict | 数量 |", "|---|---:|"])
        for verdict, count in report["execution"]["verdict_counts"].items():
            lines.append(f"| `{verdict}` | {count} |")
        return "\n".join(lines) + "\n"

    def _read_campaign(self) -> Iterable[dict[str, Any]]:
        if not self.campaign_path or not self.campaign_path.exists():
            return []
        return [json.loads(line) for line in self.campaign_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def _read_runs(self) -> Iterable[dict[str, Any]]:
        if not self.artifacts_dir or not self.artifacts_dir.exists():
            return []
        runs: list[dict[str, Any]] = []
        for path in self.artifacts_dir.glob("case-*/summary.json"):
            runs.append(json.loads(path.read_text(encoding="utf-8")))
        return runs


def write_report_files(report: dict[str, Any], output_json: Path | None, output_md: Path | None) -> None:
    if output_json:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    if output_md:
        output_md.parent.mkdir(parents=True, exist_ok=True)
        output_md.write_text(NetReportGenerator.render_markdown(report), encoding="utf-8")


def _coverage(counter: Counter) -> dict[str, Any]:
    return {"covered": len(counter), "total_observations": sum(counter.values()), "counts": dict(sorted(counter.items()))}
