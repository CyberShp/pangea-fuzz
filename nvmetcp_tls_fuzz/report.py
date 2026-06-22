from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import json
from typing import Any, Iterable


EXPECTED_VERDICTS = (
    "PASS_VALID",
    "PASS_REJECTED",
    "PASS_DISCONNECTED",
    "FAIL_SAFETY",
    "FAIL_HANG",
    "FAIL_CLEANUP",
    "FAIL_ORACLE",
    "FAIL_INFRA",
)


NIC_CHECKLIST = (
    {
        "item": "记录网卡 offload 状态",
        "command": "ethtool -k <iface>",
        "reason": "TSO/GSO/GRO/LRO/checksum offload 会改变抓包形态；报告里必须记录，必要时为可复现实验关闭。",
    },
    {
        "item": "记录队列和中断亲和性",
        "command": "ethtool -l <iface>; ethtool -x <iface>; cat /proc/interrupts",
        "reason": "多队列和 RSS 会影响 NVMe/TCP 队列时序与 race 复现概率。",
    },
    {
        "item": "记录 MTU 和链路状态",
        "command": "ip -d link show <iface>; ethtool <iface>",
        "reason": "MTU、速率、duplex、pause frame 会影响 PDU 分片、吞吐和 timeout。",
    },
    {
        "item": "记录拥塞控制与 TCP 参数",
        "command": "sysctl net.ipv4.tcp_congestion_control net.ipv4.tcp_retries2 net.ipv4.tcp_keepalive_time",
        "reason": "网络故障注入和断链恢复依赖 TCP 超时策略。",
    },
    {
        "item": "记录 NVMe/TCP 模块参数和内核日志",
        "command": "modinfo nvme_tcp; dmesg --ctime --color=never",
        "reason": "用于解释 reconnect、controller loss timeout、TLS/keyring 失败路径。",
    },
    {
        "item": "故障注入前后保存 qdisc/防火墙状态",
        "command": "tc -s qdisc show dev <iface>; iptables-save 或 nft list ruleset",
        "reason": "避免把注入规则残留误判为协议 bug。",
    },
)


@dataclass(frozen=True)
class ReportInput:
    campaign_path: Path | None = None
    artifacts_dir: Path | None = None


class ReportGenerator:
    def __init__(self, report_input: ReportInput):
        self.report_input = report_input

    @classmethod
    def from_files(
        cls,
        *,
        campaign_path: str | Path | None,
        artifacts_dir: str | Path | None,
    ) -> "ReportGenerator":
        return cls(
            ReportInput(
                Path(campaign_path) if campaign_path else None,
                Path(artifacts_dir) if artifacts_dir else None,
            )
        )

    def build(self) -> dict[str, Any]:
        campaign_cases = list(self._read_campaign_cases())
        artifact_runs = list(self._read_artifact_runs())

        pdu_counter = Counter(case.get("pdu_type", "<unknown>") for case in campaign_cases)
        strategy_counter = Counter(_mutation(case).get("strategy", "<unknown>") for case in campaign_cases)
        field_counter = Counter(_mutation(case).get("field", "<unknown>") for case in campaign_cases)
        command_counter = Counter(case.get("command", "<unknown>") for case in campaign_cases)
        direction_counter = Counter(case.get("direction", "<unknown>") for case in campaign_cases)
        verdict_counter = Counter(run["summary"].get("verdict", "<unknown>") for run in artifact_runs)

        failures = self._bucket_failures(artifact_runs)
        planned = len(campaign_cases)
        executed = len(artifact_runs)
        failed = sum(count for verdict, count in verdict_counter.items() if str(verdict).startswith("FAIL_"))

        return {
            "report_schema": "nvmetcp_tls_fuzz_report.v1",
            "campaign": {
                "planned_cases": planned,
                "random_mutation_cases": sum(1 for case in campaign_cases if case.get("random_mutation")),
                "grammar_mutation_cases": sum(1 for case in campaign_cases if not case.get("random_mutation")),
                "commands": dict(sorted(command_counter.items())),
                "directions": dict(sorted(direction_counter.items())),
            },
            "coverage": {
                "pdu_types": _coverage_summary(pdu_counter),
                "strategies": _coverage_summary(strategy_counter),
                "fields": _coverage_summary(field_counter),
            },
            "execution": {
                "executed_cases": executed,
                "execution_rate": _ratio(executed, planned),
                "verdict_counts": {verdict: verdict_counter.get(verdict, 0) for verdict in EXPECTED_VERDICTS},
                "failed_cases": failed,
                "failure_rate": _ratio(failed, executed),
            },
            "failures": failures,
            "environment": {
                "nic_host_checklist": list(NIC_CHECKLIST),
                "required_artifacts": [
                    "case.yaml",
                    "summary.json",
                    "pdu-trace.jsonl",
                    "dmesg.log",
                    "fio.json",
                    "nvme-before.json",
                    "nvme-after.json",
                    "tcpdump.pcap",
                ],
            },
            "industry_mapping": {
                "coverage_matrix": "类似 AFL/libFuzzer/OSS-Fuzz 的覆盖率摘要；本项目按 PDU、字段、策略统计。",
                "crash_buckets": "类似 ClusterFuzz crash bucket；本项目按 verdict、reason、PDU、字段聚合。",
                "reproducer": "每个失败 run 需要保留 seed、case.yaml、PDU trace 和 host artifacts。",
                "corpus": "campaign.jsonl 是输入 corpus，artifacts/ 是执行证据和失败样本集合。",
            },
        }

    @staticmethod
    def render_markdown(report: dict[str, Any]) -> str:
        campaign = report["campaign"]
        coverage = report["coverage"]
        execution = report["execution"]
        failures = report["failures"]
        checklist = report["environment"]["nic_host_checklist"]

        lines = [
            "# 业界风格 Fuzz 报告",
            "",
            "## 1. 执行摘要",
            "",
            f"- 计划用例数：{campaign['planned_cases']}",
            f"- 已执行用例数：{execution['executed_cases']}",
            f"- 执行覆盖率：{execution['execution_rate']:.2%}",
            f"- 随机变异用例数：{campaign['random_mutation_cases']}",
            f"- 语法感知变异用例数：{campaign['grammar_mutation_cases']}",
            f"- 失败用例数：{execution['failed_cases']}",
            f"- 失败率：{execution['failure_rate']:.2%}",
            "",
            "## 2. 覆盖率矩阵",
            "",
            _render_coverage_table("PDU 类型覆盖", coverage["pdu_types"]),
            "",
            _render_coverage_table("变异策略覆盖", coverage["strategies"]),
            "",
            _render_coverage_table("字段覆盖", coverage["fields"], limit=30),
            "",
            "## 3. Verdict 分布",
            "",
            "| Verdict | 数量 |",
            "|---|---:|",
        ]
        for verdict, count in execution["verdict_counts"].items():
            lines.append(f"| `{verdict}` | {count} |")

        lines.extend(["", "## 4. Crash / 失败桶", ""])
        if failures:
            lines.extend(["| Verdict | 原因 | PDU | 字段 | 数量 | 复现路径 |", "|---|---|---|---|---:|---|"])
            for failure in failures[:50]:
                lines.append(
                    f"| `{failure['verdict']}` | {failure['reason']} | `{failure['pdu_type']}` | "
                    f"`{failure['field']}` | {failure['count']} | `{failure['example_run']}` |"
                )
        else:
            lines.append("未发现失败桶。")

        lines.extend(["", "## 5. 网卡 / 主机配置检查清单", "", "| 检查项 | 命令 | 原因 |", "|---|---|---|"])
        for item in checklist:
            lines.append(f"| {item['item']} | `{item['command']}` | {item['reason']} |")

        lines.extend(
            [
                "",
                "## 6. 行业报告字段映射",
                "",
                "- AFL/libFuzzer 常见项：执行次数、crash、hang、corpus、覆盖率。本报告对应 campaign、verdict、artifacts、覆盖率矩阵。",
                "- OSS-Fuzz/ClusterFuzz 常见项：crash bucket、可复现 testcase、日志、回归范围。本报告对应失败桶、case.yaml、pdu-trace、host artifacts。",
                "- GitLab/CI fuzz 常见项：JSON report + artifacts.zip。本工具输出 JSON 报告和 Markdown 报告，并保留 artifacts 目录。",
                "",
                "## 7. 结论建议",
                "",
                "- `FAIL_SAFETY`、`FAIL_HANG`、`FAIL_CLEANUP`、`FAIL_ORACLE` 必须优先分析。",
                "- `PASS_REJECTED` 和 `PASS_DISCONNECTED` 是非法输入的可接受结果，但仍需检查是否存在资源泄漏。",
                "- 报告归档时必须同时保存 campaign、artifacts、内核版本、nvme-cli 版本、网卡配置和 TLS/keyring 配置。",
                "",
            ]
        )
        return "\n".join(lines)

    def _read_campaign_cases(self) -> Iterable[dict[str, Any]]:
        path = self.report_input.campaign_path
        if not path or not path.exists():
            return []
        cases: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped:
                    cases.append(json.loads(stripped))
        return cases

    def _read_artifact_runs(self) -> Iterable[dict[str, Any]]:
        root = self.report_input.artifacts_dir
        if not root or not root.exists():
            return []
        runs: list[dict[str, Any]] = []
        for summary_path in sorted(root.glob("**/summary.json")):
            run_dir = summary_path.parent
            summary = _load_json(summary_path)
            if summary.get("run_schema") and not str(summary.get("run_schema")).startswith("nvmetcp"):
                continue
            case = _load_case(run_dir / "case.yaml")
            runs.append({"run_dir": str(run_dir), "summary": summary, "case": case})
        return runs

    def _bucket_failures(self, runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        buckets: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        for run in runs:
            summary = run["summary"]
            verdict = str(summary.get("verdict", "<unknown>"))
            if not verdict.startswith("FAIL_"):
                continue
            case = run.get("case", {})
            mutation = _mutation(case)
            reasons = summary.get("reasons", []) or ["<no reason>"]
            reason = str(reasons[0])
            key = (verdict, reason, str(case.get("pdu_type", "<unknown>")), str(mutation.get("field", "<unknown>")))
            bucket = buckets.setdefault(
                key,
                {
                    "verdict": verdict,
                    "reason": reason,
                    "pdu_type": key[2],
                    "field": key[3],
                    "count": 0,
                    "example_run": run["run_dir"],
                    "example_seed": case.get("seed"),
                },
            )
            bucket["count"] += 1
        return sorted(buckets.values(), key=lambda item: (-item["count"], item["verdict"], item["reason"]))


def write_report_files(report: dict[str, Any], output_json: Path | None, output_markdown: Path | None) -> None:
    if output_json:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    if output_markdown:
        output_markdown.parent.mkdir(parents=True, exist_ok=True)
        output_markdown.write_text(ReportGenerator.render_markdown(report), encoding="utf-8")


def _mutation(case: dict[str, Any]) -> dict[str, Any]:
    mutation = case.get("mutation", {})
    return mutation if isinstance(mutation, dict) else {}


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_case(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _coverage_summary(counter: Counter) -> dict[str, Any]:
    total = sum(counter.values())
    items = dict(sorted(counter.items()))
    return {
        "covered": len(counter),
        "total_observations": total,
        "covered_items": list(items.keys()),
        "counts": items,
    }


def _ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return numerator / denominator


def _render_coverage_table(title: str, coverage: dict[str, Any], limit: int | None = None) -> str:
    lines = [
        f"### {title}",
        "",
        f"- 覆盖项数量：{coverage['covered']}",
        f"- 观测总数：{coverage['total_observations']}",
        "",
        "| 项 | 数量 |",
        "|---|---:|",
    ]
    counts = list(coverage["counts"].items())
    if limit is not None:
        counts = counts[:limit]
    for item, count in counts:
        lines.append(f"| `{item}` | {count} |")
    return "\n".join(lines)
