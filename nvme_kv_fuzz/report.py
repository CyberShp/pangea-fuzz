from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Iterable


def c(text: str) -> str:
    return text.encode("ascii").decode("unicode_escape")


EXPECTED_VERDICTS = (
    "PASS_VALID",
    "PASS_REJECTED",
    "PASS_RECOVERED",
    "FAIL_SAFETY",
    "FAIL_HANG",
    "FAIL_CLEANUP",
    "FAIL_ORACLE",
    "FAIL_INFRA",
)

ENV_CHECKLIST = (
    (c(r"NVMe \u8bbe\u5907\u5217\u8868"), "nvme list -v -o json", c(r"\u786e\u8ba4\u76ee\u6807 namespace\u3001model\u3001serial \u548c\u8def\u5f84\u6ca1\u6709\u6f02\u79fb\u3002")),
    (c(r"\u63a7\u5236\u5668\u4fe1\u606f"), "nvme id-ctrl <device>", c(r"\u5b9a\u4f4d KV opcode \u652f\u6301\u3001firmware\u3001controller capability\u3002")),
    (c(r"Namespace \u4fe1\u606f"), "nvme id-ns <device>", c(r"\u786e\u8ba4 NSID\u3001\u5bb9\u91cf\u548c\u683c\u5f0f\u672a\u88ab\u5176\u4ed6\u6d4b\u8bd5\u6539\u52a8\u3002")),
    (c(r"NOF \u5b50\u7cfb\u7edf"), "nvme list-subsys", c(r"\u8bb0\u5f55 NQN\u3001transport\u3001traddr\u3001reconnect \u72b6\u6001\u3002")),
    (c(r"\u5185\u6838\u65e5\u5fd7"), "dmesg --ctime --color=never", c(r"\u5b9a\u4f4d timeout\u3001reset\u3001oops\u3001controller fatal\u3002")),
    (c(r"NVMe fabrics \u6a21\u5757"), "modinfo nvme_tcp; modinfo nvme_fabrics", c(r"\u8bb0\u5f55\u4e3b\u673a NOF \u9a71\u52a8\u7248\u672c\u548c\u53c2\u6570\u3002")),
    (c(r"\u7f51\u7edc\u63a5\u53e3"), "ethtool -k <iface>; ip -d link", c(r"\u8bb0\u5f55 offload\u3001MTU\u3001\u961f\u5217\uff0c\u4fdd\u8bc1\u590d\u73b0\u6761\u4ef6\u53ef\u89e3\u91ca\u3002")),
)


@dataclass(frozen=True)
class ReportInput:
    campaign_path: Path | None = None
    artifacts_dir: Path | None = None


class ReportGenerator:
    def __init__(self, report_input: ReportInput):
        self.report_input = report_input

    @classmethod
    def from_files(cls, *, campaign_path: str | Path | None, artifacts_dir: str | Path | None) -> "ReportGenerator":
        return cls(ReportInput(Path(campaign_path) if campaign_path else None, Path(artifacts_dir) if artifacts_dir else None))

    def build(self) -> dict[str, Any]:
        campaign_cases = list(self._read_campaign_cases())
        artifact_runs = list(self._read_artifact_runs())
        operation_counter = Counter(str(case.get("operation", "<unknown>")) for case in campaign_cases)
        field_counter = Counter(str(_mutation(case).get("field", "<unknown>")) for case in campaign_cases)
        strategy_counter = Counter(str(_mutation(case).get("strategy", "<unknown>")) for case in campaign_cases)
        legality_counter = Counter(_legality(case) for case in campaign_cases)
        status_counter = Counter(str(run["summary"].get("nvme_status") or "<none>") for run in artifact_runs)
        verdict_counter = Counter(str(run["summary"].get("verdict", "<unknown>")) for run in artifact_runs)
        failures = self._bucket_failures(artifact_runs)
        planned = len(campaign_cases)
        executed = len(artifact_runs)
        failed = sum(count for verdict, count in verdict_counter.items() if verdict.startswith("FAIL_"))
        fuse_reasons = [run["summary"].get("reason") for run in artifact_runs if str(run["summary"].get("reason", "")).startswith("fuse")]

        return {
            "report_schema": "nvme_kv_fuzz_report.v1",
            "campaign": {
                "planned_cases": planned,
                "random_mutation_cases": sum(1 for case in campaign_cases if case.get("random_mutation")),
                "grammar_mutation_cases": sum(1 for case in campaign_cases if not case.get("random_mutation")),
                "operations": dict(sorted(operation_counter.items())),
            },
            "coverage": {
                "operations": _coverage_summary(operation_counter),
                "fields": _coverage_summary(field_counter),
                "strategies": _coverage_summary(strategy_counter),
                "legalities": _coverage_summary(legality_counter),
                "nvme_status": _coverage_summary(status_counter),
            },
            "execution": {
                "executed_cases": executed,
                "execution_rate": _ratio(executed, planned),
                "verdict_counts": {verdict: verdict_counter.get(verdict, 0) for verdict in EXPECTED_VERDICTS},
                "failed_cases": failed,
                "failure_rate": _ratio(failed, executed),
                "fuse_reasons": [reason for reason in fuse_reasons if reason],
            },
            "failures": failures,
            "semantic_consistency": {
                "store_retrieve": c(r"store \u6210\u529f\u540e retrieve \u5fc5\u987b\u8fd4\u56de\u540c value\u3002"),
                "delete_exist": c(r"delete \u540e exist/retrieve \u5e94\u8fd4\u56de key-not-exist \u7c7b\u72b6\u6001\u3002"),
                "list_prefix": c(r"list \u8fd4\u56de\u7ed3\u6784\u5fc5\u987b\u53ef\u89e3\u6790\uff0ckey \u957f\u5ea6\u5408\u6cd5\u4e14\u4e0d\u80fd\u8d8a\u754c\u3002"),
                "overwrite_option": c(r"duplicate store/option conflict \u4e0d\u5141\u8bb8 silent corruption\u3002"),
                "buffer_too_small": c(r"buffer too small \u4e0d\u5141\u8bb8\u4ee5\u6210\u529f\u72b6\u6001\u9759\u9ed8\u622a\u65ad\u3002"),
            },
            "environment": {
                "checklist": [{"item": item, "command": command, "reason": reason} for item, command, reason in ENV_CHECKLIST],
                "required_artifacts": [
                    "case.yaml",
                    "command.json",
                    "kv-trace.jsonl",
                    "summary.json",
                    "stdout.log",
                    "stderr.log",
                    "nvme-before.json",
                    "nvme-after.json",
                    "dmesg-before.log",
                    "dmesg-after.log",
                    "journal-kernel.log",
                ],
            },
            "industry_mapping": {
                "corpus": c(r"campaign.jsonl \u5bf9\u5e94 fuzz corpus\u3002"),
                "crash_bucket": c(r"failures[] \u6309 verdict/reason/operation/field/strategy/status \u805a\u7c7b\u3002"),
                "reproducer": c(r"summary.replay_command \u548c case.yaml \u5bf9\u5e94\u53ef\u590d\u73b0 testcase\u3002"),
                "coverage": c(r"coverage.* \u5bf9\u5e94 operation/field/strategy/status \u8986\u76d6\u77e9\u9635\u3002"),
                "artifacts_zip": c(r"artifacts/ \u53ef\u76f4\u63a5\u6253\u5305\u4f5c\u4e3a CI fuzz artifact\u3002"),
            },
        }

    @staticmethod
    def render_markdown(report: dict[str, Any]) -> str:
        campaign = report["campaign"]
        execution = report["execution"]
        coverage = report["coverage"]
        lines = [
            c(r"# \u539f\u751f KV over NOF Fuzz \u62a5\u544a"),
            "",
            c(r"## 1. \u6267\u884c\u6458\u8981"),
            "",
            c(rf"- \u8ba1\u5212\u7528\u4f8b\u6570\uff1a{campaign['planned_cases']}"),
            c(rf"- \u5df2\u6267\u884c\u7528\u4f8b\u6570\uff1a{execution['executed_cases']}"),
            c(rf"- \u6267\u884c\u8986\u76d6\u7387\uff1a{execution['execution_rate']:.2%}"),
            c(rf"- \u8bed\u6cd5\u611f\u77e5\u53d8\u5f02\u7528\u4f8b\u6570\uff1a{campaign['grammar_mutation_cases']}"),
            c(rf"- \u968f\u673a\u53d8\u5f02\u7528\u4f8b\u6570\uff1a{campaign['random_mutation_cases']}"),
            c(rf"- \u5931\u8d25\u7528\u4f8b\u6570\uff1a{execution['failed_cases']}"),
            c(rf"- \u5931\u8d25\u7387\uff1a{execution['failure_rate']:.2%}"),
        ]
        if execution["fuse_reasons"]:
            lines.append(c(r"- \u7194\u65ad\u539f\u56e0\uff1a") + "; ".join(execution["fuse_reasons"]))
        lines.extend(["", c(r"## 2. KV \u8986\u76d6\u77e9\u9635"), ""])
        lines.append(_render_coverage_table(c(r"Operation \u8986\u76d6"), coverage["operations"]))
        lines.append("")
        lines.append(_render_coverage_table(c(r"\u5b57\u6bb5\u8986\u76d6"), coverage["fields"], limit=40))
        lines.append("")
        lines.append(_render_coverage_table(c(r"\u53d8\u5f02\u7b56\u7565\u8986\u76d6"), coverage["strategies"]))
        lines.append("")
        lines.append(_render_coverage_table(c(r"\u5408\u6cd5 / \u975e\u6cd5\u8f93\u5165\u8986\u76d6"), coverage["legalities"]))
        lines.append("")
        lines.append(_render_coverage_table(c(r"NVMe Status \u8986\u76d6"), coverage["nvme_status"]))
        lines.extend(["", c(r"## 3. Verdict \u5206\u5e03"), "", c(r"| Verdict | \u6570\u91cf |"), "|---|---:|"])
        for verdict, count in execution["verdict_counts"].items():
            lines.append(f"| `{verdict}` | {count} |")

        lines.extend(["", c(r"## 4. \u5931\u8d25\u6876"), ""])
        if report["failures"]:
            lines.extend([
                c(r"| Verdict | \u539f\u56e0 | Operation | \u5b57\u6bb5 | \u7b56\u7565 | NVMe Status | \u6570\u91cf | \u590d\u73b0\u8def\u5f84 |"),
                "|---|---|---|---|---|---|---:|---|",
            ])
            for failure in report["failures"][:50]:
                lines.append(
                    f"| `{failure['verdict']}` | {failure['reason']} | `{failure['operation']}` | "
                    f"`{failure['field']}` | `{failure['strategy']}` | `{failure['nvme_status']}` | "
                    f"{failure['count']} | `{failure['example_run']}` |"
                )
        else:
            lines.append(c(r"\u672a\u53d1\u73b0\u5931\u8d25\u6876\u3002"))

        lines.extend(["", c(r"## 5. \u8bed\u4e49\u4e00\u81f4\u6027"), ""])
        for key, value in report["semantic_consistency"].items():
            lines.append(f"- `{key}`: {value}")

        lines.extend([
            "",
            c(r"## 6. \u4e3b\u673a / \u7f51\u7edc / NOF \u73af\u5883"),
            "",
            c(r"| \u68c0\u67e5\u9879 | \u547d\u4ee4 | \u539f\u56e0 |"),
            "|---|---|---|",
        ])
        for item in report["environment"]["checklist"]:
            lines.append(f"| {item['item']} | `{item['command']}` | {item['reason']} |")

        lines.extend(["", c(r"## 7. \u884c\u4e1a\u62a5\u544a\u6620\u5c04"), ""])
        for key, value in report["industry_mapping"].items():
            lines.append(f"- `{key}`: {value}")
        lines.append("")
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
            if summary_path.parent.name == "env":
                continue
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            case_path = summary_path.parent / "case.yaml"
            case = json.loads(case_path.read_text(encoding="utf-8")) if case_path.exists() else {}
            runs.append({"run_dir": str(summary_path.parent), "summary": summary, "case": case})
        return runs

    def _bucket_failures(self, runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        buckets: dict[str, dict[str, Any]] = {}
        for run in runs:
            summary = run["summary"]
            verdict = str(summary.get("verdict", "<unknown>"))
            if not verdict.startswith("FAIL_"):
                continue
            key = str(summary.get("bucket_key") or "|".join(
                [
                    verdict,
                    str(summary.get("reason", "<no reason>")),
                    str(summary.get("operation", "<unknown>")),
                    str(summary.get("field", "<unknown>")),
                    str(summary.get("strategy", "<unknown>")),
                    str(summary.get("nvme_status") or "<none>"),
                ]
            ))
            bucket = buckets.setdefault(
                key,
                {
                    "verdict": verdict,
                    "reason": str(summary.get("reason", "<no reason>")),
                    "operation": str(summary.get("operation", "<unknown>")),
                    "field": str(summary.get("field", "<unknown>")),
                    "strategy": str(summary.get("strategy", "<unknown>")),
                    "nvme_status": str(summary.get("nvme_status") or "<none>"),
                    "count": 0,
                    "example_run": run["run_dir"],
                    "replay_command": str(summary.get("replay_command", "")),
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


def _legality(case: dict[str, Any]) -> str:
    allowed = set((case.get("expected", {}) or {}).get("allowed", []))
    return "legal" if allowed == {"PASS_VALID"} else "illegal_or_recovery"


def _coverage_summary(counter: Counter) -> dict[str, Any]:
    total = sum(counter.values())
    items = dict(sorted(counter.items()))
    return {"covered": len(counter), "total_observations": total, "covered_items": list(items.keys()), "counts": items}


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator > 0 else 0.0


def _render_coverage_table(title: str, coverage: dict[str, Any], limit: int | None = None) -> str:
    lines = [
        f"### {title}",
        "",
        c(rf"- \u8986\u76d6\u9879\u6570\u91cf\uff1a{coverage['covered']}"),
        c(rf"- \u89c2\u6d4b\u603b\u6570\uff1a{coverage['total_observations']}"),
        "",
        c(r"| \u9879 | \u6570\u91cf |"),
        "|---|---:|",
    ]
    counts = list(coverage["counts"].items())
    if limit is not None:
        counts = counts[:limit]
    for item, count in counts:
        lines.append(f"| `{item}` | {count} |")
    return "\n".join(lines)
