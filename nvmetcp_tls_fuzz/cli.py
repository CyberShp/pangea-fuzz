from __future__ import annotations

import argparse
import json
from pathlib import Path

from .campaign import CampaignConfig, CampaignGenerator, DEFAULT_CASE_COUNT, DEFAULT_RANDOM_RATIO
from .case_generator import CaseGenerator
from .catalog import FieldCatalog
from .oracle import OracleAnalyzer
from .report import ReportGenerator, write_report_files
from .run import RunConfig, RunOrchestrator


def main() -> None:
    parser = argparse.ArgumentParser(prog="nvmetcp-tls-fuzz")
    subcommands = parser.add_subparsers(dest="command_name", required=True)

    gen = subcommands.add_parser("generate-case")
    gen.add_argument("--catalog", default="field_catalog.yaml")
    gen.add_argument("--seed", type=int, required=True)
    gen.add_argument("--direction", default="both", choices=["host", "target", "both"])
    gen.add_argument("--pdu-type")
    gen.add_argument("--command", default="read")
    gen.add_argument("--strategy")

    campaign = subcommands.add_parser("generate-campaign")
    campaign.add_argument("--catalog", default="field_catalog.yaml")
    campaign.add_argument("--seed", type=int, required=True)
    campaign.add_argument("--count", type=int, default=DEFAULT_CASE_COUNT)
    campaign.add_argument("--random-ratio", type=float, default=DEFAULT_RANDOM_RATIO)
    campaign.add_argument("--output", type=Path, required=True)
    campaign.add_argument("--summary", action="store_true")

    analyze = subcommands.add_parser("analyze")
    analyze.add_argument("--dmesg", type=Path)
    analyze.add_argument("--fio-json", type=Path)
    analyze.add_argument("--nvme-before", type=Path)
    analyze.add_argument("--nvme-after", type=Path)
    analyze.add_argument("--timed-out", action="store_true")

    report = subcommands.add_parser("generate-report")
    report.add_argument("--campaign", type=Path)
    report.add_argument("--artifacts-dir", type=Path)
    report.add_argument("--output-json", type=Path)
    report.add_argument("--output-md", type=Path)

    run = subcommands.add_parser("run")
    run.add_argument("--campaign", type=Path, required=True)
    run.add_argument("--artifacts-dir", type=Path, required=True)
    run.add_argument("--engine", choices=["fio", "vdbench"], default="fio")
    run.add_argument("--device", required=True)
    run.add_argument("--workers", type=int, default=1)
    run.add_argument("--shard-index", type=int, default=0)
    run.add_argument("--shard-count", type=int, default=1)
    run.add_argument("--runtime", type=int, default=5)
    run.add_argument("--timeout", type=int, default=120)
    run.add_argument("--limit", type=int)
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("--allow-write", action="store_true")
    run.add_argument("--fio-template")

    args = parser.parse_args()
    if args.command_name == "generate-case":
        catalog = FieldCatalog.from_yaml(args.catalog)
        case = CaseGenerator(catalog).generate(
            seed=args.seed,
            direction=args.direction,
            pdu_type=args.pdu_type,
            command=args.command,
            strategy=args.strategy,
        )
        print(json.dumps(case.to_dict(), indent=2, sort_keys=True))
        return

    if args.command_name == "generate-campaign":
        catalog = FieldCatalog.from_yaml(args.catalog)
        config = CampaignConfig(seed=args.seed, count=args.count, random_ratio=args.random_ratio)
        generator = CampaignGenerator(catalog)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as handle:
            for item in generator.iter_cases(config):
                handle.write(json.dumps(item.to_dict(), sort_keys=True) + "\n")
        if args.summary:
            print(json.dumps(generator.summary(config), indent=2, sort_keys=True))
        return

    if args.command_name == "generate-report":
        report_data = ReportGenerator.from_files(
            campaign_path=args.campaign,
            artifacts_dir=args.artifacts_dir,
        ).build()
        if args.output_json or args.output_md:
            write_report_files(report_data, args.output_json, args.output_md)
        else:
            print(ReportGenerator.render_markdown(report_data))
        return

    if args.command_name == "run":
        result = RunOrchestrator(
            RunConfig(
                campaign_path=args.campaign,
                artifacts_dir=args.artifacts_dir,
                engine=args.engine,
                device=args.device,
                workers=args.workers,
                shard_index=args.shard_index,
                shard_count=args.shard_count,
                runtime_s=args.runtime,
                timeout_s=args.timeout,
                limit=args.limit,
                dry_run=args.dry_run,
                allow_write=args.allow_write,
                fio_template=args.fio_template,
            )
        ).run()
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
        return

    fio_json = _load_json(args.fio_json)
    result = OracleAnalyzer().analyze(
        dmesg=_load_text(args.dmesg),
        fio_json=fio_json,
        nvme_before=_load_json(args.nvme_before) or {},
        nvme_after=_load_json(args.nvme_after) or {},
        timed_out=args.timed_out,
    )
    print(json.dumps({"verdict": result.verdict, "reasons": list(result.reasons)}, indent=2))


def _load_text(path: Path | None) -> str:
    if not path:
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _load_json(path: Path | None) -> dict | None:
    if not path:
        return None
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
