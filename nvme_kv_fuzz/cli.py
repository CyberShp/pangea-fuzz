from __future__ import annotations

import argparse
import json
from pathlib import Path

from .campaign import CampaignConfig, CampaignGenerator, DEFAULT_CASE_COUNT, DEFAULT_RANDOM_RATIO
from .case_generator import CaseGenerator
from .catalog import FieldCatalog
from .report import ReportGenerator, write_report_files
from .run import RunConfig, RunOrchestrator, collect_env


def main() -> None:
    parser = argparse.ArgumentParser(prog="nvme-kv-fuzz")
    sub = parser.add_subparsers(dest="command_name", required=True)

    gen_case = sub.add_parser("generate-case")
    gen_case.add_argument("--catalog", default="kv_field_catalog.yaml")
    gen_case.add_argument("--seed", type=int, required=True)
    gen_case.add_argument("--operation", choices=["store", "retrieve", "list", "delete", "exist"])
    gen_case.add_argument("--strategy")
    gen_case.add_argument("--key-prefix", default="kvfuzz-")
    gen_case.add_argument("--nsid", type=int, default=1)

    campaign = sub.add_parser("generate-campaign")
    campaign.add_argument("--catalog", default="kv_field_catalog.yaml")
    campaign.add_argument("--seed", type=int, required=True)
    campaign.add_argument("--count", type=int, default=DEFAULT_CASE_COUNT)
    campaign.add_argument("--random-ratio", type=float, default=DEFAULT_RANDOM_RATIO)
    campaign.add_argument("--output", type=Path, required=True)
    campaign.add_argument("--summary", action="store_true")
    campaign.add_argument("--key-prefix", default="kvfuzz-")
    campaign.add_argument("--nsid", type=int, default=1)

    run = sub.add_parser("run")
    run.add_argument("--campaign", type=Path, required=True)
    run.add_argument("--config", dest="config_path", type=Path, required=True)
    run.add_argument("--artifacts-dir", type=Path, required=True)
    run.add_argument("--limit", type=int)
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("--allow-live-target", action="store_true")
    run.add_argument("--shard-index", type=int, default=0)
    run.add_argument("--shard-count", type=int, default=1)
    run.add_argument("--stop-on-failure", action="store_true")

    replay = sub.add_parser("replay")
    replay.add_argument("case_path", type=Path)
    replay.add_argument("--config", dest="config_path", type=Path, required=True)
    replay.add_argument("--artifacts-dir", type=Path, default=Path("artifacts/replay"))
    replay.add_argument("--dry-run", action="store_true")
    replay.add_argument("--allow-live-target", action="store_true")

    minimize = sub.add_parser("minimize")
    minimize.add_argument("case_path", type=Path)
    minimize.add_argument("--config", dest="config_path", type=Path, required=True)
    minimize.add_argument("--output", type=Path)

    report = sub.add_parser("generate-report")
    report.add_argument("--campaign", type=Path)
    report.add_argument("--artifacts-dir", type=Path)
    report.add_argument("--output-json", type=Path)
    report.add_argument("--output-md", type=Path)

    env = sub.add_parser("collect-env")
    env.add_argument("--config", dest="config_path", type=Path, required=True)
    env.add_argument("--output", type=Path, required=True)

    args = parser.parse_args()
    if args.command_name == "generate-case":
        catalog = FieldCatalog.from_yaml(args.catalog)
        case = CaseGenerator(catalog, key_prefix=args.key_prefix, nsid=args.nsid).generate(
            seed=args.seed,
            operation=args.operation,
            strategy=args.strategy,
        )
        print(json.dumps(case.to_dict(), indent=2, ensure_ascii=False, sort_keys=True))
        return

    if args.command_name == "generate-campaign":
        catalog = FieldCatalog.from_yaml(args.catalog)
        config = CampaignConfig(seed=args.seed, count=args.count, random_ratio=args.random_ratio)
        generator = CampaignGenerator(catalog, key_prefix=args.key_prefix, nsid=args.nsid)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as handle:
            for item in generator.iter_cases(config):
                handle.write(json.dumps(item.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
        if args.summary:
            print(json.dumps(generator.summary(config), indent=2, ensure_ascii=False, sort_keys=True))
        return

    if args.command_name == "run":
        result = RunOrchestrator(
            RunConfig(
                campaign_path=args.campaign,
                config_path=args.config_path,
                artifacts_dir=args.artifacts_dir,
                dry_run=args.dry_run,
                allow_live_target=args.allow_live_target,
                limit=args.limit,
                shard_index=args.shard_index,
                shard_count=args.shard_count,
                stop_on_failure=args.stop_on_failure,
            )
        ).run()
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
        return

    if args.command_name == "replay":
        case = json.loads(args.case_path.read_text(encoding="utf-8"))
        campaign_path = args.artifacts_dir / "replay-campaign.jsonl"
        campaign_path.parent.mkdir(parents=True, exist_ok=True)
        case["campaign_index"] = case.get("campaign_index", 0)
        campaign_path.write_text(json.dumps(case, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        result = RunOrchestrator(
            RunConfig(
                campaign_path=campaign_path,
                config_path=args.config_path,
                artifacts_dir=args.artifacts_dir,
                dry_run=args.dry_run,
                allow_live_target=args.allow_live_target,
                limit=1,
            )
        ).run()
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
        return

    if args.command_name == "minimize":
        case = json.loads(args.case_path.read_text(encoding="utf-8"))
        minimized = {
            "campaign_index": case.get("campaign_index", 0),
            "seed": case["seed"],
            "operation": case["operation"],
            "opcode": case["opcode"],
            "nsid": case.get("nsid", 1),
            "key_hex": case.get("key_hex", ""),
            "key_ascii": case.get("key_ascii", ""),
            "key_length": case.get("key_length", 0),
            "value_hex": case.get("value_hex", ""),
            "value_length": case.get("value_length", 0),
            "cdw": case.get("cdw", {}),
            "data_direction": case.get("data_direction", "none"),
            "mutation": case.get("mutation", {}),
            "expected": case.get("expected", {}),
        }
        text = json.dumps(minimized, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text, encoding="utf-8")
        else:
            print(text, end="")
        return

    if args.command_name == "generate-report":
        report_data = ReportGenerator.from_files(campaign_path=args.campaign, artifacts_dir=args.artifacts_dir).build()
        if args.output_json or args.output_md:
            write_report_files(report_data, args.output_json, args.output_md)
        else:
            print(ReportGenerator.render_markdown(report_data))
        return

    result = collect_env(args.config_path, args.output)
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
