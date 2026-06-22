from __future__ import annotations

import argparse
import json
from pathlib import Path

from .campaign import DEFAULT_CASE_COUNT, DEFAULT_RANDOM_RATIO, NetCampaignConfig, NetCampaignGenerator
from .case_generator import NetCaseGenerator
from .catalog import NetFieldCatalog
from .report import NetReportGenerator, write_report_files
from .run import NetProtocolRunner, NetRunConfig


def main() -> None:
    parser = argparse.ArgumentParser(prog="net-protocol-fuzz")
    sub = parser.add_subparsers(dest="command_name", required=True)

    gen = sub.add_parser("generate-case")
    gen.add_argument("--catalog", default="net_field_catalog.yaml")
    gen.add_argument("--seed", type=int, required=True)
    gen.add_argument("--protocol")
    gen.add_argument("--strategy")

    campaign = sub.add_parser("generate-campaign")
    campaign.add_argument("--catalog", default="net_field_catalog.yaml")
    campaign.add_argument("--seed", type=int, required=True)
    campaign.add_argument("--count", type=int, default=DEFAULT_CASE_COUNT)
    campaign.add_argument("--random-ratio", type=float, default=DEFAULT_RANDOM_RATIO)
    campaign.add_argument("--output", type=Path, required=True)
    campaign.add_argument("--summary", action="store_true")

    pcap = sub.add_parser("generate-pcap")
    _add_run_args(pcap)

    send = sub.add_parser("send")
    _add_run_args(send)
    send.add_argument("--iface", required=True)
    send.add_argument("--allow-send", action="store_true")
    send.add_argument("--allow-disruptive", action="store_true")
    send.add_argument("--iface-allowlist", action="append", default=[])
    send.add_argument("--allow-default-route-iface", action="store_true")

    replay = sub.add_parser("replay")
    replay.add_argument("--pcap", type=Path, required=True)
    replay.add_argument("--artifacts-dir", type=Path, required=True)
    replay.add_argument("--iface", required=True)
    replay.add_argument("--dry-run", action="store_true")
    replay.add_argument("--allow-send", action="store_true")
    replay.add_argument("--tcpreplay-bin", default="tcpreplay")
    _add_runtime_args(replay)

    report = sub.add_parser("generate-report")
    report.add_argument("--campaign", type=Path)
    report.add_argument("--artifacts-dir", type=Path)
    report.add_argument("--output-json", type=Path)
    report.add_argument("--output-md", type=Path)

    env = sub.add_parser("collect-env")
    env.add_argument("--output", type=Path, required=True)
    env.add_argument("--tcpdump-bin", default="tcpdump")

    args = parser.parse_args()
    if args.command_name == "generate-case":
        catalog = NetFieldCatalog.from_yaml(args.catalog)
        case = NetCaseGenerator(catalog).generate(seed=args.seed, protocol=args.protocol, strategy=args.strategy)
        print(json.dumps(case.to_dict(), indent=2, ensure_ascii=False, sort_keys=True))
        return
    if args.command_name == "generate-campaign":
        catalog = NetFieldCatalog.from_yaml(args.catalog)
        generator = NetCampaignGenerator(catalog)
        config = NetCampaignConfig(seed=args.seed, count=args.count, random_ratio=args.random_ratio)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as handle:
            for item in generator.iter_cases(config):
                handle.write(json.dumps(item.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
        if args.summary:
            print(json.dumps(generator.summary(config), indent=2, ensure_ascii=False, sort_keys=True))
        return
    if args.command_name == "generate-pcap":
        result = NetProtocolRunner(_run_config(args)).generate_pcap()
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
        return
    if args.command_name == "send":
        result = NetProtocolRunner(
            _run_config(
                args,
                iface=args.iface,
                allow_send=args.allow_send,
                allow_disruptive=args.allow_disruptive,
                iface_allowlist=tuple(args.iface_allowlist),
                forbid_default_route_iface=not args.allow_default_route_iface,
            )
        ).send()
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
        return
    if args.command_name == "replay":
        config = NetRunConfig(
            campaign_path=args.pcap,
            artifacts_dir=args.artifacts_dir,
            iface=args.iface,
            dry_run=args.dry_run,
            allow_send=args.allow_send,
            tcpreplay_bin=args.tcpreplay_bin,
            run_id=args.run_id,
            artifact_budget_gb=args.artifact_budget_gb,
            free_space_floor_gb=args.free_space_floor_gb,
            progress_interval_s=args.progress_interval,
            quiet=args.quiet,
            no_compress=args.no_compress,
            keep_pass_full=args.keep_pass_full,
            keep_pcap=args.keep_pcap,
        )
        result = NetProtocolRunner(config).replay(args.pcap)
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
        return
    if args.command_name == "generate-report":
        data = NetReportGenerator(args.campaign, args.artifacts_dir).build()
        if args.output_json or args.output_md:
            write_report_files(data, args.output_json, args.output_md)
        else:
            print(NetReportGenerator.render_markdown(data))
        return
    args.output.mkdir(parents=True, exist_ok=True)
    summary = {
        "mode": "net_protocol",
        "collected": ["ip-link", "route", "neighbor"],
        "tool_paths": {"tcpdump": args.tcpdump_bin},
        "note": "collect-env is best-effort in v1; tcpdump is optional and used for observation only",
    }
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True))


def _add_run_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--shard-index", type=int, default=0)
    parser.add_argument("--shard-count", type=int, default=1)
    _add_runtime_args(parser)


def _add_runtime_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--run-id")
    parser.add_argument("--artifact-budget-gb", type=float)
    parser.add_argument("--free-space-floor-gb", type=float)
    parser.add_argument("--progress-interval", type=float, default=5.0)
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--no-compress", action="store_true")
    parser.add_argument("--keep-pass-full", action="store_true")
    parser.add_argument("--keep-pcap", choices=["always", "never", "on-fail", "on-new-bucket"])


def _run_config(
    args,
    *,
    iface: str = "",
    allow_send: bool = False,
    allow_disruptive: bool = False,
    iface_allowlist: tuple[str, ...] = (),
    forbid_default_route_iface: bool = True,
) -> NetRunConfig:
    return NetRunConfig(
        campaign_path=args.campaign,
        artifacts_dir=args.artifacts_dir,
        iface=iface,
        limit=args.limit,
        dry_run=args.dry_run,
        allow_send=allow_send,
        allow_disruptive=allow_disruptive,
        iface_allowlist=iface_allowlist,
        forbid_default_route_iface=forbid_default_route_iface,
        run_id=args.run_id,
        artifact_budget_gb=args.artifact_budget_gb,
        free_space_floor_gb=args.free_space_floor_gb,
        progress_interval_s=args.progress_interval,
        quiet=args.quiet,
        no_compress=args.no_compress,
        keep_pass_full=args.keep_pass_full,
        keep_pcap=args.keep_pcap,
        shard_index=args.shard_index,
        shard_count=args.shard_count,
    )


if __name__ == "__main__":
    main()
