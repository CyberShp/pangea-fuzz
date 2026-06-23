from __future__ import annotations

import argparse
import json
from pathlib import Path

from pangea_fuzz.config import load_pangea_config

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
    run.add_argument("--config", type=Path)
    run.add_argument("--campaign", type=Path, required=True)
    run.add_argument("--artifacts-dir", type=Path)
    run.add_argument("--engine", choices=["fio", "vdbench"])
    run.add_argument("--device")
    run.add_argument("--workers", type=int)
    run.add_argument("--shard-index", type=int)
    run.add_argument("--shard-count", type=int)
    run.add_argument("--runtime", type=int)
    run.add_argument("--timeout", type=int)
    run.add_argument("--limit", type=int)
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("--allow-write", action="store_true")
    run.add_argument("--fio-template")
    run.add_argument("--fio-bin")
    run.add_argument("--vdbench-bin")
    run.add_argument("--nvme-bin")
    run.add_argument("--keyctl-bin")
    run.add_argument("--transport")
    run.add_argument("--target-traddr")
    run.add_argument("--target-trsvcid")
    run.add_argument("--subsysnqn")
    run.add_argument("--hostnqn")
    run.add_argument("--connect-extra-arg", action="append", default=[])
    run.add_argument("--disconnect-extra-arg", action="append", default=[])
    run.add_argument("--connection-lifecycle", choices=["none", "per-case"])
    run.add_argument("--discover-before-connect", action="store_true")
    run.add_argument("--no-disconnect-after-case", action="store_true")
    run.add_argument("--tls-key-source", choices=["none", "preloaded", "env", "file"])
    run.add_argument("--tls-key-env")
    run.add_argument("--tls-key-file")
    run.add_argument("--tls-key-identity")
    run.add_argument("--tls-keyring")
    run.add_argument("--import-tls-key", action="store_true")
    run.add_argument("--run-id")
    run.add_argument("--artifact-budget-gb", type=float)
    run.add_argument("--free-space-floor-gb", type=float)
    run.add_argument("--progress-interval", type=float, default=5.0)
    run.add_argument("--quiet", action="store_true")
    run.add_argument("--no-compress", action="store_true")
    run.add_argument("--keep-pass-full", action="store_true")
    run.add_argument("--keep-pcap", choices=["always", "never", "on-fail", "on-new-bucket"])

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
        pangea_config = _load_run_config(args.config)
        global_config = pangea_config.get("global", {})
        mode_config = pangea_config.get("modes", {}).get("nvmetcp_tls", {})
        artifacts_dir = args.artifacts_dir or Path(str(global_config.get("artifacts_dir", "artifacts")))
        device = args.device or str(mode_config.get("device", ""))
        if not device:
            raise SystemExit("nvmetcp-tls run requires --device or modes.nvmetcp_tls.device in pangea.config.yaml")
        engine = args.engine or str(mode_config.get("engine", "fio"))
        connect_extra_args = tuple(args.connect_extra_arg or _list_config(mode_config.get("connect_extra_args")))
        disconnect_extra_args = tuple(args.disconnect_extra_arg or _list_config(mode_config.get("disconnect_extra_args")))
        tls_key_config = mode_config.get("tls_key") if isinstance(mode_config.get("tls_key"), dict) else {}
        result = RunOrchestrator(
            RunConfig(
                campaign_path=args.campaign,
                artifacts_dir=artifacts_dir,
                engine=engine,
                device=device,
                workers=int(args.workers if args.workers is not None else global_config.get("workers", 1)),
                shard_index=int(args.shard_index if args.shard_index is not None else global_config.get("shard_index", 0)),
                shard_count=int(args.shard_count if args.shard_count is not None else global_config.get("shard_count", 1)),
                runtime_s=int(args.runtime if args.runtime is not None else mode_config.get("runtime_s", mode_config.get("runtime", 5))),
                timeout_s=int(args.timeout if args.timeout is not None else mode_config.get("timeout_s", mode_config.get("timeout", 120))),
                limit=args.limit,
                dry_run=args.dry_run,
                allow_write=args.allow_write or bool(mode_config.get("allow_write", False)),
                fio_template=args.fio_template or mode_config.get("fio_template"),
                fio_bin=args.fio_bin or str(mode_config.get("fio_bin") or mode_config.get("tool_paths", {}).get("fio") or "fio"),
                vdbench_bin=args.vdbench_bin or str(mode_config.get("vdbench_bin") or mode_config.get("tool_paths", {}).get("vdbench") or "vdbench"),
                nvme_bin=args.nvme_bin or str(mode_config.get("nvme_bin") or mode_config.get("tool_paths", {}).get("nvme") or "nvme"),
                keyctl_bin=args.keyctl_bin or str(mode_config.get("keyctl_bin") or mode_config.get("tool_paths", {}).get("keyctl") or "keyctl"),
                transport=args.transport or str(mode_config.get("transport", "tcp")),
                traddr=args.target_traddr or str(mode_config.get("target_traddr") or mode_config.get("traddr") or ""),
                trsvcid=args.target_trsvcid or str(mode_config.get("target_trsvcid") or mode_config.get("trsvcid") or ""),
                subsysnqn=args.subsysnqn or str(mode_config.get("subsysnqn", "")),
                hostnqn=args.hostnqn or str(mode_config.get("hostnqn", "")),
                connect_extra_args=connect_extra_args,
                disconnect_extra_args=disconnect_extra_args,
                connection_lifecycle=args.connection_lifecycle or str(mode_config.get("connection_lifecycle", "none")),
                discover_before_connect=args.discover_before_connect or bool(mode_config.get("discover_before_connect", False)),
                disconnect_after_case=not args.no_disconnect_after_case and bool(mode_config.get("disconnect_after_case", True)),
                tls_key_source=args.tls_key_source or str(tls_key_config.get("source") or mode_config.get("tls_key_source") or "none"),
                tls_key_env=args.tls_key_env or str(tls_key_config.get("env") or mode_config.get("tls_key_env") or ""),
                tls_key_file=args.tls_key_file or str(tls_key_config.get("file") or mode_config.get("tls_key_file") or ""),
                tls_key_identity=args.tls_key_identity or str(tls_key_config.get("identity") or mode_config.get("tls_key_identity") or ""),
                tls_keyring=args.tls_keyring or str(tls_key_config.get("keyring") or mode_config.get("tls_keyring") or "@u"),
                import_tls_key=args.import_tls_key or bool(tls_key_config.get("import", mode_config.get("import_tls_key", False))),
                run_id=args.run_id,
                artifact_policy=pangea_config.get("artifact_policy", {}),
                artifact_budget_gb=args.artifact_budget_gb,
                free_space_floor_gb=args.free_space_floor_gb,
                progress_interval_s=args.progress_interval,
                quiet=args.quiet,
                no_compress=args.no_compress,
                keep_pass_full=args.keep_pass_full,
                keep_pcap=args.keep_pcap,
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


def _load_run_config(path: Path | None) -> dict:
    config_path = path
    if config_path is None and Path("pangea.config.yaml").exists():
        config_path = Path("pangea.config.yaml")
    return load_pangea_config(config_path)


def _list_config(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, tuple):
        return [str(item) for item in value]
    return [str(value)]


if __name__ == "__main__":
    main()
