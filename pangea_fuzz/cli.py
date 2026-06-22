from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import load_pangea_config
from .report import MultiModeReportGenerator, write_multi_mode_report
from .runtime import inspect_run, pack_repro


def main() -> None:
    parser = argparse.ArgumentParser(prog="pangea-fuzz")
    sub = parser.add_subparsers(dest="mode", required=True)

    for mode in ("nvmetcp-tls", "nvme-kv"):
        mode_parser = sub.add_parser(mode)
        mode_parser.add_argument("mode_args", nargs=argparse.REMAINDER)

    net = sub.add_parser("net-protocol")
    net.add_argument("mode_args", nargs=argparse.REMAINDER)

    report = sub.add_parser("generate-report")
    report.add_argument("--artifacts-root", type=Path, required=True)
    report.add_argument("--output-json", type=Path)
    report.add_argument("--output-md", type=Path)

    config_cmd = sub.add_parser("show-config")
    config_cmd.add_argument("--config", type=Path)

    inspect = sub.add_parser("inspect-run")
    inspect.add_argument("--artifacts-dir", type=Path, required=True)
    inspect.add_argument("--output-json", type=Path)

    repro = sub.add_parser("pack-repro")
    repro.add_argument("--case-dir", type=Path, required=True)
    repro.add_argument("--output", type=Path, required=True)

    args = parser.parse_args()
    if args.mode == "nvmetcp-tls":
        _delegate("nvmetcp-tls-fuzz", "nvmetcp_tls_fuzz.cli", args.mode_args)
        return
    if args.mode == "nvme-kv":
        _delegate("nvme-kv-fuzz", "nvme_kv_fuzz.cli", args.mode_args)
        return
    if args.mode == "net-protocol":
        _delegate("net-protocol-fuzz", "pangea_fuzz.net_protocol.cli", args.mode_args)
        return
    if args.mode == "generate-report":
        data = MultiModeReportGenerator(args.artifacts_root).build()
        if args.output_json or args.output_md:
            write_multi_mode_report(data, args.output_json, args.output_md)
        else:
            print(MultiModeReportGenerator.render_markdown(data))
        return
    if args.mode == "inspect-run":
        data = inspect_run(args.artifacts_dir)
        if args.output_json:
            args.output_json.parent.mkdir(parents=True, exist_ok=True)
            args.output_json.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        print(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True))
        return
    if args.mode == "pack-repro":
        data = pack_repro(args.case_dir, args.output)
        print(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True))
        return
    print(json.dumps(load_pangea_config(args.config), indent=2, ensure_ascii=False, sort_keys=True))


def _delegate(prog: str, module_name: str, args: list[str]) -> None:
    module = __import__(module_name, fromlist=["main"])
    old_argv = sys.argv[:]
    try:
        sys.argv = [prog, *args]
        module.main()
    finally:
        sys.argv = old_argv


if __name__ == "__main__":
    main()
