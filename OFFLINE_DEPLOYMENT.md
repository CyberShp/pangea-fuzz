# Offline Deployment

This project is designed to be cloned from GitHub into an intranet without
Python package downloads.

## Included In The Minimal GitHub Repository

- Python package: `nvmetcp_tls_fuzz/`
- Field catalog: `field_catalog.yaml`
- Example config: `config.example.yaml`
- CLI entrypoint: `python -m nvmetcp_tls_fuzz.cli`
- Offline package helper: `scripts/package_offline.ps1`

Tests and GitHub CI are intentionally omitted from the minimal pushed copy.

## Python Requirements

- Python 3.11 or newer.
- No third-party Python runtime dependencies.
- `requirements.txt` is intentionally empty except for comments.

## Linux Host Tools Still Required

These are system tools and should be installed from the target environment's OS
mirror or golden image:

- `nvme-cli`
- `keyutils` / `keyctl`
- `fio`
- `tcpdump`
- `iproute2`
- `iptables` or `nftables`

## Install From GitHub Clone

```bash
git clone <repo-url> nvmetcp-tls-fuzz
cd nvmetcp-tls-fuzz
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Run Without Installing

```bash
cd nvmetcp-tls-fuzz
python -m nvmetcp_tls_fuzz.cli generate-campaign \
  --seed 20260617 \
  --output artifacts/campaign.jsonl \
  --summary
```

## Create A Zip For Air-Gap Transfer

On Windows:

```powershell
.\scripts\package_offline.ps1
```

This creates `dist\nvmetcp-tls-fuzz-offline.zip` with source, catalog, and docs,
excluding caches and generated artifacts.
