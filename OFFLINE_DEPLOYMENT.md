# 离线部署说明

这个项目设计目标是：上传到 GitHub 后，内网机器可以直接 clone 使用，不需要下载第三方 Python 包。

## 最小 GitHub 仓库包含什么

- Python 包：`nvmetcp_tls_fuzz/`
- Python 包：`nvme_kv_fuzz/`
- 顶层多模式包：`pangea_fuzz/`
- 字段字典：`field_catalog.yaml`
- KV 字段字典：`kv_field_catalog.yaml`
- 网络协议字段字典：`net_field_catalog.yaml`
- 配置模板：`config.example.yaml`
- 多模式配置模板：`pangea.config.yaml`
- 命令入口：`python -m nvmetcp_tls_fuzz.cli`
- 多模式入口：`python -m pangea_fuzz.cli`
- 离线打包脚本：`scripts/package_offline.ps1`

按要求，最小推送版本不包含 `tests/` 和 `.github/` CI。

## Python 要求

- Python 3.11 或更新版本。
- 运行时没有第三方 Python 依赖。
- `requirements.txt` 只有说明，没有需要安装的包。

## Linux 主机仍需准备的系统工具

这些是系统级工具，不随 Python 仓库打包，需要从内网 OS 源或测试机镜像安装：

- `nvme-cli`
- `keyutils` / `keyctl`
- `fio`
- `vdbench`（如果使用 `--engine vdbench`）
- `iproute2`
- `iptables` 或 `nftables`

可选工具：

- `tcpdump`：只用于抓包、查看 pcap 和留证据；ARM 环境可用 `tcpdump_aarch64`。
- `tcpreplay`：只在 `net-protocol replay` 真实回放 pcap 时需要；ARM 环境可用 `tcpreplay_aarch64`。

这些可选工具不要求固定名字。比如：

```bash
python -m pangea_fuzz.cli net-protocol replay \
  --pcap artifacts/net-run-pcap/packets.pcap \
  --artifacts-dir artifacts/net-replay \
  --iface eth-test \
  --tcpreplay-bin /opt/fuzz/bin/tcpreplay_aarch64 \
  --dry-run
```

## 从 GitHub 克隆后运行

```bash
git clone <repo-url> nvmetcp-tls-fuzz
cd nvmetcp-tls-fuzz
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

生成 1,500,000 条默认 campaign：

```bash
python -m pangea_fuzz.cli nvmetcp-tls generate-campaign \
  --seed 20260617 \
  --output artifacts/campaign.jsonl \
  --summary
```

先 dry-run 检查命令生成、分片和多进程调度：

```bash
python -m pangea_fuzz.cli nvmetcp-tls run \
  --campaign artifacts/campaign.jsonl \
  --artifacts-dir artifacts \
  --engine fio \
  --device /dev/nvme1n1 \
  --workers 8 \
  --limit 100 \
  --dry-run
```

使用 fio 执行 campaign：

```bash
python -m pangea_fuzz.cli nvmetcp-tls run \
  --campaign artifacts/campaign.jsonl \
  --artifacts-dir artifacts \
  --engine fio \
  --device /dev/nvme1n1 \
  --workers 8 \
  --runtime 5 \
  --timeout 120 \
  --allow-write
```

使用 vdbench 执行 campaign：

```bash
python -m pangea_fuzz.cli nvmetcp-tls run \
  --campaign artifacts/campaign.jsonl \
  --artifacts-dir artifacts \
  --engine vdbench \
  --device /dev/nvme1n1 \
  --workers 4 \
  --runtime 5 \
  --timeout 120 \
  --allow-write
```

多台内网机器并发时使用分片，例如 4 台机器分别使用 `--shard-count 4 --shard-index 0/1/2/3`。这样 150 万条用例会按 `campaign_index` 均匀切分，不需要手工拆文件：

```bash
python -m pangea_fuzz.cli nvmetcp-tls run \
  --campaign artifacts/campaign.jsonl \
  --artifacts-dir artifacts/shard-0 \
  --engine fio \
  --device /dev/nvme1n1 \
  --workers 8 \
  --shard-count 4 \
  --shard-index 0 \
  --allow-write
```

注意：写类 workload 默认不会执行，必须显式加 `--allow-write`。只允许对 fake target 的内存 namespace 或白名单测试 namespace 打开。

生成 KV campaign 并 dry-run：

```bash
python -m pangea_fuzz.cli nvme-kv generate-campaign \
  --seed 20260622 \
  --count 100 \
  --output artifacts/kv-campaign.jsonl \
  --summary

python -m pangea_fuzz.cli nvme-kv run \
  --campaign artifacts/kv-campaign.jsonl \
  --config config.example.yaml \
  --artifacts-dir artifacts/kv-run-dry \
  --dry-run
```

生成网络协议 campaign 和 pcap：

```bash
python -m pangea_fuzz.cli net-protocol generate-campaign \
  --seed 20260622 \
  --count 100 \
  --output artifacts/net-campaign.jsonl \
  --summary

python -m pangea_fuzz.cli net-protocol generate-pcap \
  --campaign artifacts/net-campaign.jsonl \
  --artifacts-dir artifacts/net-run-pcap \
  --limit 100
```

网络协议真实发包默认禁止，必须显式 `--allow-send`，高风险 ARP/IPv6 ND/TCP RST 类 case 还必须 `--allow-disruptive`。

生成中文报告：

```bash
python -m pangea_fuzz.cli nvmetcp-tls generate-report \
  --campaign artifacts/campaign.jsonl \
  --artifacts-dir artifacts \
  --output-md artifacts/fuzz-report.md \
  --output-json artifacts/fuzz-report.json
```

生成多模式总览报告：

```bash
python -m pangea_fuzz.cli generate-report \
  --artifacts-root artifacts \
  --output-md artifacts/pangea-report.md \
  --output-json artifacts/pangea-report.json
```

## 制作离线 zip

在 Windows 上执行：

```powershell
.\scripts\package_offline.ps1
```

输出：

```text
dist\nvmetcp-tls-fuzz-offline.zip
```

该 zip 包含源码、字段字典、配置模板和文档，不包含缓存、测试、CI 和运行产生的 artifacts。
