# 离线部署说明

本仓库的运行时代码只依赖 Python 标准库，适合在内网 x86_64 / aarch64 测试机上直接 clone 使用。

## 仓库包含内容

- `pangea_fuzz/`：多模式入口、配置、报告、可信执行底座。
- `nvmetcp_tls_fuzz/`：NVMe/TCP TLS campaign、run、report。
- `nvme_kv_fuzz/`：NVMe KV campaign、run、replay、report。
- `pangea_fuzz/net_protocol/`：网络协议包生成、pcap、send、replay。
- `field_catalog.yaml`：NVMe/TCP TLS 字段字典。
- `kv_field_catalog.yaml`：NVMe KV 字段字典。
- `net_field_catalog.yaml`：网络协议字段字典。
- `pangea.config.yaml`：统一配置模板。
- `scripts/package_offline.ps1`：离线包打包脚本。

按当前约定，最小推送不包含 `tests/`、`.github/` 和真实运行 artifacts。

## Python

```bash
git clone https://github.com/CyberShp/pangea-fuzz.git
cd pangea-fuzz
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

验证：

```bash
python -m pangea_fuzz.cli --help
```

## 系统工具

按实际 mode 准备：

```bash
nvme version
fio --version
keyctl --version
```

可选工具：

```bash
tcpdump --version
tcpreplay --version
vdbench -h
```

`tcpdump` 只用于观察和留证；`tcpreplay` 只用于 `net-protocol replay` 真实回放。ARM 环境可以使用 777 权限的单文件二进制：

```bash
/opt/fuzz/bin/tcpdump_aarch64 --version
/opt/fuzz/bin/tcpreplay_aarch64 --version
```

回放时显式传路径：

```bash
python -m pangea_fuzz.cli net-protocol replay \
  --pcap artifacts/net-run/packets.pcap \
  --artifacts-dir artifacts/net-replay \
  --iface eth-test \
  --dry-run \
  --tcpreplay-bin /opt/fuzz/bin/tcpreplay_aarch64
```

## 离线打包

Windows 开发机：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\package_offline.ps1 -Output dist\pangea-fuzz-offline.zip
```

内网 Linux 解压后：

```bash
unzip pangea-fuzz-offline.zip
cd pangea-fuzz-offline
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## 长跑产物控制

默认配置：

```yaml
artifact_policy:
  max_total_gb: 200
  stop_when_free_space_below_gb: 20
```

执行时可以覆盖：

```bash
python -m pangea_fuzz.cli nvmetcp-tls run \
  --campaign artifacts/tls-150w.jsonl \
  --artifacts-dir artifacts/tls-run \
  --device /dev/nvme1n1 \
  --workers 16 \
  --artifact-budget-gb 200 \
  --free-space-floor-gb 20 \
  --progress-interval 5 \
  --run-id tls-run
```

每轮 run 都会生成：

```text
run-manifest.json
case-ledger.jsonl
events.jsonl
progress.json
index.json
run-summary.json
```

检查完整性：

```bash
python -m pangea_fuzz.cli inspect-run --artifacts-dir artifacts/tls-run
```

打包复现：

```bash
python -m pangea_fuzz.cli pack-repro \
  --case-dir artifacts/tls-run/case-123 \
  --output artifacts/repro-case-123.zip
```

