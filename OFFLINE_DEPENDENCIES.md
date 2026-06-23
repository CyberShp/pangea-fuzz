# 离线依赖清单

本项目 Python 运行时代码不依赖第三方 Python 包。仓库内已经包含所有 Python 源码、字段字典、配置模板和离线打包脚本。

## Python 依赖

```text
Python: 3.11 或更新
第三方 Python 包: 无
requirements.txt: 仅说明，无需 pip 下载外部包
pyproject.toml dependencies: []
```

离线安装命令：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

如果内网不允许 `pip install -e .`，也可以直接在仓库根目录执行：

```bash
python -m pangea_fuzz.cli --help
```

## 系统工具依赖

这些不是 Python 依赖，通常来自测试机 OS、测试机镜像或你们内部工具目录。

### NVMe/TCP TLS mode

必需：

```text
nvme-cli
fio 或 vdbench
keyutils/keyctl
Linux nvme_tcp / nvme_fabrics 内核模块
```

建议：

```text
iproute2
ethtool
journalctl
dmesg
tcpdump，可选，只用于抓包和留证
```

### NVMe KV mode

必需：

```text
nvme-cli
Linux NVMe 相关内核支持
```

建议：

```text
iproute2
ethtool
dmesg
journalctl
```

### Net Protocol mode

生成 pcap 不需要额外系统工具。

真实发包需要：

```text
root 权限或 CAP_NET_RAW
Linux raw socket 支持
```

pcap 回放需要：

```text
tcpreplay，可选，只用于 net-protocol replay
```

抓包或观察需要：

```text
tcpdump，可选
```

## x86_64 / aarch64 二进制

仓库不内置 `tcpdump`、`tcpreplay`、`fio`、`nvme` 等系统二进制，原因是这些工具和目标 OS、glibc/musl、驱动、发行版、许可证和安全基线强相关。推荐由测试机镜像或内部制品库提供。

如果内网 ARM 环境只有单文件 777 可执行二进制，可以这样放置：

```text
/opt/fuzz/bin/tcpdump_aarch64
/opt/fuzz/bin/tcpreplay_aarch64
/opt/fuzz/bin/fio_aarch64
/opt/fuzz/bin/nvme_aarch64
```

当前 CLI 已支持显式传 `tcpreplay` 路径：

```bash
python -m pangea_fuzz.cli net-protocol replay \
  --pcap artifacts/net-run/packets.pcap \
  --artifacts-dir artifacts/net-replay \
  --iface eth-test \
  --dry-run \
  --tcpreplay-bin /opt/fuzz/bin/tcpreplay_aarch64
```

NVMe/TCP TLS mode 也支持显式传 `nvme`、`fio`、`vdbench` 路径：

```bash
python -m pangea_fuzz.cli nvmetcp-tls run \
  --campaign artifacts/tls-campaign.jsonl \
  --artifacts-dir artifacts/tls-run \
  --device /dev/nvme1n1 \
  --fio-bin /opt/fuzz/bin/fio_aarch64 \
  --vdbench-bin /opt/fuzz/bin/vdbench \
  --nvme-bin /opt/fuzz/bin/nvme_aarch64 \
  --connection-lifecycle per-case \
  --target-traddr 192.0.2.10 \
  --target-trsvcid 4420 \
  --subsysnqn nqn.2026-06.example:nvmetcp-tls-fuzz \
  --connect-extra-arg=--tls \
  --dry-run
```

也可以写入 `pangea.config.yaml`：

```yaml
modes:
  nvmetcp_tls:
    tool_paths:
      nvme: /opt/fuzz/bin/nvme_aarch64
      fio: /opt/fuzz/bin/fio_aarch64
      vdbench: /opt/fuzz/bin/vdbench
```

`tcpdump` 路径可在环境采集时记录：

```bash
python -m pangea_fuzz.cli net-protocol collect-env \
  --output artifacts/env-net \
  --tcpdump-bin /opt/fuzz/bin/tcpdump_aarch64
```

## 离线包生成

Windows 开发机：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\package_offline.ps1 -Output dist\pangea-fuzz-offline.zip
```

该 zip 包包含源码、字段字典、配置模板和中文文档，不包含 `tests/`、`.github/`、真实运行 artifacts、`dist/` 内旧包。

## 依赖检查建议

进入测试环境后先执行：

```bash
python -m pangea_fuzz.cli --help
python -m pangea_fuzz.cli show-config --config pangea.config.yaml

nvme version || true
fio --version || true
keyctl --version || true
tcpdump --version || true
tcpreplay --version || true
```

正式 campaign 的 `run-manifest.json` 会记录工具路径和可用性。工具不存在不会让 manifest 写入失败，而是记录为：

```json
{"tool": "tcpdump", "available": false, "error": "..."}
```
