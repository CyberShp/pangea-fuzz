# Pangea Fuzz 使用手册

Pangea Fuzz 是一个多模式 fuzz 平台，当前包含三个 mode：

```text
nvmetcp-tls   NVMe/TCP TLS host initiator 流程 fuzz
nvme-kv       NVMe Key Value Command Set over NOF fuzz
net-protocol  Ethernet / ARP / IPv4 / IPv6 / ICMP / TCP / UDP 协议包 fuzz
```

顶层入口：

```bash
python -m pangea_fuzz.cli <mode> <command>
```

兼容旧入口：

```bash
python -m nvmetcp_tls_fuzz.cli ...
python -m nvme_kv_fuzz.cli ...
```

当前阶段重点解决三件事：测试过程可信、产物空间可控、长跑过程可观测。每轮执行都会生成：

```text
run-manifest.json   本轮输入、环境、工具版本、配置 hash
case-ledger.jsonl   每个 case 的阶段流水
events.jsonl        run/case/bucket/预算事件流
progress.json       实时进度快照
index.json          产物索引、大小、sha256、类别
run-summary.json    本轮执行摘要、trust level、预算和失败桶
```

## 1. 环境要求

Python 代码只依赖标准库，支持 x86_64 和 aarch64。建议 Python 3.11 或更新版本。

```bash
git clone https://github.com/CyberShp/pangea-fuzz.git
cd pangea-fuzz
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

检查 CLI：

```bash
python -m pangea_fuzz.cli --help
python -m pangea_fuzz.cli nvmetcp-tls --help
python -m pangea_fuzz.cli nvme-kv --help
python -m pangea_fuzz.cli net-protocol --help
```

系统工具按 mode 准备：

```bash
# NVMe/TCP TLS
nvme version
fio --version
keyctl --version

# 可选
vdbench -h
tcpdump --version
tcpreplay --version
```

`tcpdump` 只用于观察和留证，不影响 campaign 生成、dry-run、pcap 生成。`tcpreplay` 只在 `net-protocol replay` 真实回放 pcap 时需要。

ARM 环境如果只有 777 权限的单文件二进制，例如：

```bash
/opt/fuzz/bin/tcpdump_aarch64 --version
/opt/fuzz/bin/tcpreplay_aarch64 --version
```

可以在命令里显式传路径：

```bash
python -m pangea_fuzz.cli net-protocol replay \
  --pcap artifacts/net/packets.pcap \
  --artifacts-dir artifacts/net-replay \
  --iface eth-test \
  --dry-run \
  --tcpreplay-bin /opt/fuzz/bin/tcpreplay_aarch64
```

## 2. 配置文件

统一配置文件是 `pangea.config.yaml`。最重要的是 `artifact_policy`，它决定 5 万、150 万级长跑时如何控制磁盘：

```yaml
artifact_policy:
  max_total_gb: 200
  stop_when_free_space_below_gb: 20
  compression:
    enabled: true
    format: gzip
  pass:
    keep_full: false
    keep_stdout_tail_kb: 16
    keep_stderr_tail_kb: 16
    keep_trace: true
    keep_payload: false
    keep_pcap: false
  fail:
    keep_full: true
    keep_first_n_per_bucket: 5
    keep_every_n_after: 100
    keep_pcap: on_new_bucket
    max_pcap_mb: 64
    keep_payload: true
```

命令行可以临时覆盖：

```bash
--run-id run-001
--artifact-budget-gb 200
--free-space-floor-gb 20
--progress-interval 5
--quiet
--no-compress
--keep-pass-full
--keep-pcap always|never|on-fail|on-new-bucket
```

`nvmetcp-tls run` 会自动读取当前目录的 `pangea.config.yaml`。如果配置文件不在当前目录，可以显式指定：

```bash
python -m pangea_fuzz.cli nvmetcp-tls run \
  --config /opt/fuzz/pangea.config.yaml \
  --campaign artifacts/tls-campaign.jsonl \
  --dry-run
```

命令行参数优先级高于配置文件。也就是说，配置文件里可以放稳定环境参数，现场只覆盖本轮需要变化的 `--campaign`、`--run-id`、`--workers` 等。

经验值：过去 5 万次迭代打满 300GB，约等于每 case 6MB。150 万次如果不裁剪会接近 9TB。因此正式长跑必须保留 PASS tail、只对失败桶保留完整样本。

## 3. NVMe/TCP TLS

先确认主机能正常 discover、connect、list、disconnect。TLS PSK configured key 由 hostnqn、subsysnqn 和阵列侧配置生成；当前假设主机只支持 SHA256 configured key。

如果要让每个 case 覆盖“建链 -> 下发 IO -> 断链”的完整流程，在 `pangea.config.yaml` 中打开：

```yaml
modes:
  nvmetcp_tls:
    device: /dev/nvme1n1
    engine: fio
    tool_paths:
      nvme: /opt/fuzz/bin/nvme_aarch64
      fio: /opt/fuzz/bin/fio_aarch64
      vdbench: /opt/fuzz/bin/vdbench
    target_traddr: 192.0.2.10
    target_trsvcid: 4420
    subsysnqn: nqn.2026-06.example:nvmetcp-tls-fuzz
    transport: tcp
    connection_lifecycle: per-case
    discover_before_connect: false
    disconnect_after_case: true
    connect_extra_args: [--tls]
```

`connect_extra_args` 用来适配不同 nvme-cli 版本的 TLS 参数；如果你们内网 nvme-cli 使用的是 `--tls_key`、`--keyring` 或其他参数，不需要改代码，直接写到这个列表里。

生成小 campaign：

```bash
python -m pangea_fuzz.cli nvmetcp-tls generate-campaign \
  --seed 1001 \
  --count 100 \
  --random-ratio 0.35 \
  --output artifacts/tls-campaign.jsonl
```

先 dry-run，确认 fio/vdbench 命令、分片、多进程和产物链路：

```bash
python -m pangea_fuzz.cli nvmetcp-tls run \
  --campaign artifacts/tls-campaign.jsonl \
  --dry-run \
  --run-id tls-run-001 \
  --progress-interval 5
```

如果不使用配置文件，也可以全用命令行：

```bash
python -m pangea_fuzz.cli nvmetcp-tls run \
  --campaign artifacts/tls-campaign.jsonl \
  --artifacts-dir artifacts/tls-run-001 \
  --device /dev/nvme1n1 \
  --engine fio \
  --fio-bin /opt/fuzz/bin/fio_aarch64 \
  --nvme-bin /opt/fuzz/bin/nvme_aarch64 \
  --connection-lifecycle per-case \
  --target-traddr 192.0.2.10 \
  --target-trsvcid 4420 \
  --subsysnqn nqn.2026-06.example:nvmetcp-tls-fuzz \
  --connect-extra-arg=--tls \
  --dry-run
```

真实读 workload：

```bash
python -m pangea_fuzz.cli nvmetcp-tls run \
  --campaign artifacts/tls-campaign.jsonl \
  --artifacts-dir artifacts/tls-run-002 \
  --device /dev/nvme1n1 \
  --engine fio \
  --workers 8 \
  --runtime 5 \
  --timeout 120
```

写 workload 默认禁止；必须确认 namespace 是白名单测试盘后再加：

```bash
--allow-write
```

## 4. NVMe KV

准备 KV 配置：

```yaml
device_path: /dev/nvme1n1
nsid: 1
target_nqn: nqn.2026-06.example:kv
allowed_model_or_serial: [TEST_ARRAY_MODEL_OR_SERIAL]
key_prefix: kvfuzz-test-
max_qps: 10
timeout_ms: 1000
```

生成 campaign：

```bash
python -m pangea_fuzz.cli nvme-kv generate-campaign \
  --seed 2001 \
  --count 1000 \
  --output artifacts/kv-campaign.jsonl
```

dry-run：

```bash
python -m pangea_fuzz.cli nvme-kv run \
  --campaign artifacts/kv-campaign.jsonl \
  --config kv.config.yaml \
  --artifacts-dir artifacts/kv-run-001 \
  --dry-run \
  --run-id kv-run-001
```

真实目标默认禁止；确认 allowlist 命中后再加：

```bash
--allow-live-target
```

重放某个 case：

```bash
python -m pangea_fuzz.cli nvme-kv replay \
  artifacts/kv-run-001/case-0-seed-*/case.yaml \
  --config kv.config.yaml \
  --artifacts-dir artifacts/kv-replay-001 \
  --dry-run
```

## 5. Net Protocol

默认只生成 pcap，不发包：

```bash
python -m pangea_fuzz.cli net-protocol generate-campaign \
  --seed 3001 \
  --count 1000 \
  --output artifacts/net-campaign.jsonl

python -m pangea_fuzz.cli net-protocol generate-pcap \
  --campaign artifacts/net-campaign.jsonl \
  --artifacts-dir artifacts/net-run-001 \
  --run-id net-run-001
```

真实发包需要 root 或 `CAP_NET_RAW`，并显式加 `--allow-send`：

```bash
sudo python -m pangea_fuzz.cli net-protocol send \
  --campaign artifacts/net-campaign.jsonl \
  --artifacts-dir artifacts/net-send-001 \
  --iface eth-test \
  --allow-send \
  --allow-default-route-iface \
  --run-id net-send-001
```

pcap 回放：

```bash
sudo python -m pangea_fuzz.cli net-protocol replay \
  --pcap artifacts/net-run-001/packets.pcap \
  --artifacts-dir artifacts/net-replay-001 \
  --iface eth-test \
  --allow-send \
  --tcpreplay-bin /opt/fuzz/bin/tcpreplay_aarch64
```

## 6. 实时进度

默认每 5 秒输出一行进度；非 TTY 或 `--quiet` 时不打印终端，但仍刷新 `progress.json`。

进度文件可直接查看：

```bash
watch -n 2 'cat artifacts/tls-run-001/progress.json'
tail -f artifacts/tls-run-001/events.jsonl
tail -f artifacts/tls-run-001/case-ledger.jsonl
```

典型字段：

```json
{
  "planned": 1500000,
  "selected": 38210,
  "finished": 38210,
  "rate_per_sec": 126.4,
  "eta_sec": 11520,
  "verdict_counts": {"PASS_VALID": 37990, "FAIL_ORACLE": 20},
  "artifact_bytes": 1524712345,
  "artifact_budget_bytes": 214748364800,
  "current_case": {"case_index": 38210, "field": "r2t.r2t_length", "strategy": "random_value"}
}
```

## 7. 可信度与排查

每个 run 和失败 case 都会标记 `trust_level`：

```text
host_only     只有 host 命令、summary、stdout/stderr
host_network  有 host + pcap/packet trace/网卡计数器
host_target   有 host + target 日志或目标状态
full          host + network + target 证据齐全
```

缺证不会让 run 失败，但会写入报告：

```json
{
  "trust_level": "host_only",
  "missing_evidence": ["target_log", "switch_counter", "pcap"]
}
```

检查 run 完整性：

```bash
python -m pangea_fuzz.cli inspect-run \
  --artifacts-dir artifacts/tls-run-001
```

它会检查：

```text
manifest 是否存在
index 是否存在
ledger 阶段是否缺失
缺 summary 的 case
重复 case 目录
孤儿产物
预算是否触发
trust level
可疑 failure bucket
```

打包最小复现：

```bash
python -m pangea_fuzz.cli pack-repro \
  --case-dir artifacts/tls-run-001/case-123 \
  --output artifacts/repro-case-123.zip
```

## 8. 报告

单 mode 报告：

```bash
python -m pangea_fuzz.cli nvmetcp-tls generate-report \
  --campaign artifacts/tls-campaign.jsonl \
  --artifacts-dir artifacts/tls-run-001 \
  --output-json artifacts/tls-report.json \
  --output-md artifacts/tls-report.md
```

多 mode 总览：

```bash
python -m pangea_fuzz.cli generate-report \
  --artifacts-root artifacts \
  --output-json artifacts/pangea-report.json \
  --output-md artifacts/pangea-report.md
```

报告会显示：

```text
执行完整性
mode/verdict 分布
trust level
missing evidence
artifact bytes
pruning/compression/truncation 统计
failure bucket
失败样本路径和原因
```

## 9. 150 万级长跑建议

先生成 campaign：

```bash
python -m pangea_fuzz.cli nvmetcp-tls generate-campaign \
  --seed 9001 \
  --count 1500000 \
  --random-ratio 0.35 \
  --output artifacts/tls-150w.jsonl
```

单机多进程：

```bash
python -m pangea_fuzz.cli nvmetcp-tls run \
  --campaign artifacts/tls-150w.jsonl \
  --artifacts-dir artifacts/tls-150w-run \
  --device /dev/nvme1n1 \
  --workers 16 \
  --artifact-budget-gb 200 \
  --free-space-floor-gb 20 \
  --progress-interval 5 \
  --run-id tls-150w-run
```

多机分片示例，8 个 shard 中的第 2 片：

```bash
python -m pangea_fuzz.cli nvmetcp-tls run \
  --campaign artifacts/tls-150w.jsonl \
  --artifacts-dir artifacts/tls-150w-shard-2 \
  --device /dev/nvme1n1 \
  --workers 16 \
  --shard-count 8 \
  --shard-index 2 \
  --artifact-budget-gb 200 \
  --free-space-floor-gb 20 \
  --run-id tls-150w-shard-2
```

现场判断是否卡死时，优先看：

```bash
cat artifacts/tls-150w-run/progress.json
tail -n 50 artifacts/tls-150w-run/events.jsonl
tail -n 50 artifacts/tls-150w-run/case-ledger.jsonl
python -m pangea_fuzz.cli inspect-run --artifacts-dir artifacts/tls-150w-run
```

## 10. 网卡配置建议

做协议边界和报文复现时，建议归档网卡状态：

```bash
IFACE=eth-test
ip -d link show dev $IFACE > artifacts/env/ip-link-$IFACE.txt
ip route > artifacts/env/ip-route.txt
ip neigh > artifacts/env/ip-neigh.txt
ethtool -k $IFACE > artifacts/env/ethtool-k-$IFACE.txt
ethtool -S $IFACE > artifacts/env/ethtool-S-$IFACE.txt
ethtool -l $IFACE > artifacts/env/ethtool-l-$IFACE.txt 2>&1 || true
ethtool -x $IFACE > artifacts/env/ethtool-x-$IFACE.txt 2>&1 || true
```

如果需要 pcap 和实际线上的包边界一致，建议关闭 GRO/LRO，必要时关闭 TSO/GSO：

```bash
sudo ethtool -K $IFACE gro off lro off
sudo ethtool -K $IFACE tso off gso off
```

如果本轮更关注吞吐或压力，不一定要关闭 offload，但必须把 offload 状态归档进报告。

## 11. 当前边界

`nvmetcp-tls run` 现在支持两种执行方式：默认 `connection_lifecycle: none` 时只在已有 device 上调度 fio/vdbench；设置 `connection_lifecycle: per-case` 后，每个 case 会执行 `nvme connect -> fio/vdbench -> nvme disconnect`，并把建链命令、workload 命令和证据写入 case 目录。

`fake_target.py` 和 `split_proxy.py` 目前仍是可复用模块，不是一键启动的完整协议注入 CLI。TLS PDU proxy/fake target 的 per-case 自动字段注入仍是后续工作。

目标侧日志和交换机计数器当前只定义外部导入目录和报告字段，第一阶段不实现厂商 API 对接。
