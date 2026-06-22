# NVMe/TCP TLS 协议字段 Fuzz 框架

这是一个面向 **NVMe/TCP TLS** 的语法感知协议字段 fuzz 框架。它不修改 TLS 密文，而是在 TLS 终止后的 **NVMe/TCP 明文 PDU 层** 做字段变异、错误码构造、PDU 顺序扰动和执行结果归档。

Python 运行路径没有第三方依赖，适合上传到 GitHub 后在内网拉取使用。离线部署说明见 [OFFLINE_DEPLOYMENT.md](OFFLINE_DEPLOYMENT.md)。

## 组件

- `field_catalog.yaml`：可变异字段字典，覆盖 common header、ICReq/ICResp、CapsuleCmd、Completion、R2T、H2C/C2H data、TermReq、digest/padding、TLS key。
- `CaseGenerator`：按 seed 生成可复现 fuzz case。
- `CampaignGenerator`：默认生成 1,500,000 条用例，其中 10% 为随机值变异。
- `MutationEngine`：对 NVMe/TCP common header 做字节级变异，后续可扩展到更深字段。
- `OracleAnalyzer`：把每轮结果归类为 `PASS_*` 或 `FAIL_*`。
- `ReportGenerator`：生成中文 fuzz 报告，包含覆盖率、错误桶、复现路径、网卡/主机配置检查。
- `FakeTarget`：target 侧 harness，用于构造 target->host 的异常 PDU。
- `SplitProxy`：代理 harness，用于 host->target 和 target->host 的 PDU 变异。

> 注意：Python 3.11 标准库 `ssl` 不直接暴露 TLS-PSK callback。真实 PSK 环境建议在 fake target/proxy 前后放置支持 PSK 的 TLS 终止器，或替换成支持 TLS 1.3 PSK 的绑定。

## 生成用例

生成单条可复现 case：

```bash
python -m nvmetcp_tls_fuzz.cli generate-case \
  --seed 1337 \
  --direction target \
  --pdu-type c2hdata \
  --command read
```

生成默认 1,500,000 条 campaign，其中 10% 是随机值变异：

```bash
python -m nvmetcp_tls_fuzz.cli generate-campaign \
  --seed 20260617 \
  --output artifacts/campaign.jsonl \
  --summary
```

小规模冒烟：

```bash
python -m nvmetcp_tls_fuzz.cli generate-campaign \
  --seed 1 \
  --count 1000 \
  --random-ratio 0.2 \
  --output artifacts/campaign-smoke.jsonl \
  --summary
```

## 运行用例：fio / vdbench

`generate-campaign` 只负责生成 corpus；真正把每条 case 转成 IO 压力并落盘执行结果，需要使用 `run` 子命令。`run` 会为每条 case 创建独立目录，保存 `case.yaml`、`command.json`、`stdout.log`、`stderr.log`、`summary.json`，后续 `generate-report` 会读取这些产物统计覆盖率和失败桶。

先做 dry-run，确认命令、分片和并发都符合预期，不会真正调用 fio/vdbench：

```bash
python -m nvmetcp_tls_fuzz.cli run \
  --campaign artifacts/campaign.jsonl \
  --artifacts-dir artifacts \
  --engine fio \
  --device /dev/nvme1n1 \
  --workers 8 \
  --dry-run
```

运行 fio：

```bash
python -m nvmetcp_tls_fuzz.cli run \
  --campaign artifacts/campaign.jsonl \
  --artifacts-dir artifacts \
  --engine fio \
  --device /dev/nvme1n1 \
  --workers 8 \
  --runtime 5 \
  --timeout 120 \
  --allow-write
```

运行 vdbench：

```bash
python -m nvmetcp_tls_fuzz.cli run \
  --campaign artifacts/campaign.jsonl \
  --artifacts-dir artifacts \
  --engine vdbench \
  --device /dev/nvme1n1 \
  --workers 4 \
  --runtime 5 \
  --timeout 120 \
  --allow-write
```

`--allow-write` 是安全闸门：只要 case 映射到写 workload，默认会被标记为 `FAIL_INFRA` 并跳过真实执行。只有确认目标是内存 fake namespace 或白名单测试 namespace 时才打开。

### 150 万次 campaign 的并发方式

单机并发使用 `--workers`，内部用多进程执行 case，适合把 fio/vdbench 的启动、等待和日志收集并行化：

```bash
python -m nvmetcp_tls_fuzz.cli run \
  --campaign artifacts/campaign.jsonl \
  --artifacts-dir artifacts \
  --engine fio \
  --device /dev/nvme1n1 \
  --workers 16 \
  --runtime 3 \
  --allow-write
```

多台机器并发使用分片，保证每台只跑 `campaign_index % shard_count == shard_index` 的子集。例如 4 台机器：

```bash
# 机器 0
python -m nvmetcp_tls_fuzz.cli run --campaign artifacts/campaign.jsonl --artifacts-dir artifacts/shard-0 --engine fio --device /dev/nvme1n1 --workers 8 --shard-count 4 --shard-index 0 --allow-write

# 机器 1
python -m nvmetcp_tls_fuzz.cli run --campaign artifacts/campaign.jsonl --artifacts-dir artifacts/shard-1 --engine fio --device /dev/nvme1n1 --workers 8 --shard-count 4 --shard-index 1 --allow-write
```

150 万次不要一上来全速压满。建议顺序是：`--limit 100 --dry-run`，再 `--limit 1000` 冒烟，确认 controller 清理、reconnect、日志采集正常后，再扩大到全量。fio/vdbench 自己也有内部并发能力，外层 `--workers` 过大可能把阵列或主机打成压力测试，而不是协议 fuzz；推荐先从 CPU 核数的 1/4 到 1/2 起步。

如果需要自定义 fio 参数，可以用 `--fio-template`，可用变量包括 `{case_id}`、`{device}`、`{rw}`、`{runtime}`、`{seed}`、`{field}`、`{strategy}`：

```bash
python -m nvmetcp_tls_fuzz.cli run \
  --campaign artifacts/campaign.jsonl \
  --artifacts-dir artifacts \
  --engine fio \
  --device /dev/nvme1n1 \
  --fio-template "--name={case_id} --filename={device} --rw={rw} --direct=1 --ioengine=libaio --bs=4k --iodepth=32 --time_based --runtime={runtime}" \
  --workers 8 \
  --allow-write
```

## 分析单轮结果

```bash
python -m nvmetcp_tls_fuzz.cli analyze \
  --dmesg artifacts/dmesg.log \
  --fio-json artifacts/fio.json \
  --nvme-before artifacts/nvme-before.json \
  --nvme-after artifacts/nvme-after.json
```

可能的 verdict：

- `PASS_VALID`：合法用例成功。
- `PASS_REJECTED`：非法输入被干净拒绝。
- `PASS_DISCONNECTED`：非法输入导致断链，但清理正常。
- `FAIL_SAFETY`：kernel oops/panic/KASAN/KCSAN/use-after-free 等安全问题。
- `FAIL_HANG`：hung task、阶段超时、IO 长时间卡死。
- `FAIL_CLEANUP`：controller、device、网络规则或资源残留。
- `FAIL_ORACLE`：语义错误，例如 partial data 被当成成功、fio verify mismatch。
- `FAIL_INFRA`：环境、命令、依赖或测试基础设施失败。

## 生成中文 Fuzz 报告

报告会输出业界常见 fuzz 报告结构：

- 执行摘要
- PDU / 字段 / 策略覆盖率矩阵
- Verdict 分布
- Crash / 失败桶
- 失败 case 复现路径
- 网卡 / 主机配置检查清单
- 与 AFL/libFuzzer/OSS-Fuzz/ClusterFuzz/GitLab fuzz report 的字段映射

生成 Markdown 和 JSON 报告：

```bash
python -m nvmetcp_tls_fuzz.cli generate-report \
  --campaign artifacts/campaign.jsonl \
  --artifacts-dir artifacts \
  --output-md artifacts/fuzz-report.md \
  --output-json artifacts/fuzz-report.json
```

如果只想在终端查看：

```bash
python -m nvmetcp_tls_fuzz.cli generate-report \
  --campaign artifacts/campaign.jsonl \
  --artifacts-dir artifacts
```

## 网卡 / 主机配置是否需要单独开关？

需要至少 **记录**，部分场景建议 **固定或关闭**。原因是 NVMe/TCP fuzz 关注协议时序、断链、超时和数据完整性，网卡 offload、多队列、RSS、MTU、TCP 参数都会改变复现条件。

建议每轮 campaign 前归档：

```bash
ethtool -k <iface>
ethtool -l <iface>
ethtool -x <iface>
ip -d link show <iface>
tc -s qdisc show dev <iface>
ss -tnpi
sysctl net.ipv4.tcp_congestion_control net.ipv4.tcp_retries2 net.ipv4.tcp_keepalive_time
modinfo nvme_tcp
dmesg --ctime --color=never
```

可复现实验中常见做法：

- 保持 MTU 固定，不在 campaign 中途变化。
- 记录 TSO/GSO/GRO/LRO/checksum offload 状态。
- 如果抓包和 PDU 边界分析优先，建议关闭 GRO/LRO，必要时关闭 TSO/GSO：

```bash
ethtool -K <iface> gro off lro off
ethtool -K <iface> tso off gso off
```

- 如果性能/压力优先，不一定关闭 offload，但必须把状态写进报告。
- RSS、多队列、中断亲和性会影响 race 复现概率，建议固定配置并记录：

```bash
ethtool -l <iface>
ethtool -x <iface>
cat /proc/interrupts
```

- `tc` / `iptables` / `nft` 故障注入后必须清理并归档前后状态，避免把残留规则误判为协议 bug。

## 业界 Fuzz 报告长什么样，本项目如何对应？

常见 fuzz 平台会输出：

- AFL/libFuzzer：执行次数、crash、hang、corpus、覆盖率、失败样本。
- OSS-Fuzz/ClusterFuzz：crash bucket、stack trace、crashing testcase、可复现日志、回归范围。
- GitLab/CI fuzz：JSON report、artifacts.zip、crash corpus、job summary。

本项目报告对应为：

- `campaign.jsonl`：输入 corpus。
- `artifacts/<run-id>/case.yaml`：crashing testcase / reproducer。
- `artifacts/<run-id>/pdu-trace.jsonl`：协议级复现轨迹。
- `summary.json`：verdict 和失败原因。
- `fuzz-report.json`：机器可读报告。
- `fuzz-report.md`：人可读中文报告。
- 覆盖率矩阵：按 PDU 类型、字段、变异策略统计。
- 失败桶：按 verdict、reason、PDU、字段聚合。

## 安全默认值

- `config.example.yaml` 默认禁止 destructive write。
- 非法协议输入允许被拒绝、断链或超时后恢复。
- kernel crash、hung task、controller 泄漏、fio verify mismatch、partial data silent success 永远算失败。
