# NVMe/TCP TLS Fuzz 测试使用手册

本项目现在是 Pangea Fuzz 多模式平台，用于把 NVMe/TCP TLS、NVMe KV over NOF、网络协议包 fuzz 放到同一套执行和报告框架里。当前仓库已经提供：

- 基于 `field_catalog.yaml` 的 grammar-aware 用例生成。
- 基于 `kv_field_catalog.yaml` 的 NVMe KV command set fuzz。
- 基于 `net_field_catalog.yaml` 的 Ethernet/ARP/IP/ICMP/TCP/UDP 协议包 fuzz。
- 150 万级 campaign 的流式生成。
- `fio` / `vdbench` workload 执行编排。
- 单机多进程和多机分片。
- 每个 case 的执行产物归档。
- 中文 JSON / Markdown 覆盖率和错误报告。

顶层入口是：

```bash
python -m pangea_fuzz.cli <mode> <command>
```

三个 mode：

```text
nvmetcp-tls   NVMe/TCP TLS 连接和 IO workload fuzz
nvme-kv       NVMe Key Value Command Set over NOF fuzz
net-protocol  Ethernet / ARP / IPv4 / IPv6 / ICMP / TCP / UDP 协议包 fuzz
```

旧入口仍保留：

```bash
python -m nvmetcp_tls_fuzz.cli ...
python -m nvme_kv_fuzz.cli ...
```

当前仓库需要特别注意的一点：`fake_target.py` 和 `split_proxy.py` 是可复用模块，不是已经封装好的一键启动 CLI。也就是说，当前 `nvmetcp-tls run` 会消费 campaign 并驱动 fio/vdbench 产生 IO 与报告产物；协议级 PDU 注入链路需要后续把 fake target / split proxy 接入运行器，或由测试环境外部脚本启动。

## 1. 测试拓扑

推荐先按下面的顺序推进，不要一上来跑 150 万条：

1. 只生成 10 到 100 条 case，确认工具能运行。
2. 对 campaign 做 `--dry-run`，确认 fio/vdbench 命令、分片、多进程调度正确。
3. 在 fake namespace 或白名单测试 namespace 上跑 100 到 1000 条冒烟。
4. 生成报告，确认执行数、覆盖率、失败桶都正常。
5. 再扩大到 150 万条全量 campaign。

典型拓扑：

```text
Linux host initiator
  |
  | nvme/tcp tls connect + fio/vdbench IO
  v
NVMe/TCP TLS target
```

如果要做 host->target 或 target->host PDU 字段注入，建议拓扑变成：

```text
Linux host initiator
  |
  v
split proxy / fake target / TLS terminator
  |
  v
真实阵列或内存 namespace
```

## 2. 环境准备

### 2.1 Python

要求 Python 3.11 或更新版本。仓库运行时没有第三方 Python 包依赖。

```bash
git clone https://github.com/CyberShp/pangea-fuzz.git
cd pangea-fuzz
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

验证 CLI 是否可用：

```bash
python -m pangea_fuzz.cli --help
python -m pangea_fuzz.cli nvmetcp-tls --help
python -m pangea_fuzz.cli nvme-kv --help
python -m pangea_fuzz.cli net-protocol --help
```

### 2.2 Linux 系统工具

测试机需要准备这些系统工具：

```bash
nvme version
fio --version
keyctl --version
```

如果使用 vdbench，还需要确认：

```bash
vdbench -h
```

常用包名可能包括：

```bash
nvme-cli fio keyutils iproute2 ethtool
```

`tcpdump` 和 `tcpreplay` 不是核心依赖：

- `tcpdump` 只用于抓包、查看 pcap、留证据；不影响 campaign 生成、pcap 生成、dry-run。
- `tcpreplay` 只在执行 `net-protocol replay` 且真实回放 pcap 时需要。
- ARM 环境如果只有 `tcpdump_aarch64`、`tcpreplay_aarch64` 这种 777 可执行二进制，可以直接传完整路径或文件名。

示例：

```bash
/opt/fuzz/bin/tcpdump_aarch64 --version
/opt/fuzz/bin/tcpreplay_aarch64 --version
```

### 2.3 内核和网卡状态归档

每次正式 campaign 前保存环境信息，避免后续无法复现：

```bash
mkdir -p artifacts/env

uname -a > artifacts/env/uname.txt
nvme version > artifacts/env/nvme-version.txt
fio --version > artifacts/env/fio-version.txt
modinfo nvme_tcp > artifacts/env/modinfo-nvme_tcp.txt 2>&1 || true
dmesg --ctime --color=never > artifacts/env/dmesg-before.log

ip -d link show > artifacts/env/ip-link.txt
ss -tnpi > artifacts/env/ss-before.txt
sysctl net.ipv4.tcp_congestion_control net.ipv4.tcp_retries2 net.ipv4.tcp_keepalive_time > artifacts/env/tcp-sysctl.txt
```

指定网卡，例如 `eth0`：

```bash
IFACE=eth0
ethtool -k $IFACE > artifacts/env/ethtool-k-$IFACE.txt
ethtool -l $IFACE > artifacts/env/ethtool-l-$IFACE.txt 2>&1 || true
ethtool -x $IFACE > artifacts/env/ethtool-x-$IFACE.txt 2>&1 || true
tc -s qdisc show dev $IFACE > artifacts/env/tc-qdisc-$IFACE.txt
```

如果你要分析抓包里的 PDU 边界，建议在可复现实验中关闭 GRO/LRO，必要时关闭 TSO/GSO：

```bash
sudo ethtool -K $IFACE gro off lro off
sudo ethtool -K $IFACE tso off gso off
```

如果本轮更关注性能压力，可以不关闭 offload，但必须把状态归档进报告。

## 3. NVMe/TCP TLS 连接准备

本工具不会替你配置真实阵列、hostnqn、subsysnqn、TLS PSK keyring。正式跑 IO 前，先保证主机能正常 discover、connect、list、断开。

下面命令中的地址和 NQN 需要替换成你的环境。

```bash
TRADDR=192.0.2.10
TRSVCID=4420
HOSTNQN=$(cat /etc/nvme/hostnqn)

sudo nvme discover \
  -t tcp \
  -a $TRADDR \
  -s $TRSVCID
```

从 discover 输出里拿到 `subnqn`：

```bash
SUBSYSNQN=nqn.2026-06.example:nvmetcp-tls-fuzz
```

TLS PSK 的 configured key 需要由 hostnqn、subsysnqn 和阵列侧配置生成。当前假设主机只支持 SHA256 的 36 字节 configured key。请按你们阵列和主机已有流程导入 keyring，例如：

```bash
sudo keyctl show
sudo keyctl padd psk "NVMeTLSkey-1:<identity>" @u < configured-key-file
```

不同发行版和 nvme-cli 版本的 TLS 参数可能不同，下面只展示检查思路：

```bash
sudo nvme connect \
  -t tcp \
  -a $TRADDR \
  -s $TRSVCID \
  -n $SUBSYSNQN

nvme list
nvme list-subsys
```

确认出现测试 namespace，例如：

```bash
DEV=/dev/nvme1n1
test -b $DEV && echo "device ready: $DEV"
```

断开重连也必须正常：

```bash
sudo nvme disconnect -n $SUBSYSNQN
sudo nvme connect -t tcp -a $TRADDR -s $TRSVCID -n $SUBSYSNQN
```

如果 TLS key 不存在、identity 不匹配、key 删除后 connect，预期必须 clean fail，不能残留 `/dev/nvmeXnY` 或 controller。

## 4. 生成 campaign

### 4.1 NVMe/TCP TLS case

先用单条 case 确认字段字典和生成器正常：

```bash
python -m pangea_fuzz.cli nvmetcp-tls generate-case \
  --seed 1337 \
  --direction target \
  --pdu-type c2hdata \
  --command read
```

输出里需要看到 `seed`、`pdu_type`、`direction`、`command`、`mutation` 等字段。

### 4.2 冒烟 campaign

```bash
mkdir -p artifacts

python -m pangea_fuzz.cli nvmetcp-tls generate-campaign \
  --seed 20260617 \
  --count 100 \
  --random-ratio 0.2 \
  --output artifacts/campaign-smoke.jsonl \
  --summary
```

检查数量：

```bash
wc -l artifacts/campaign-smoke.jsonl
head -n 3 artifacts/campaign-smoke.jsonl
```

### 4.3 全量 150 万 campaign

```bash
python -m pangea_fuzz.cli nvmetcp-tls generate-campaign \
  --seed 20260617 \
  --count 1500000 \
  --random-ratio 0.1 \
  --output artifacts/campaign-150w.jsonl \
  --summary
```

默认 count 本来就是 150 万，上面显式写出是为了测试记录更清楚。

### 4.4 KV campaign

```bash
python -m pangea_fuzz.cli nvme-kv generate-campaign \
  --seed 20260622 \
  --count 100 \
  --output artifacts/kv-campaign-smoke.jsonl \
  --summary
```

### 4.5 网络协议 campaign

```bash
python -m pangea_fuzz.cli net-protocol generate-campaign \
  --seed 20260622 \
  --count 100 \
  --output artifacts/net-campaign-smoke.jsonl \
  --summary
```

## 5. Dry-run 验证执行编排

`run` 子命令会把 campaign 中每条 case 映射成 fio/vdbench 命令，并为每条 case 写入独立产物目录。

先不要真实跑 IO，做 dry-run：

```bash
python -m pangea_fuzz.cli nvmetcp-tls run \
  --campaign artifacts/campaign-smoke.jsonl \
  --artifacts-dir artifacts/run-smoke-dry \
  --engine fio \
  --device /dev/nvme1n1 \
  --workers 4 \
  --limit 20 \
  --dry-run
```

检查输出：

```text
planned_cases: campaign 总数
selected_cases: 本轮选中的 case 数
executed_cases: 本轮实际处理的 case 数
verdict_counts: dry-run 下通常应为 PASS_VALID，写类 case 没有 --allow-write 时会是 FAIL_INFRA
```

检查产物：

```bash
find artifacts/run-smoke-dry -maxdepth 2 -type f | sort | head -n 20
cat artifacts/run-smoke-dry/case-0/command.json
cat artifacts/run-smoke-dry/case-0/summary.json
```

如果 dry-run 都不能生成 `command.json` 和 `summary.json`，不要继续跑真实 IO。

## 6. 使用 fio 跑测试

### 6.1 只读冒烟

先跑 read 类 workload，风险最低：

```bash
DEV=/dev/nvme1n1

python -m pangea_fuzz.cli nvmetcp-tls run \
  --campaign artifacts/campaign-smoke.jsonl \
  --artifacts-dir artifacts/run-fio-read-smoke \
  --engine fio \
  --device $DEV \
  --workers 4 \
  --runtime 5 \
  --timeout 120 \
  --limit 100
```

注意：如果 case 被映射为 write，但没有 `--allow-write`，该 case 会被标记为 `FAIL_INFRA` 并跳过真实执行。这是安全设计。

### 6.2 允许写入

只有目标是 fake target 的内存 namespace 或白名单测试 namespace 时，才允许写入：

```bash
python -m pangea_fuzz.cli nvmetcp-tls run \
  --campaign artifacts/campaign-smoke.jsonl \
  --artifacts-dir artifacts/run-fio-write-smoke \
  --engine fio \
  --device $DEV \
  --workers 4 \
  --runtime 5 \
  --timeout 120 \
  --limit 100 \
  --allow-write
```

### 6.3 自定义 fio 参数

可以通过 `--fio-template` 控制 fio。可用变量：

```text
{case_id} {device} {rw} {runtime} {seed} {field} {strategy}
```

示例：

```bash
python -m pangea_fuzz.cli nvmetcp-tls run \
  --campaign artifacts/campaign-smoke.jsonl \
  --artifacts-dir artifacts/run-fio-custom \
  --engine fio \
  --device $DEV \
  --workers 4 \
  --runtime 10 \
  --timeout 180 \
  --limit 100 \
  --allow-write \
  --fio-template "--name={case_id} --filename={device} --rw={rw} --direct=1 --ioengine=libaio --bs=4k --iodepth=32 --time_based --runtime={runtime}"
```

工具会自动补 `--output-format=json`，便于后续 oracle 和报告读取。

## 7. 使用 vdbench 跑测试

vdbench 会为每个 case 生成独立参数文件 `vdbench.parm`：

```bash
python -m pangea_fuzz.cli nvmetcp-tls run \
  --campaign artifacts/campaign-smoke.jsonl \
  --artifacts-dir artifacts/run-vdbench-smoke \
  --engine vdbench \
  --device $DEV \
  --workers 2 \
  --runtime 5 \
  --timeout 120 \
  --limit 50 \
  --allow-write
```

## 8. KV mode 测试

KV mode 通过 `nvme io-passthru` 运行 KV command set case。真实阵列执行必须显式打开 `--allow-live-target`，否则只允许 dry-run。

配置文件示例见 `config.example.yaml` 或 `pangea.config.yaml` 中的 `modes.nvme_kv`。

dry-run：

```bash
python -m pangea_fuzz.cli nvme-kv run \
  --campaign artifacts/kv-campaign-smoke.jsonl \
  --config config.example.yaml \
  --artifacts-dir artifacts/kv-run-dry \
  --dry-run
```

真实测试阵列：

```bash
python -m pangea_fuzz.cli nvme-kv run \
  --campaign artifacts/kv-campaign-smoke.jsonl \
  --config config.example.yaml \
  --artifacts-dir artifacts/kv-run-live \
  --limit 100 \
  --allow-live-target
```

复现和最小化：

```bash
python -m pangea_fuzz.cli nvme-kv replay artifacts/kv-run-live/run-*/case-0-seed-*/case.yaml \
  --config config.example.yaml \
  --dry-run

python -m pangea_fuzz.cli nvme-kv minimize artifacts/kv-run-live/run-*/case-0-seed-*/case.yaml \
  --config config.example.yaml \
  --output artifacts/minimized-kv-case.json
```

## 9. 网络协议 mode 测试

`net-protocol` 是独立协议 mode，覆盖 Ethernet、ARP、IPv4、IPv6、ICMP、ICMPv6、TCP、UDP。默认只生成 pcap，不发包。

生成可审查 pcap：

```bash
python -m pangea_fuzz.cli net-protocol generate-pcap \
  --campaign artifacts/net-campaign-smoke.jsonl \
  --artifacts-dir artifacts/net-run-pcap \
  --limit 100
```

检查：

```bash
tcpdump -nn -r artifacts/net-run-pcap/packets.pcap
cat artifacts/net-run-pcap/packet-trace.jsonl
```

如果环境里二进制叫 `tcpdump_aarch64`，直接替换命令即可：

```bash
/opt/fuzz/bin/tcpdump_aarch64 -nn -r artifacts/net-run-pcap/packets.pcap
```

dry-run 发包计划：

```bash
python -m pangea_fuzz.cli net-protocol send \
  --campaign artifacts/net-campaign-smoke.jsonl \
  --artifacts-dir artifacts/net-send-dry \
  --iface eth-test \
  --limit 10 \
  --dry-run
```

真实发包必须显式授权：

```bash
python -m pangea_fuzz.cli net-protocol send \
  --campaign artifacts/net-campaign-smoke.jsonl \
  --artifacts-dir artifacts/net-send-live \
  --iface eth-test \
  --iface-allowlist eth-test \
  --allow-default-route-iface \
  --allow-send \
  --limit 10
```

高风险协议包，例如 ARP、IPv6 ND/RA、TCP RST/异常顺序，需要额外：

```bash
--allow-disruptive
```

pcap replay：

```bash
python -m pangea_fuzz.cli net-protocol replay \
  --pcap artifacts/net-run-pcap/packets.pcap \
  --artifacts-dir artifacts/net-replay \
  --iface eth-test \
  --tcpreplay-bin /opt/fuzz/bin/tcpreplay_aarch64 \
  --dry-run
```

真实 replay 同样必须 `--allow-send`。

检查参数文件：

```bash
find artifacts/run-vdbench-smoke -name vdbench.parm | head
cat artifacts/run-vdbench-smoke/case-0/vdbench.parm
```

## 10. 多进程和多机器分片

### 10.1 单机多进程

`--workers` 使用多进程执行 case。内部是有界队列，不会一次性提交 150 万个任务。

```bash
python -m pangea_fuzz.cli nvmetcp-tls run \
  --campaign artifacts/campaign-150w.jsonl \
  --artifacts-dir artifacts/run-150w-host0 \
  --engine fio \
  --device $DEV \
  --workers 16 \
  --runtime 3 \
  --timeout 120 \
  --allow-write
```

建议从 CPU 核数的 1/4 到 1/2 起步。`fio` / `vdbench` 自身也有并发能力，`--workers` 太大可能把测试变成压力测试。

### 10.2 多机分片

4 台机器并发时，每台机器使用同一个 campaign 文件，但设置不同的 `--shard-index`：

```bash
# 机器 0
python -m pangea_fuzz.cli nvmetcp-tls run \
  --campaign artifacts/campaign-150w.jsonl \
  --artifacts-dir artifacts/run-150w-shard0 \
  --engine fio \
  --device $DEV \
  --workers 8 \
  --shard-count 4 \
  --shard-index 0 \
  --runtime 3 \
  --allow-write

# 机器 1
python -m pangea_fuzz.cli nvmetcp-tls run \
  --campaign artifacts/campaign-150w.jsonl \
  --artifacts-dir artifacts/run-150w-shard1 \
  --engine fio \
  --device $DEV \
  --workers 8 \
  --shard-count 4 \
  --shard-index 1 \
  --runtime 3 \
  --allow-write
```

分片规则是：

```text
campaign_index % shard_count == shard_index
```

## 11. 生成报告

对 TLS 单个 run 目录生成报告：

```bash
python -m pangea_fuzz.cli nvmetcp-tls generate-report \
  --campaign artifacts/campaign-smoke.jsonl \
  --artifacts-dir artifacts/run-fio-write-smoke \
  --output-md artifacts/fuzz-report-smoke.md \
  --output-json artifacts/fuzz-report-smoke.json
```

KV 报告：

```bash
python -m pangea_fuzz.cli nvme-kv generate-report \
  --campaign artifacts/kv-campaign-smoke.jsonl \
  --artifacts-dir artifacts/kv-run-dry \
  --output-md artifacts/kv-report.md \
  --output-json artifacts/kv-report.json
```

网络协议报告：

```bash
python -m pangea_fuzz.cli net-protocol generate-report \
  --campaign artifacts/net-campaign-smoke.jsonl \
  --artifacts-dir artifacts/net-run-pcap \
  --output-md artifacts/net-report.md \
  --output-json artifacts/net-report.json
```

多模式总览报告：

```bash
python -m pangea_fuzz.cli generate-report \
  --artifacts-root artifacts \
  --output-md artifacts/pangea-report.md \
  --output-json artifacts/pangea-report.json
```

查看摘要：

```bash
cat artifacts/fuzz-report-smoke.md
```

报告会包含：

- campaign 总数、随机变异数、语法变异数。
- PDU 类型覆盖率。
- 字段覆盖率。
- 变异策略覆盖率。
- verdict 分布。
- `FAIL_*` 失败桶。
- 复现路径。
- 网卡和主机配置检查清单。

多机分片后，可以把各机器的 `artifacts/run-150w-shard*` 拷贝回同一目录，再对父目录生成报告：

```bash
python -m pangea_fuzz.cli nvmetcp-tls generate-report \
  --campaign artifacts/campaign-150w.jsonl \
  --artifacts-dir artifacts/all-shards \
  --output-md artifacts/fuzz-report-150w.md \
  --output-json artifacts/fuzz-report-150w.json
```

## 12. Verdict 判定

允许结果：

- `PASS_VALID`：合法 case 成功。
- `PASS_REJECTED`：非法输入被命令或目标拒绝。
- `PASS_DISCONNECTED`：非法输入导致断链，但清理正常。

必须分析的失败：

- `FAIL_SAFETY`：kernel oops、panic、KASAN、KCSAN、use-after-free。
- `FAIL_HANG`：hung task、IO 卡死、命令超时。
- `FAIL_CLEANUP`：controller、namespace、key、网络规则残留。
- `FAIL_ORACLE`：fio verify mismatch、partial data silent success、数据错乱。
- `FAIL_INFRA`：环境、命令、工具依赖、权限、参数错误。

`FAIL_INFRA` 不一定是协议 bug，但必须先清掉，否则会污染覆盖率和失败率。

## 13. 失败 case 复现

每个 case 的目录通常包含：

```text
case.yaml
command.json
stdout.log
stderr.log
summary.json
fio.json
vdbench.parm
```

复现步骤：

```bash
CASE_DIR=artifacts/run-fio-write-smoke/case-17
cat $CASE_DIR/case.yaml
cat $CASE_DIR/command.json
cat $CASE_DIR/summary.json
```

从 `command.json` 取出 `argv`，在同一台测试机上重新执行。复现前后建议采集：

```bash
nvme list -o json > $CASE_DIR/nvme-before.json
dmesg --ctime --color=never > $CASE_DIR/dmesg-before.log

# 这里执行 command.json 里的命令

nvme list -o json > $CASE_DIR/nvme-after.json
dmesg --ctime --color=never > $CASE_DIR/dmesg-after.log
```

如果是断链、残留或 hang，要额外保存：

```bash
nvme list-subsys -o json > $CASE_DIR/nvme-subsys-after.json
ss -tnpi > $CASE_DIR/ss-after.txt
```

## 14. 清理和恢复

每轮冒烟后建议主动清理：

```bash
sudo nvme disconnect -n $SUBSYSNQN || true
nvme list
nvme list-subsys
dmesg --ctime --color=never | tail -n 200
```

如果使用了 `tc`、`iptables` 或 `nft` 故障注入，必须恢复：

```bash
sudo tc qdisc del dev $IFACE root 2>/dev/null || true
sudo iptables-save > artifacts/env/iptables-after.rules
sudo nft list ruleset > artifacts/env/nft-after.rules 2>/dev/null || true
```

确认能重新 connect：

```bash
sudo nvme connect -t tcp -a $TRADDR -s $TRSVCID -n $SUBSYSNQN
nvme list
```

## 15. 常见问题

### 15.1 dry-run 全是 PASS，但真实运行全是 FAIL_INFRA

检查 fio/vdbench 是否安装、是否在 `PATH` 中、当前用户是否有权限访问 `$DEV`。

```bash
which fio
fio --version
ls -l $DEV
```

### 15.2 写 case 被跳过

这是预期安全行为。写类 workload 必须显式加：

```bash
--allow-write
```

只允许对内存 fake namespace 或白名单测试 namespace 使用。

### 15.3 `planned_cases` 和 `selected_cases` 不一样

如果使用了 `--limit` 或分片，这是正常的：

- `planned_cases`：campaign 文件总 case 数。
- `selected_cases`：本轮实际选择执行的 case 数。
- `executed_cases`：本轮已经处理并写 summary 的 case 数。

### 15.4 浏览器能访问 GitHub，但 Git 不行

如果 Windows 浏览器走本地代理，例如 `127.0.0.1:7890`，Git 也要配置代理：

```bash
git config http.proxy http://127.0.0.1:7890
git config https.proxy http://127.0.0.1:7890
```

取消：

```bash
git config --unset http.proxy
git config --unset https.proxy
```

### 15.5 当前版本是否已经真正做 PDU 注入

当前 README 中的 `run` 路径会消费 campaign，并驱动 fio/vdbench 产生 IO 和报告产物。它还没有把每条 case 自动接入 `fake_target` 或 `split_proxy`，所以不会自动篡改 TLS 后明文 PDU。

如果要做真正的协议字段注入，需要补齐运行时集成：

- 启动 fake target 或 split proxy 的 CLI。
- 根据 case mutation 生成 proxy rule。
- 在每个 case 执行前后自动 connect、跑 IO、断链、采集 oracle。
- 把 PDU trace 写入 case artifact。

这部分是下一步实现重点。

## 16. 最小可跑命令清单

下面是一条从生成到报告的最小闭环：

```bash
mkdir -p artifacts

python -m pangea_fuzz.cli nvmetcp-tls generate-campaign \
  --seed 20260617 \
  --count 100 \
  --random-ratio 0.2 \
  --output artifacts/campaign-smoke.jsonl \
  --summary

python -m pangea_fuzz.cli nvmetcp-tls run \
  --campaign artifacts/campaign-smoke.jsonl \
  --artifacts-dir artifacts/run-smoke-dry \
  --engine fio \
  --device /dev/nvme1n1 \
  --workers 4 \
  --limit 20 \
  --dry-run

python -m pangea_fuzz.cli nvmetcp-tls generate-report \
  --campaign artifacts/campaign-smoke.jsonl \
  --artifacts-dir artifacts/run-smoke-dry \
  --output-md artifacts/fuzz-report-smoke.md \
  --output-json artifacts/fuzz-report-smoke.json
```

看到 `artifacts/fuzz-report-smoke.md` 后，再进入真实 IO 冒烟和全量 campaign。
