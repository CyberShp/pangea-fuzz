# 离线部署说明

这个项目设计目标是：上传到 GitHub 后，内网机器可以直接 clone 使用，不需要下载第三方 Python 包。

## 最小 GitHub 仓库包含什么

- Python 包：`nvmetcp_tls_fuzz/`
- 字段字典：`field_catalog.yaml`
- 配置模板：`config.example.yaml`
- 命令入口：`python -m nvmetcp_tls_fuzz.cli`
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
- `tcpdump`
- `iproute2`
- `iptables` 或 `nftables`

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
python -m nvmetcp_tls_fuzz.cli generate-campaign \
  --seed 20260617 \
  --output artifacts/campaign.jsonl \
  --summary
```

生成中文报告：

```bash
python -m nvmetcp_tls_fuzz.cli generate-report \
  --campaign artifacts/campaign.jsonl \
  --artifacts-dir artifacts \
  --output-md artifacts/fuzz-report.md \
  --output-json artifacts/fuzz-report.json
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
