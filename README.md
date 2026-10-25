# Project Vuln Repair

Project Vuln Repair 是一个面向 IoT 固件的大模型自动漏洞修复系统。控制器负责固件输入、隔离重托管、证据采集、请求编码、候选部署、回归验收和回滚；大模型只负责调查和提出受约束的修复提案。任何候选都必须先通过控制器的运行时证据，再进入最终报告。

项目长期目标是让“固件包 + 可复现 PoC + 验收条件”逐步成为常规输入，自动完成提取、启动、复现、定位、修复和独立验证。当前版本 **0.3.1** 已经在 D-Link DIR-825 Rev. B 2.03 的 `sbin/httpd` 上完成两个真实闭环：CVE-2025-6291 栈溢出和 CVE-2024-57595 命令注入。这个结果不能推广为任意固件、任意架构或物理硬件支持。

## 当前能力

| 能力 | 当前状态 |
|---|---|
| 权威固件运行时 | `native-proot-mips32be`：隔离 namespace + PRoot/QEMU |
| 架构后端 | `mips32be`：ELF32 big-endian MIPS32 / o32 |
| 协议驱动 | 80 端口受限 ASCII GET/HEAD；受限表单 POST、Cookie/字段捕获和多步 HTTP |
| 已验证设备 | D-Link DIR-825 Rev. B 2.03 / `sbin/httpd` |
| 漏洞类型 | 栈溢出致命退出、命令注入空文件 marker 差异 |
| 固件输入路线 | FirmAE diagnostic-only compatibility/analysis → `repair intake` → 权威 runtime |
| 设备接入 | 通用 session/runtime 层 + 封闭 profile 注册表 + 只读 BootPlan 推断 |
| 模型接口 | OpenAI 兼容 Chat Completions；真实证据使用智谱 GLM-5.3 |

未注册的 runtime、架构、协议、品牌或 profile 会被 doctor 显式拒绝，不会静默降级到近似方案。Greenhouse 目前只有 diagnostic-only 适配契约，真实 CLI 兼容性未验证。

## 系统要求

- Ubuntu 24.04 或兼容 Linux 发行版；
- Python 3.11+、`python3-venv`、`pip`；
- 固件路线需要 PRoot、QEMU user、clang/LLVM MIPS 交叉目标、`iproute2`、`util-linux`；
- FirmAE 路线 A 由受控 wrapper 调用，不要求把 FirmAE 作为权威修复运行时。

Windows 可以运行部分纯单元测试。POSIX 锁、Unix socket、PRoot/QEMU、交叉编译和固件集成测试必须在 Linux 环境执行。

## Ubuntu 快速开始

### 安装

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip build-essential cmake clang llvm strace unzip qemu-user proot util-linux iproute2

mkdir -p ~/tools
cd /path/to/release-download
sha256sum -c project-vuln-repair-0.3.1.zip.sha256
unzip project-vuln-repair-0.3.1.zip -d ~/tools

cd ~/tools/project-vuln-repair
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m pip check
python -c 'import repair_tool; print(repair_tool.__version__)'
```

版本命令必须输出 `0.3.1`。发布包固定只有一个顶层 `project-vuln-repair/` 目录，不要把版本号写进安装路径。

### 检查就绪状态

```bash
repair doctor --config /path/to/case.yaml
```

只有 doctor 输出 `ready` 后才执行 `repair run`。doctor 会同时检查模型配置、runtime、namespace、目标 ELF、架构、协议、profile 和 fixed checks 能力。

## 模型配置

推荐把密钥放在环境变量中，并在安装目录使用被 Git 忽略的 `config.yaml`：

```yaml
model:
  provider: openai_compatible
  base_url: https://model-provider.example/v1
  name: your-model
  api_key_env: REPAIR_API_KEY
```

```bash
read -s REPAIR_API_KEY
export REPAIR_API_KEY
```

控制器不内置模型密钥或端点。真实 `repair run` 会向配置的模型服务商外发目标证据、PoC、诊断和分析数据；路线 A 向导在第 5 步要求输入大写 `YES`，且该确认只对当次任务有效。

## 最小工作流

### 路线 A：从原始固件进入修复

如果已有路线 A intake 模板，可使用交互式向导：

```bash
cd ~/tools/project-vuln-repair
source .venv/bin/activate
python scripts/firmae_route_a_wizard.py \
  --config /path/to/route-a-intake.yaml \
  --firmware /path/to/firmware.bin \
  --brand dlink \
  --output-root /path/to/new-case
```

向导会依次执行输入检查、FirmAE analysis、intake/rootfs 物化、doctor、真实修复、报告查看和可选独立验证。每一步都有状态、产物路径和失败诊断；真实模型步骤必须显式确认。

也可以按 [操作手册](docs/OPERATIONS.md) 使用 `repair triage`、`repair intake`、`repair doctor` 和 `repair run` 的显式命令。

### 已有 rootfs 的固件案例

```bash
repair doctor --config /path/to/case.yaml
repair run --config /path/to/case.yaml
repair inspect --run /path/to/repair-results/run-id
repair verify --run /path/to/repair-results/run-id
```

`repair run` 总是创建新任务，不会从旧任务的中断模型轮次恢复。`validated_candidate` 表示控制器在已支持运行时上观察到固定检查、稳定 PoC 重放身份、生成测试、回滚和候选重部署证据；它不表示物理硬件验收。

## 命令参考

| 命令 | 用途 |
|---|---|
| `repair doctor` | 校验模型配置、runtime、namespace、目标、架构、协议、profile 和能力 |
| `repair triage` | 导入或执行 diagnostic-only FirmAE/Greenhouse 诊断 |
| `repair intake` | 校验 FirmAE analysis run，物化 rootfs 并生成案例 |
| `repair boot-plan` | 只读扫描 rootfs，输出候选目标、init 线索和架构，不授权运行 |
| `repair run` | 创建新的源码或固件修复任务 |
| `repair inspect` | 只读查看已完成 run 并汇总证据 |
| `repair verify` | 不调用模型，独立验证已接受 run |
| `scripts/firmae_route_a_wizard.py` | 交互式路线 A 向导 |
| `scripts/package.py` | 构建并校验版本化发布包 |

## 文档

| 文档 | 内容 |
|---|---|
| [操作手册](docs/OPERATIONS.md) | 安装、配置、路线 A、更新、结果解释和故障处理 |
| [架构说明](docs/ARCHITECTURE.md) | 控制流、信任边界、session/runtime/profile 分层和扩展点 |
| [已验证固件清单](docs/SUPPORTED_FIRMWARE.md) | 真实闭环证据的唯一入口 |
| [路线图](docs/ROADMAP.md) | 通用化阶段、完成标准和成功指标 |
| [案例规范](cases/README.md) | PoC、补丁和脱敏结果的团队归档契约 |
| [贡献指南](docs/CONTRIBUTING.md) | 开发环境、测试策略、PR 检查单和案例贡献 |
| [安全策略](docs/SECURITY.md) | 信任边界、模型数据外发、隔离和漏洞报告 |
| [变更记录](docs/CHANGELOG.md) | 面向使用者的版本变化 |
| [验证账本](VALIDATION.md) | 历史测试、真实 run 和独立 verify 记录 |

完整文档索引见 [docs/README.md](docs/README.md)。

## 仓库布局

```text
repair_tool/                控制器、源码/固件工作流、模型契约和 CLI
  firmware/session/         通用进程身份、清理和会话私有 HTTP 隧道
  firmware/runtimes/        权威 runtime 的装载与运行事实
  firmware/profiles/        封闭设备 profile、DIR-825 profile 和 BootPlan
  firmware/protocol.py      封闭协议注册表
  arch/                     架构后端注册表与 MIPS32BE 后端
scripts/                    打包、路线 A 向导、受控 FirmAE wrapper
tests/                      单元、契约、夹具和 Linux 集成测试
docs/                       操作、架构、支持矩阵、路线图和发布记录
cases/                      可分享案例卡、PoC、配置模板和脱敏证据
dist/                       本地生成的发布包；不进入 Git
config.yaml                 本地被忽略模型配置；不进入 Git
tmp/、local-archive/        本地工作目录和历史资料；不进入 Git
```

## 验证状态

- 0.3.0 已在 Ubuntu 24.04 WSL 固定安装路径完成一次部署后全量回归：`728 passed, 1 skipped`。
- CVE-2025-6291 真实 run `20261021-024629-b18f2722`：`validated_candidate`；独立 verify：`verified_with_cleanup_warnings`。
- CVE-2024-57595 真实 run `20261023-015556-7ca0e8ea`：`validated_candidate`；最终测试 4/4；独立 verify：`verified_with_cleanup_warnings`。
- 0.3.1 完成定向测试与发布包校验，尚未执行新的 Ubuntu 部署后全量回归。

证据边界和逐项记录见 [VALIDATION.md](VALIDATION.md) 与 [docs/SUPPORTED_FIRMWARE.md](docs/SUPPORTED_FIRMWARE.md)。

## 参与贡献

代码、测试、文档和案例贡献都欢迎。贡献必须说明验证环境、定向测试结果和未验证边界；不要提交密钥、原始固件、rootfs、完整模型响应或私有路径。开始前请阅读 [贡献指南](docs/CONTRIBUTING.md) 与 [安全策略](docs/SECURITY.md)。
