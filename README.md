# Project Vuln Repair 0.3.0

Project Vuln Repair 是一个证据驱动的漏洞修复控制器，支持两类流程：C/C++ 源码项目修复，以及重托管 IoT 固件的路线 A 修复。控制器负责执行、证据、验收和回滚；模型只获得经过批准的分析材料，并返回受约束的提案，最终由软件自行验证。

长期目标是逐步扩展为面向绝大多数固件的大模型自动漏洞修复系统。当前不能这样宣称：真实端到端修复证据仍只覆盖 D-Link DIR-825 B 2.03 的 CVE-2025-6291 场景，即 MIPS32 big-endian `sbin/httpd` 栈溢出类漏洞。已验证固件/CVE 矩阵见 [docs/SUPPORTED_FIRMWARE.md](docs/SUPPORTED_FIRMWARE.md)，可迁移的案例说明见 [cases/README.md](cases/README.md)，通用化路线、阶段边界和完成标准见 [docs/ROADMAP.md](docs/ROADMAP.md)。

当前版本：**0.3.0**。本版是当前固件管线的文档和源码树基线。当前验证边界见 [VALIDATION.md](VALIDATION.md)，架构说明见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)，操作手册见 [docs/OPERATIONS.md](docs/OPERATIONS.md)。

## 功能定位

### C/C++ 源码修复

用户提供源码项目、PoC、构建命令和测试。控制器复制项目，在隔离副本中复现故障，调用模型分析并生成补丁 proposal，再构建、测试、独立评估每个候选，最终输出可复查的报告和候选产物。原始源码目录不会被直接修改。

### IoT 固件路线 A

当前有真实修复闭环证据的固件只有 D-Link DIR-825 B 2.03 的 CVE-2025-6291 场景：MIPS32 big-endian/o32、目标 `sbin/httpd`、80 端口 ASCII HTTP GET/HEAD、栈溢出类致命内存破坏。0.3.0 已在同一固件的 CVE-2024-57595 命令注入案例中通过受限 HTTP 表单 POST / Cookie / 多步协议的 doctor 与 marker reproduce 验证；该新路线尚未调用模型、尚未生成候选，也尚未完成独立 verify。FirmAE 只执行 diagnostic-only 的 compatibility/analysis，导出转换后的文件系统映像；`repair intake` 校验并把该映像物化为隔离 rootfs，生成案例配置。随后控制器使用权威运行时 `native-proot-mips32be` 完成 PoC 复现、定位、测试生成、补丁植入、回滚和最终验证。

交互式路线 A 向导会逐步引导输入检查、FirmAE analysis、intake、doctor、真实模型修复、报告查看和可选独立验证。第 5 步会向模型服务商外发数据，必须输入大写 `YES`。

## 能力边界

| 层级 | 当前能力 |
|---|---|
| 权威固件运行时 | `native-proot-mips32be` |
| 架构后端 | ELF32 big-endian MIPS32 / o32（`mips32be`） |
| 协议驱动 | 80 端口、ASCII HTTP GET/HEAD；另有受限表单 POST、Cookie 捕获/重放和多步 HTTP 驱动 |
| 已验证固件路线 | D-Link DIR-825 B 2.03，`dlink`，`mipseb`，`sbin/httpd` |
| 设备接入层 | 通用 session/runtime 逻辑 + 封闭 profile 注册表 + 只读 `repair boot-plan` 候选推断 |
| FirmAE 角色 | diagnostic-only compatibility/analysis 与路线 A 文件系统 intake；拒绝 `run/-r` |
| Greenhouse 角色 | 仅存在诊断适配契约；不声称真实 CLI 或修复权威可用 |
| 源码模式 | 保留 Ubuntu C/C++ 项目修复 |
| 模型接口 | OpenAI 兼容 API；真实证据使用智谱 GLM-5.3 |

未注册的运行时、架构、协议、品牌或目标会显式报告能力不支持，不会静默使用近似方案。

## 当前能力与发展路线

| 范围 | 当前状态 |
|---|---|
| 真实修复闭环 | 仅 DIR-825 B 2.03 / CVE-2025-6291 / MIPS32BE / `sbin/httpd` / 栈溢出类漏洞 |
| 架构后端 | 仅 `mips32be`；MIPS32LE、ARM32、AArch64 等未验证 |
| 权威固件运行时 | 仅 `native-proot-mips32be` |
| 协议驱动 | 已注册 GET/HEAD 与受限表单 POST/多步协议；仅 GET/HEAD 路线有真实闭环证据；HTTPS、非 80 端口和任意 header/body 未支持 |
| FirmAE | 路线 A diagnostic-only analysis/intake；不执行 `run/-r`，不作为权威验收 |
| Greenhouse | 仅 diagnostic-only adapter 契约；真实 CLI 兼容性未验证 |
| 漏洞类型 | 仅真实验证栈溢出类致命内存破坏；堆溢出、UAF、格式化字符串等未验证 |

后续按 `docs/ROADMAP.md` 的 P1–P6 推进：先泛化输入与诊断，再扩展架构族、runtime、协议和漏洞类型，最后建立批量评测。同固件的 CVE-2024-57595 命令注入已经完成受控 PoC 方法验证和控制器 doctor/marker reproduce；下一步是模型定位、候选修复和独立 verify。任何新固件都必须同时满足 [docs/SUPPORTED_FIRMWARE.md](docs/SUPPORTED_FIRMWARE.md) 的入库标准，获得提取、启动、协议、架构、定位、补丁、回滚、独立 verify 和真实 `validated_candidate` 证据后，才进入“已支持”清单。

## Ubuntu 快速开始

### 安装

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip build-essential cmake clang llvm strace unzip qemu-user proot util-linux iproute2
mkdir -p ~/tools
sha256sum -c project-vuln-repair-0.3.0.zip.sha256
unzip project-vuln-repair-0.3.0.zip -d ~/tools
cd ~/tools/project-vuln-repair
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m pip check
python -c 'import repair_tool; print(repair_tool.__version__)'
```

版本命令必须输出 `0.3.0`。

### 检查就绪状态

```bash
repair doctor --config <case.yaml>
```

路线 A 使用 `repair intake` 生成的 case。只有 doctor 输出 `ready` 后才执行 `repair run`。

### 启动路线 A 向导

```bash
cd ~/tools/project-vuln-repair
source .venv/bin/activate
python scripts/firmae_route_a_wizard.py \
  --config <route-a-intake.yaml> \
  --firmware <original-firmware.bin> \
  --brand dlink \
  --output-root <new-or-empty-generated-case-dir>
```

向导把不含密钥的进度保存在 intake 模板旁。失败后先诊断当前 run；重跑真实模型必须显式选择菜单 5，并输入大写 `YES`。

### 启动修复任务

```bash
repair run --config <case.yaml>
```

`repair run` 总是创建新任务，不会从旧任务的中断模型轮次恢复。

### 查看和独立验证

```bash
repair inspect --run <run-id-or-directory>
repair verify --run <run-id-or-directory>
```

`validated_candidate` 表示控制器在已支持运行时上观察到固定检查、稳定 PoC 重放身份、生成测试、回滚/复现和候选重部署证据。它不表示物理硬件验收。

## 命令

| 命令 | 用途 |
|---|---|
| `repair doctor` | 校验模型/配置、运行时、namespace、目标、架构、协议和能力 |
| `repair triage` | 导入或执行 diagnostic-only FirmAE/Greenhouse 诊断 |
| `repair intake` | 校验 FirmAE analysis run，并物化路线 A generated case |
| `repair boot-plan` | 只读扫描 rootfs，输出常见目标、init 线索和架构候选；不授权运行 |
| `repair run` | 创建新的源码或固件修复任务 |
| `repair inspect` | 只读查看已完成 run 并汇总证据 |
| `repair verify` | 不调用模型，独立验证已接受 run |
| `scripts/firmae_route_a_wizard.py` | 交互式路线 A 分步流程 |
| `scripts/package.py` | 构建并校验版本化源码发布包 |

## 模型与数据边界

- 模型密钥不进入被跟踪的 case 文件或报告。
- 凭据可以放在被忽略的软件级 `config.yaml`，或由配置的环境变量提供。
- 外部诊断只是不可信事实；可以只读查询，不能替代新鲜补丁位点注册。
- 每个定位/重定位会话都必须有新的 `register_patch_site` 证据。
- 未完成的生成 POST 不会自动重放。
- 固件请求由注册协议驱动编码；仅允许 80 端口 ASCII GET/HEAD，或封闭校验的表单 POST、有限 Cookie 和声明式多步请求。marker 验收只允许预声明空文件。
- `repair run` 会把目标证据、PoC、诊断和分析数据外发给配置的模型服务商；向导要求显式确认。

## 源码树

```text
repair_tool/       控制器、固件模型循环、session/runtime/profile 分层
  firmware/session/       通用进程身份、清理和会话私有 HTTP 隧道
  firmware/runtimes/      已注册执行运行时的通用装载与运行事实
  firmware/profiles/      设备 profile 注册表、候选 BootPlan 和 DIR-825 profile
scripts/           打包工具、路线 A 向导、受控 FirmAE wrapper
tests/             单元、契约、夹具和集成测试
docs/              当前架构、路线图、操作手册、变更记录和发布记录
cases/             案例说明、PoC、模板、修复源码和脱敏结果；本地归档被忽略
dist/              生成的发布 ZIP；不是团队源码
config.yaml        本地被忽略软件配置；如存在则不得提交
.test-python/      本地 Windows 测试依赖
.linux-python/     本地 Linux 方向测试依赖
local-archive/     被忽略的历史资料；不发布
tmp/               被忽略的工作目录
```

过程性旧文档、历史 ZIP 和临时资料由各 operator 保存在被忽略的本机归档目录。它们可用于审计，但构建和运行 0.3.0 不依赖这些内容。

## 验证策略

每个部署后的程序版本只执行一次 Ubuntu 全量回归。同版本小修只跑必要定向检查，除非明确要求全量。部署测试必须运行在固定 Ubuntu 安装目录，不能从 Windows 源码目录的挂载路径借用源码运行。

0.3.0 已部署到 Ubuntu 24.04 WSL 固定路径并完成一次全量回归：`728 passed, 1 skipped`。随后真实 DIR-825 路线 A 从原始 `.bin` 经 FirmAE analysis、intake、doctor、GLM-5.3 repair run 到独立 verify 全链路通过：run `20261021-024629-b18f2722` 为 `validated_candidate`，独立验证为 `verified_with_cleanup_warnings`。详细证据见 [VALIDATION.md](VALIDATION.md)。

## 版本历史

- **0.2.0 之前：** 0.0.x–0.1.x 建立了源码项目修复循环、构建/ASan 绑定、模型适配、打包和报告验证，是源码模式的历史基础。
- **0.2.0：** 引入 DIR-825 固件修复模式和证据驱动重托管循环。
- **0.2.1–0.2.9：** 收紧重放身份、测试语义、结果血缘、阶段时限、上下文限制、查询预算和定位状态机。
- **0.2.10–0.2.15：** 改进模型调用策略、智谱 reasoning 兼容、分页、地址别名、重定位、语义提名和证据账本审计。
- **0.2.16：** 增加受控 FirmAE analysis wrapper 和自动路线 A intake；首次完成真实 DIR-825 从 `.bin` 到 `validated_candidate`。
- **0.2.17：** 增加交互式路线 A 向导和单模板 FirmAE execute 装载。
- **0.2.18：** 修复崩溃后端口占用者清理，保留结构化失败/会话诊断。
- **0.3.0：** 围绕当前能力基线整理项目，重构 session/runtime/profile 分层并新增只读 `repair boot-plan`，注册受限 HTTP 表单 POST/多步协议和 marker 验收，新增固件通用化路线图，重构中文团队文档，把文档纳入发布包，归档过期过程资料，并优化路线 A 向导交互。

逐版简史见 [docs/CHANGELOG.md](docs/CHANGELOG.md)。
