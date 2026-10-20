# 0.3.0 验证状态

日期：2026-10-21（Asia/Shanghai）

## 当前范围

0.3.0 是当前固件管线的版本、文档、打包和源码树基线。本页记录 0.3.0 已执行的检查、真实修复成功 run，以及 CVE-2024-57595 控制器 marker reproduce 结果。

当前已完成真实端到端修复的固件/CVE 组合见 [docs/SUPPORTED_FIRMWARE.md](docs/SUPPORTED_FIRMWARE.md)。

本发布步骤中没有提交或上传 GitHub。

## 0.3.0 检查

以下检查在 2026-10-21 的 Windows 源码工作区执行：

1. `python -m py_compile scripts\package.py scripts\firmae_route_a_wizard.py repair_tool\__init__.py tests\test_package_contents.py tests\test_firmae_route_a_wizard.py` — 通过。
2. `python -m pytest tests\test_firmae_route_a_wizard.py tests\test_package_contents.py -q --basetemp=tmp\pytest-0.3.0-ui-final` — **10 passed**。
3. `python -m pytest tests\test_package_contents.py -q --basetemp=tmp\pytest-0.3.0-roadmap` — **2 passed**，覆盖新增路线图文档的打包断言。
4. 首次向导测试尝试因 pytest 默认外部临时目录无法创建 `tmp_path` 而在 fixture setup 报 7 个环境错误；改用项目内 `--basetemp` 后同一测试集合通过。该失败不涉及产品代码断言。
5. `python scripts\package.py` — 生成 101 个文件的 `dist/project-vuln-repair-0.3.0.zip` 与同名 `.zip.sha256`。
6. `python scripts\package.py --check` — 压缩包 checksum、固定根目录、文件列表、CRC 和逐文件源码字节一致性通过。
7. `git diff --check` — 通过，无空白错误。

本轮 session/runtime/profile 重构和候选 BootPlan 追加以下检查：

1. 对 profile 注册表、BootPlan、DIR-825 profile supervisor/wireless、通用 session 进程与 HTTP 隧道、MIPS32BE runtime loader、rehost/case/intake/config/CLI 执行 `python -m py_compile` — 通过。
2. `python -m pytest tests\test_firmware_boot_plan.py tests\test_firmware_doctor_capabilities.py tests\test_config_validation.py tests\test_firmware_intake.py tests\test_firmware_triage_cli.py tests\test_firmware_fault_context.py tests\test_firmware_supervisor_restart.py tests\test_package_contents.py -q --basetemp=tmp\pytest-profile-refactor-final` — **62 passed, 1 skipped**。跳过项为 Windows 无法创建 POSIX symlink。
3. `python -m pytest tests\test_firmware_case.py -q --basetemp=tmp\pytest-profile-refactor-case-final -k "firmware_mode or request_bytes or doctor"` — **20 passed, 1 skipped, 7 deselected**。跳过项同为 POSIX symlink 环境限制。
4. `python scripts\package.py` — 重新生成 110 个文件的 `dist/project-vuln-repair-0.3.0.zip` 与同名 `.zip.sha256`。

部署前补充检查发现并修复三个 0.3.0 文档/测试遗留问题：打包测试夹具缺少 `.gitattributes`、README 快速开始缺少 ZIP checksum 校验、源码示例仍使用字符串命令且配置 schema 与 argv 数组契约不一致。修复后：

- `python -m pytest tests\test_packaging.py tests\test_config_validation.py -q` — **14 passed**；
- 重新生成 110 个文件的 0.3.0 包并通过 `python scripts\package.py --check`。

## Ubuntu 24.04 WSL 部署与全量回归

- 固定安装路径：`$HOME/tools/project-vuln-repair/`。
- 包先复制到 Ubuntu 下载目录并通过 `sha256sum -c`；checksum 以 `dist/project-vuln-repair-0.3.0.zip.sha256` 为准。
- 旧管理目录已先备份到安装目录旁的备份目录，随后完整替换 `repair_tool/`、`tests/`、`scripts/`、`docs/` 和顶层项目文件；原 `.venv`、案例、诊断和历史结果保留。
- `python -m pip install -e '.[dev]'` 与 `python -m pip check` 通过；模块版本 `0.3.0`，实际加载路径位于固定 Ubuntu 安装目录内。
- 第一次全量回归为 **3 failed, 5 errors, 720 passed, 1 skipped**。失败原因是 0.3.0 文档重构后打包测试仍按旧 README/夹具断言，并暴露 `*.command` 配置 schema 与 argv 数组契约不一致；已修复并重新打包部署。
- 修复后同一部署版本的全量回归：**728 passed, 1 skipped, 531.78 seconds**。日志保留在部署备份目录的 `pytest-full-0.3.0-final.log`。

最终压缩包 SHA256 不复制到会被打包的文档中，避免自引用。当前摘要以 `dist/project-vuln-repair-0.3.0.zip.sha256` 为准。

## 已验证固件/CVE 清单补充检查

发布后新增 `docs/SUPPORTED_FIRMWARE.md`，登记当前唯一真实闭环样本 DIR-825 B 2.03 / CVE-2025-6291、run `20261021-024629-b18f2722`、独立验证结果和 GET 场景边界；README、路线图、架构说明和发布记录均已链接该矩阵。

该补充为文档和打包清单变更，不修改程序代码，不重新部署，也不重复全量回归。定向检查和重新打包结果见本文“最终清单补充验证”。

## 源码树与归档状态

当前团队源码树包含控制器、测试、脚本、精选文档、打包元数据、本地依赖目录、被忽略的本地配置和被忽略的工作目录。

历史资料保留在被忽略的本机归档目录，包括：

- 旧顶层 README 和 VALIDATION；
- 已被替代的设计文档与任务书；
- 历史 0.2.x 发布 ZIP 和 checksum；
- 实验、历史修复结果、临时资料和缓存。

归档被有意排除在 Git 和发布包外。它是审计轨迹，不是运行时依赖。

## 0.3.0 真实 DIR-825 / CVE-2025-6291 路线 A 验证

- CVE-2025-6291 case 已整理为团队可上传的 PoC、输入模板、修复源码和脱敏结果；完整 run 身份见 `cases/dlink/dir825b-2.03/cve-2025-6291/results/result-summary.json`。
- 原始固件：`dir825_revB_fw_203NA.bin`，SHA256 `379836b8625f32fb3c2642656f056e9bf43f929101e2ff758bb5049c5373ef2d`。
- FirmAE diagnostic-only analysis run：`triage-20261021-024422-5551`，状态 `diagnostics_generated`，`returncode=0`，耗时 91.809 秒；报告兼容、启动、网络、rootfs 提取和 `mipseb` 架构，原始固件执行前后 SHA 不变。
- `repair intake` 状态 `intake_ready`：物化 521 个文件、80 个目录、78 个符号链接；目标 `sbin/httpd` SHA256 `a7b4741736dd3f5572da480deb3a785fb17d3b5b60e7bf82f686b9844b5097b7`，身份为 ELF32 big-endian MIPS/o32 `mips32be`。
- 真实 rootfs 上 `repair boot-plan` 找到 `sbin/httpd`，架构和协议均已注册，置信度 0.93，并识别 `sbin/rc`、`etc/rc.d/rcS` 等 init 线索。
- `repair doctor` 输出 profile `dlink/dir825b-2.03`，runtime/architecture/protocol 全部 supported，状态 **`ready`**。
- 真实 GLM-5.3 `repair run`：`20261021-024629-b18f2722`，状态 **`validated_candidate`**，耗时 855.539 秒；基线固定检查 1/1 通过，最终生成测试 3/3 通过，PoC 重放身份稳定。
- 修复位点：十进制 `4236836`；候选 `sbin/httpd` SHA256 `464832db54db8c4dec28c3d7ef335a2313d172a3144bf50a52db92ce6f1d8ddd`。
- 独立 `repair verify`：**`verified_with_cleanup_warnings`**。警告仅是非 root 控制器无法删除 root 持有的临时 `host-rootfs` 目录，候选验证本身通过。

该组合的固件/CVE 矩阵、证据摘要和解释边界见 [docs/SUPPORTED_FIRMWARE.md](docs/SUPPORTED_FIRMWARE.md)。

## CVE-2024-57595 PoC 方法验证

2026-10-21 使用 0.3.0 已部署的 DIR-825 profile 在 WSL 中启动一次性隔离 PRoot/QEMU session，验证同固件的 CVE-2024-57595 PoC 方法。该实验不调用模型、不生成候选、不运行 `repair run`，也不是部署版本全量回归。

- 静态检查确认 `sbin/httpd` 含 `apc_client_pin.cgi`、`wps_pin`、`wpatalk ... 'configme pin=%s clean' ...` 命令模板，并导入 `system` 与 `popen`。
- 登录后 `GET /lan.asp` 出现 `login_who="admin"`。
- 合法 PIN `12345670` 返回 HTTP 200，未创建 marker；目标保持存活。
- 正好 8 字节的 `wps_pin=';>/Q ;#` 返回 HTTP 200，并在隔离 rootfs 根创建空文件 `/Q`。
- 注入后再次提交合法 PIN，服务仍可响应，`/Q` 保持不变。
- 观察窗口内目标退出记录为 0；源 rootfs 中 `sbin/httpd` SHA256 保持 `a7b4741736dd3f5572da480deb1a785fb17d3b5b60e7bf82f686b9844b5097b7`。
- 脱敏证据见 `cases/dlink/dir825b-2.03/cve-2024-57595/results/poc-validation.json`。

该结果证明隔离 PoC 方法。0.3.0 源码随后实现了受限表单 POST、Cookie 捕获/重放、多步 HTTP 和空文件 marker 验收；控制器 doctor/reproduce 的真实验证见下一节。该 CVE 仍未完成模型修复 run 与独立 verify，因此不进入已验证固件清单。

## CVE-2024-57595 控制器 doctor / marker reproduce

2026-10-21 将 0.3.0 部署到 WSL 固定安装路径后执行：

- 压缩包 checksum、固定根目录、文件列表、CRC 和逐文件源码字节一致性通过；部署保留 `.venv`、本机配置、案例和历史结果。
- `python -m pip install -e '.[dev]'`、`python -m pip check` 通过；模块版本 `0.3.0`，实际加载路径位于固定安装目录内。
- 真实 `repair doctor` 返回 **`ready`**；profile 为 `dlink/dir825b-2.03`，runtime `native-proot-mips32be`、architecture `mips32be`、protocol `http-ascii-auth-form-multi-step-port80` 全部 supported。
- 真实控制器 marker reproduce 返回 **`marker_reproduced`**；`home`、`login`、`authenticated_page`、`valid_pin_control` 和 `marker_trigger` 全部 `ok`。
- 合法 PIN 未创建 marker；正好 8 字节注入 PIN 创建空文件 `/Q`；target PID/SHA 前后一致；无非预期 target exit；复现结束后 `/Q` 清理成功。
- 认证页是慢速 close-delimited 响应，只有在步骤显式声明 `accept_timeout: true`，并同时匹配声明状态码和 `login_who= "admin"` 内容时才被接受。无自描述分帧的普通 timeout 仍失败。
- 脱敏结果见 `cases/dlink/dir825b-2.03/cve-2024-57595/results/controller-marker-reproduction.json`。
- 本次未调用模型、未生成候选、未执行 `repair run` 或独立 verify。

为到达最终状态，先修复了 framed envelope 超时竞态、close-delimited 响应验收、固定 checks 校验改写输入导致 lineage 哈希漂移，以及旧测试对配置隐式改写的过时断言。最终部署包全量回归：**749 passed, 1 skipped, 549.84 seconds**。

## 能力边界

当前固件能力必须区分“已注册实现”和“已有真实闭环证据”：

- 运行时：`native-proot-mips32be`；
- 架构：ELF32 big-endian MIPS32/o32（`mips32be`）；
- 已注册协议：80 端口 ASCII HTTP GET/HEAD，以及受限表单 POST、有限 Cookie、声明式多步 HTTP 与空文件 marker 验收；
- 已有真实修复闭环证据的协议和漏洞类型：ASCII HTTP GET/HEAD 与栈溢出类致命内存破坏；
- 已有真实控制器 marker reproduce 证据的协议和漏洞类型：受限表单 POST、认证多步 HTTP 与 OS command injection marker；
- 已验证修复路线：仅 D-Link DIR-825 B 2.03 / CVE-2025-6291 路线 A；
- FirmAE 角色：diagnostic-only compatibility/analysis 与文件系统 intake；
- Greenhouse 角色：仅 adapter 契约，真实 CLI 兼容性未验证。

`repair boot-plan` 只是只读候选推断。受限 POST/多步协议已有 CVE-2024-57595 doctor 与 marker reproduce 证据，但尚无 `validated_candidate` 和独立 verify，不改变已验证修复矩阵。

## 最终清单补充验证

- `python -m pytest tests\test_package_contents.py tests\test_packaging.py -q --basetemp=tmp\pytest-supported-firmware-doc` — **9 passed, 1 skipped**。跳过项为既有 Windows 环境限制。
- `python scripts\package.py` 与 `python scripts\package.py --check` — 重新生成并校验 **111 个文件**的 0.3.0 包。
- `git diff --check` — 通过，无空白错误。
- 该变更只影响文档和发布清单，未修改程序代码，未重新部署 WSL，未重复全量回归。

## 案例索引补充验证

2026-10-21 新增 `cases/` 案例说明索引后执行：

- `python -m py_compile scripts\package.py tests\test_package_contents.py` — 通过。
- `python -m pytest tests\test_package_contents.py tests\test_packaging.py -q --basetemp=tmp\pytest-case-index-final` — **9 passed, 1 skipped**。跳过项为既有 Windows 环境限制。
- `git check-ignore` 验证 case 的固件、rootfs、生成配置和 `repair-results/` 会被排除；案例 README、PoC、模板、修复源码和脱敏结果 JSON 不会被忽略。
- `python scripts\package.py` 与 `python scripts\package.py --check` — 重新生成并校验 **114 个文件**的 0.3.0 包。
- `git diff --check` — 通过，无空白错误。

后续案例精简复核：不保留原始固件、完整 rootfs 或完整 run 压缩包，只保留 PoC、示例配置、修复源码、PoC 计划、生成测试和结果摘要；固件来源、大小和 SHA256 已写入案例卡。

2026-10-21 按上述精简规则复核后执行：

- 删除 case 本地 `archive/`、`archive-manifest.json` 和临时提取目录；保留的 case 内容合计 **15,996 bytes**。
- `result-summary.json` 只保留 0.3.0 run `20261021-024629-b18f2722`，不再登记旧版本 run。
- 3 个结果 JSON 解析通过。
- `python -m py_compile scripts\package.py tests\test_package_contents.py` — 通过。
- `python -m pytest tests\test_package_contents.py tests\test_packaging.py -q --basetemp=tmp\pytest-case-slim-final` — **9 passed, 1 skipped**。跳过项为既有 Windows 环境限制。
- ZIP 边界检查确认包含 PoC、修复源码、PoC 计划、生成测试和结果摘要，不包含 `archive/`、`.ZIP`、`.bin` 或 `.tar.gz`。
- `git check-ignore` 确认固件、rootfs、生成配置和 `repair-results/` 被排除；案例 README、PoC、模板、修复源码和结果 JSON 不被排除。
- `python scripts\package.py` 与 `python scripts\package.py --check` — 重新生成并校验 **120 个文件**的 0.3.0 包。
- `git diff --check` — 通过，无空白错误。

## CVE-2024-57595 案例补充验证

2026-10-21 完成 PoC 方法验证并整理团队案例后执行：

- `python -m py_compile cases/dlink/dir825b-2.03/cve-2024-57595/poc/poc_trigger.py` — 通过。
- `python -m json.tool cases/dlink/dir825b-2.03/cve-2024-57595/results/poc-validation.json` — 通过。
- `python -m pytest tests/test_package_contents.py tests/test_packaging.py -q --basetemp=tmp/pytest-cve2024-poc-doc` — **9 passed, 1 skipped**。跳过项为既有 Windows 环境限制。
- `git check-ignore` 确认本地官方固件 ZIP 位于被忽略的 `cases/**/archive/**`，不会进入 Git 或发布包。
- `python scripts/package.py` 与 `python scripts/package.py --check` — 重新生成并校验 **122 个文件**的 0.3.0 包。
- `git diff --check` — 通过，无空白错误。

本补充未调用模型、未执行 `repair run`、未部署新版本，也未重复全量回归。

## 受限 POST/多步协议实现验证

2026-10-21 为 CVE-2024-57595 增加受限 `http-ascii-auth-form-multi-step-port80` 协议和空文件 marker 验收后，在 Windows 源码工作区执行定向测试：

- 协议、多步执行、runtime 能力、doctor、plan、验证安全、配置和发布清单：
  `python -m pytest tests/test_firmware_protocol.py tests/test_firmware_http_multi_step.py tests/test_firmware_runtime_capabilities.py tests/test_firmware_doctor_capabilities.py tests/test_firmware_plan.py tests/test_firmware_verification_safety.py tests/test_config_validation.py tests/test_package_contents.py -q --basetemp=tmp/pytest-cve2024-protocol-core` — **69 passed, 4 skipped**。跳过项为 Windows 无法创建 Unix socket 的既有集成用例。
- intake/profile/BootPlan 兼容性：
  `python -m pytest tests/test_firmware_intake.py tests/test_firmware_boot_plan.py -q --basetemp=tmp/pytest-cve2024-protocol-intake` — **17 passed, 1 skipped**。
- 旧 GET/HEAD 案例兼容子集：**3 passed**。
- 所有主要修改模块执行 `python -m py_compile` — 通过。
- 文档更新后复核发布清单和打包契约：
  `python -m pytest tests/test_package_contents.py tests/test_packaging.py -q --basetemp=tmp/pytest-cve2024-protocol-final-doc` — **9 passed, 1 skipped**。
- 首次真实 marker reproduce 暴露 `execute_steps()` 未把 `firmware.poc_request_timeout` 传给 `SessionControl.deliver()`，认证页仍受默认 6 秒传输超时影响。修复后新增超时传递测试：
  `python -m pytest tests/test_firmware_http_multi_step.py tests/test_firmware_plan.py tests/test_firmware_verification_safety.py -q --basetemp=tmp/pytest-marker-timeout-fix` — **18 passed, 4 skipped**。

实现范围包括：封闭协议驱动、URL 编码表单 POST、有限 Cookie/隐藏字段捕获与重放、声明式多步执行、marker 路径和文件类型安全检查、doctor 能力判断、fixed checks、PoC plan、生成测试、reproduce、replay、redeploy verify 和模型摘要脱敏。默认 GET/HEAD 请求在不新增协议字段时保持原语义。

本节只证明定向测试和代码集成。未在 WSL 部署该未打包源码状态，未执行真实 CVE-2024 doctor/reproduce/run/verify，未调用模型，未启动真实 FirmAE/Greenhouse，也未重复全量回归。

完成上述实现和文档同步后重新执行：

- `python scripts/package.py` — 生成 **125 个文件**的 `dist/project-vuln-repair-0.3.0.zip` 与同名 `.zip.sha256`；
- `python scripts/package.py --check` — checksum、固定根目录、文件列表、CRC 和逐文件源码字节一致性通过；
- ZIP 边界检查确认不包含本地配置、固件 ZIP/BIN、rootfs、历史 `repair-results/`、归档、虚拟环境或临时目录；
- `git diff --check` — 通过。

超时修复后的最终 0.3.0 包以 `dist/project-vuln-repair-0.3.0.zip.sha256` 为准；本页不复制最终自引用 checksum。

## 0.3.0 未验证项

- 未执行 Greenhouse，也未验证其兼容性。
- 未验证额外固件架构、协议或 runtime 后端。
- 未验证真实 DIR-825 硬件。

后续部署必须遵循 `AGENTS.md`：安装或更新固定 Ubuntu 路径，保留用户资料，对该部署版本只执行一次全量回归，并把结果记录到本页或新的对应发布记录。
