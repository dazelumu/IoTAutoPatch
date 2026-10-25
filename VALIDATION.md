# 0.3.0 / 0.3.1 验证状态

日期：2026-10-21（Asia/Shanghai）

## 当前范围

0.3.0 是固件管线的文档与源码树基线；0.3.1 在其上完成 CVE-2024-57595 wrapper 修复闭环并归档团队案例。本页记录两个版本的检查、真实修复成功 run 与独立验证结果。

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

## wrapper 同位点修正与 relocalize 预算补充

2026-10-22 针对 CVE-2024-57595 的真实失败证据补充以下控制逻辑：

- wrapper 候选因正常控制请求被破坏、触发请求传输/功能失败、marker 仍创建或生成测试回归而失败时，先保留原 site 和 `mode=wrapper`，给模型一次只修正 `repair_entry` 判定逻辑的机会；第二次失败仍按旧策略 relocalize，leaf 候选不启用该重试。
- 同位点修正由控制器硬校验：模型不能把该修正换成新 site 或 leaf；如果证明该调用层无法保留必要行为，仍必须使用 semantic rejection。
- 修正提示包含模型上一版 `repair_entry` 源码、结构化 replay/测试反馈，并明确禁止“整条厂商命令出现任意 shell 元字符就阻断”的粗策略。
- regression/independent 的 pass 测试复用已确认恶意触发时，在 baseline oracle 前直接判为测试设计错误；若变体仍进入 oracle，反馈会明确 marker 触发不能作为 pass 测试。
- relocalize 默认查询预算调整为 16；案例 YAML 显式配置仍优先，当前 CVE-2024-57595 案例若写为 8，需要按续测命令改为 16。
- wrapper patch record 记录最终写入 candidate 的 implant bytes、改写前 bytes、原 callee GOT offset、改写后的 load 指令和 trampoline offset，避免审计记录与候选二进制不一致。

定向验证在 Ubuntu-24.04 / WSL 的项目测试虚拟环境中执行，pytest 临时目录位于 Ubuntu 原生 `/home/lumu/tmp`：

- 精确节点组合首轮 **13 passed, 1 failed**；唯一失败是新增 prompt 测试断言未考虑提示文本换行，修正测试断言后该用例单独复跑通过。
- 相关覆盖包括 wrapper 植入和原调用保留、leaf 旧失败路径、同 site/mode 硬约束、pass 测试复用恶意触发拒绝、marker 验证分类、配置默认值与案例覆盖、patch record 和 proposal prompt。
- 修改模块与测试执行 `python -m py_compile` 通过；`git diff --check` 通过。
- 重新执行 `python scripts/package.py` 与 `python scripts/package.py --check`，生成并校验 **127 个文件**的 0.3.0 包。

本补充未部署 WSL 固定安装路径，未执行全量回归，未调用真实模型，也未运行新的 `repair run` 或独立 verify。

## baseline 复用与受控重试补充

2026-10-22 针对 CVE-2024-57595 真实 run `20261022-181026-c76a4396` 暴露的冗余 `httpd-2` 重启和 `httpd-3` readiness 前崩溃补充以下控制逻辑：

- `baseline-fixed-checks` 在执行前先读取当前 live target 身份；PID/SHA 均仍绑定到 baseline 时直接复用该实例，不再无条件重启。
- 当前 target 缺失、SHA 不匹配或身份查询失败时，仍按原安全规则重启到 baseline。
- baseline 重启若因 `target_start_failed` 失败，只立即受控重试一次；第一次失败的 launch exit 以 PID、信号、阶段和 PC/RA 等中性字段保存到 warning，不携带本地日志路径。
- 非 `target_start_failed` 不重试；连续第二次启动失败直接失败并保留第一次 warning。
- 候选 replace/restart 与候选 pre-ready 崩溃不启用该重试。候选启动失败仍作为候选失败证据进入 failure triage / relocalize，不会被 baseline 重试掩盖。
- 复现成功后的 baseline 恢复同样复用该受控重启入口。

定向验证在 Ubuntu-24.04 / WSL 的项目测试虚拟环境中执行，pytest 临时目录位于 Ubuntu 原生 `/home/lumu/tmp`：

- `python -m pytest tests/test_firmware_loop.py -q -k "baseline_checks_reuse_ready_baseline_without_extra_restart or baseline_checks_restart_when_live_target_is_wrong or baseline_restart_retries_one_target_start_failure or baseline_restart_does_not_retry_non_start_or_repeated_failure or pre_ready_candidate_exit_relocalizes_with_sanitized_fault or reproduction_failure_surfaces_restart_failure"` — **6 passed**。
- `python -m py_compile repair_tool/firmware/loop.py tests/test_firmware_loop.py` — 通过。
- `git diff --check -- repair_tool/firmware/loop.py tests/test_firmware_loop.py` — 通过。
- 重新执行 `python scripts/package.py` 与 `python scripts/package.py --check`，生成并校验 **127 个文件**的 0.3.0 包；最终 checksum 以 `dist/project-vuln-repair-0.3.0.zip.sha256` 为准。

本节只证明源码逻辑与定向测试。该 baseline 复用/重试修复尚未部署到 WSL 固定安装路径，尚未通过新的真实 CVE-2024-57595 run 验证，未执行全量回归，也未调用模型。

## wrapper 参数保存与 semantic rejection 合同修复

2026-10-22 分析真实 run `20261022-183103-44c71de6` 后修复两个问题：

- 第 1、2 轮 wrapper 候选都在合法 PIN 请求上出现 `valid_pin_control: incomplete_response`。第 2 轮判定函数对合法 PIN 明确返回 0，本应原样调用原函数；根因是 controller 生成的 trampoline 调用 `repair_entry` 后未恢复 MIPS o32 参数寄存器。`repair_entry` 可以破坏 `$a0-$a3`，随后尾跳原函数时原 callee 收到损坏参数。
- trampoline 现在在调用判定函数前保存 `$ra/$gp/$a0-$a3`，调用后恢复全部参数，再根据返回值尾跳原 callee 或阻断。
- 第 3 轮模型返回了 `edits=[] + rejection_reason + retry_scope` 的正确 semantic rejection 形式，但顶层合同校验先按普通 edits 提案拒绝这两个字段。现在空 edits 会先进入既有 semantic rejection 校验；非空 edits 携带 semantic rejection 字段仍被拒绝。
- 保留候选启动安全规则，不改变 relocalize 的 fresh site 要求。

定向验证：

- Ubuntu-24.04 / WSL 既有测试虚拟环境：
  `pytest tests/test_firmware_implant.py -k "wrapper_preserves_original_arguments_across_helper_call or wrapper_implant_preserves_original_call or semantic_rejection_top_level_contract"` — **3 passed**。
- 新增用例中的判定函数显式清空 `$a0/$a1`，若 trampoline 不恢复参数则两个原调用都会跳过副作用；修复后 QEMU 仍保留原调用副作用。
- Ubuntu-24.04 / WSL：
  `pytest tests/test_firmware_loop.py -k "semantic_rejection_relocalizes_without_deploying_candidate or repeated_semantic_rejection_does_not_observe_missing_candidate"` — **2 passed**。
- 未执行全量回归，未部署新版，未再次调用真实模型。

## 测试生成 canonical 触发场景归一化

2026-10-22 分析真实 run `20261022-185908-d1654e62` 后修复测试生成阶段的重复失败：

- 该 run 的 PoC 复现、baseline fixed checks 和 localization 均已完成；失败发生在 `generate-tests`，最终 `contract_information_required`。
- 4 次模型输出中，第 1 次为 JSON 语法错误；第 2 次漏洞场景已完全匹配但部分测试携带无语义空占位；第 3 次把需要认证/timeout 前缀的页面压缩成独立请求；第 4 次漏洞测试遗漏 host/form/step expect 等默认字段，触发“必须逐字复放确认场景”校验。
- `tests_prompt()` 继续提供 controller-owned `confirmed_trigger_scenarios`，并明确要求复制该对象而不是重新默写。
- validator 现在丢弃空 `request:{}` 或空 `steps:[]` 占位；两个非空表示仍会被拒绝。
- 接受 `form_encoding` 作为 `content_type` 的无歧义别名，随后仍进入封闭字段和值校验。
- 当 marker 漏洞测试的 marker、最终 method/path/form 与确认触发场景完全一致时，控制器用自己保存的 canonical 多步场景替换模型重述的前缀。模型修改 payload、path 或 marker 时不会归一化，仍按 near-miss 拒绝。
- 需要认证或 `accept_timeout=true` 的路径仍禁止压缩成独立 request，安全规则未放宽。

定向验证：

- Ubuntu-24.04 / WSL 既有测试虚拟环境：
  `pytest tests/test_firmware_loop.py -k marker_tests_must_preserve_confirmed_trigger_scenario` — **1 passed**。
- 用该真实 run 的 4 次原始模型输出回放新 validator：
  - 第 1 次：仍因 JSON 语法错误拒绝；
  - 第 2 次：通过，生成 4 个测试；
  - 第 3 次：仍因压缩确认多步路径拒绝；
  - 第 4 次：通过，生成 4 个测试。
- 未执行全量回归，未部署新版，未再次调用真实模型。

## candidate 传输重试与 marker 错位 site 修正

2026-10-22 继续分析真实 run `20261022-193857-68a86758` 和无模型对照诊断：

- 无模型 QEMU 诊断确认 `/Q` marker 确实来自 shell `open("/Q", O_WRONLY|O_CREAT|O_TRUNC)`；诊断脚本最初漏传 candidate marker，后续修正后重新判定。
- 在模型曾选择的 `0x00413540` 部署“包含 `/Q` 即阻断”的 wrapper，合法 PIN 可通过但 marker 仍会创建；该 site 未拦截确认触发流。
- 在 handler `0x00412f0c` 内的 `0x004131ec` 部署同一 wrapper，合法 PIN 通过且 candidate 阶段 marker 不再创建。该结果证明 wrapper/trampoline、参数恢复和原调用保留机制可用，失败主因是 localization 选错 command sink。

依据上述证据调整控制策略：

- marker replay 中仅当候选 SHA 身份稳定、失败仅为 `incomplete_response` 且没有任何进程退出时，允许一次审计记录的同 SHA candidate restart 后重放。该规则只作用于 candidate 已完成 fixed checks 后的 replay，不改变候选 pre-ready 崩溃不可重试的安全边界。
- marker 仍创建、响应语义失败或进程退出均不允许 transport retry，保留为决定性候选失败。
- `marker_still_created` 不再触发 wrapper 同 site predicate 修正，直接 relocalize；该类反馈明确提示旧 wrapper site 未拦截确认 marker，应重新对已恢复 handler 做窄过滤 `function_calls` 并选择另一个 command sink。
- 反馈记录失败 wrapper site 和 mode，避免模型重复注册同一错误位点；仍要求 fresh `register_patch_site`，不向模型提供控制器硬编码答案。

定向验证在 Ubuntu-24.04 / WSL 项目测试虚拟环境执行：

- `pytest tests/test_firmware_verification_safety.py tests/test_firmware_loop.py::test_wrapper_same_site_refinement_is_single_and_leaf_compatible tests/test_firmware_loop.py::test_candidate_failure_triage_separates_new_fault_from_unfixed -q --basetemp=/home/lumu/tmp/pytest-marker-retry-focused` — **19 passed**。
- `py_compile repair_tool/firmware/verify.py repair_tool/firmware/loop.py tests/test_firmware_verification_safety.py tests/test_firmware_loop.py` — 通过。
- `git diff --check`（限定上述修改文件） — 通过。
- 重新执行 `python scripts/package.py` 与 `python scripts/package.py --check` — 生成并校验 **127 个文件** 的 0.3.0 包；最终 checksum 以 `dist/project-vuln-repair-0.3.0.zip.sha256` 为准。

本节的无模型诊断只证明 `0x004131ec` 对当前 CVE-2024-57595 触发流有效，不把它写入通用核心或跳过模型 fresh localization。尚未用新版执行真实 `repair run`，未执行全量回归，未调用模型。

## marker 数据表 handler 覆盖门禁

2026-10-22 分析真实 run `20261022-205754-c24ef788` 后补充控制器级约束：

- 该 run 的 PoC 复现、baseline fixed checks、16 次静态查询和 9 次模型调用均完成；失败主因是模型在 `data_table_context` 同时恢复 `0x0041322c` 与 `0x00412f0c` 两个 executable handler 后，只检查前者并把剩余预算用于错误 handler 的 sink 反汇编，最终诚实报告证据不足。
- 新增通用 marker handler coverage 状态：仅当确认故障为 `command_injection_marker`，且模型已经通过确认请求 path/form 字符串的 `ascii_search -> data_reference -> data_table_context` 链恢复出相邻 executable pointer 时才启用。
- 对每个确认字符串的 bounded window 只取最近的左右 executable handler，最多 8 个；地址全部来自模型已经收到的查询答案，不写入 DIR-825 profile 地址，也不把这些 handler 宣称为补丁点。
- 未覆盖 handler 前，控制器拒绝无关 `disassemble`、`register_patch_site` 和 “证据不足”结论；拒绝被写入 query trace，且不消耗主定位查询预算。反馈明确列出未覆盖 handler 的来源和必查 `function_calls` 地址。
- `function_calls` 覆盖规则为：带 `contains` 的过滤查询必须返回至少一个 call；过滤空结果不算覆盖。未过滤查询即使为空也可作为该 handler 无调用的中性证明。
- 覆盖完成后，模型仍必须自己筛选 sink、反汇编精确 site、执行 fresh `register_patch_site` 并输出结论；控制器不指定 site 或补丁模式。

定向验证在 Ubuntu-24.04 / WSL 的项目测试虚拟环境执行，pytest 临时目录位于 Ubuntu 原生 `/home/lumu/tmp`：

- 新增 helper 与集成测试：
  `python -m pytest tests/test_firmware_loop.py -q -k "marker_handler_coverage or localization_marker_gate"` — **2 passed**。
- 现有 marker/localize 相关回归子集：
  `python -m pytest tests/test_firmware_loop.py -q -k "marker or localize"` — **19 passed, 80 deselected**。
- `python -m py_compile repair_tool/firmware/loop.py tests/test_firmware_loop.py` — 通过。
- `git diff --check -- repair_tool/firmware/loop.py tests/test_firmware_loop.py VALIDATION.md` — 通过。
- 重新执行 `python scripts/package.py` 与 `python scripts/package.py --check` — 生成并校验 **127 个文件**的 0.3.0 包；最终 checksum 以 `dist/project-vuln-repair-0.3.0.zip.sha256` 为准。

本节只证明源码逻辑和定向测试。该覆盖门禁尚未部署到 WSL 固定安装路径，尚未用新的真实 CVE-2024-57595 run 验证，未执行全量回归，也未调用模型。

## marker 候选验证窗口与 relocalize 证据合并修复

2026-10-22 继续分析真实 run `20261022-215428-bddc458c`：

- 两轮 wrapper 候选都完成编译、植入、部署和身份校验，目标无崩溃、candidate SHA 稳定，但 `valid_pin_control` 在 5 秒 exploratory 窗口内被误判为 `incomplete_response`。baseline 复现与独立诊断均显示同一合法 PIN 请求需要接近案例的 15 秒请求预算；候选行为验证现在直接使用 `firmware.poc_request_timeout`，不再用较短的 exploratory 值做最终功能判定。旧配置键仅保留兼容，报告中同时记录 `observation_seconds` 和旧字段。
- 同一 handler 的 `function_calls` 宽泛分页与后续 `contains=system` 过滤结果现在合并保留，不再让过滤结果覆盖先前已经看到的 exact call site。该 run 中 `e26` 曾暴露 `0x00413338`，随后 `e32` 的过滤结果把它从 eligibility 状态中抹掉，导致重复注册。
- 已 deferred 的 nomination 会记录原 site entry 和缺失证据；同一 site 在缺失证据未补齐前重复提交会被拒绝且不消耗主查询预算。补齐只读证据后允许重新注册。
- 对 `command_injection_marker`，已知非 command-execution callee（如 `nvram_safe_get`）不能仅凭 request-handler exact-call 链注册为修复点；无 callee 身份时先 deferred。该约束基于漏洞类别通用生效，不写入 DIR-825 地址。

定向验证在 Ubuntu-24.04 / WSL 的项目测试虚拟环境执行，pytest 临时目录位于 Ubuntu 原生 `/home/lumu/tmp`：

- 核心新增/受影响用例：
  `pytest tests/test_firmware_loop.py -q -k "candidate_iteration_uses_full_request_observation_window or marker_call_evidence_merges_broad_and_filtered_pages or command_marker_requires_command_execution_sink or duplicate_deferred_nomination_does_not_burn_query_budget or localization_marker_gate_rejects_bypass_without_charging_budget"` — **5 passed, 97 deselected**。
- marker 子集复验：
  `pytest tests/test_firmware_loop.py -q -k "marker"` — **7 passed, 95 deselected**。
- `python -m py_compile repair_tool/firmware/loop.py tests/test_firmware_loop.py` — 通过。
- `git diff --check -- repair_tool/firmware/loop.py tests/test_firmware_loop.py` — 通过。

本节尚未重新打包、尚未部署 WSL 固定安装路径、尚未执行全量回归、尚未调用真实模型，也不能把上一轮真实 run 解释为新逻辑的成功证据。

## runtime sink differential probe

2026-10-23 针对 CVE-2024-57595 多个静态 `system/_system` 调用点实现受控差分探测：

- 仅当确认故障为 `command_injection_marker` 时启用。首轮 localize 在 marker handler 覆盖完成且模型已看到至少两个 redirectable command sink 后动态执行一次；relocalize 阶段仍可在候选失败后使用剩余候选继续探测。
- 候选只来自 evidence ledger 中模型已经收到的 baseline `function_calls` 答案，必须是 redirectable command-execution 调用；真实候选反馈中已失败的 wrapper site 会被排除。控制器不写入 DIR-825 地址，也不把探测结果变成补丁答案。
- 每个探测使用控制器固定生成的 wrapper：发现 shell 元字符返回非零阻断原调用，否则返回 0 保留原调用。模型不能提供该诊断 wrapper 的判定代码。
- 探测在私有 session 副本上部署，只重放 reproduction 已确认的 marker 触发步骤，观察 marker 是否消失、目标身份是否稳定和失败步骤状态；随后必须回滚 baseline。回滚失败记录为 `infrastructure_failed`，不允许被后续步骤掩盖。
- 探测结果写入 `runtime_sink_probe` evidence 与 `runtime-sink-probes/` 工件，并提供给后续重定位 prompt；结果标记为 diagnostic-only，不能替代新鲜 `register_patch_site`。
- 默认 `firmware_runtime_sink_probe_limit=3`，找到 marker 被阻断的 site 后停止后续探测。
- 修复部署 RPC 哈希读取：probe 现在校验 `replace_target()` 返回的 `target.sha256`，而不是顶层不存在的 `sha256` 字段；部署后成功回滚记录为 `baseline_restored`。

2026-10-23 依据真实 run `20261023-002636-64322675` 继续收口四个控制流问题：

- marker handler coverage 在 reproduction 缺少 confirmed request 明细时，会使用 `fault.request` 中已被 marker 复现确认的同一个请求作为兜底；地址仍只能来自模型已收到的静态查询答案，不引入设备地址。
- nomination 被 deferred 后进入 `registration_recovery_required`：下一轮允许精确 site 反汇编或对应 handler 的 `function_calls`，拒绝无关宽泛查询和重复注册；重复注册保留 `already deferred`、缺失证据和 `budget_charged=false` 语义，不消耗主查询预算。对没有函数元数据的 stripped ELF，可从已返回的 `function_calls` 页面恢复暴露该 site 的查询地址。
- 最终 localization 写入前重新执行语义门禁；cited `model_code_site` 若仍是 deferred/rejected，会被持久化为对应 nomination 状态并拒绝写入成功定位，防止绕过 registration gate。
- marker 查询策略明确优先 `function_calls(handler, contains="system")`，过滤为空才扩展 `_system/popen/exec` 或宽泛分页；同参数重复查询会继续消耗预算，必须在 `next_offset` 或过滤条件上推进。
- 首轮 localize 的 runtime sink probe 改为动态触发：本轮 `function_calls` 答案写入 ledger 后重新计算候选，在 handler coverage 已闭合、确认 marker、模型可见 command sink 至少两个时执行一次受控探测，并把 diagnostic-only 结果放入下一轮 prompt。

定向验证在 Ubuntu-24.04 / WSL 既有项目测试虚拟环境执行，pytest 临时目录位于 Ubuntu 原生 `/home/lumu/tmp`：

- `pytest tests/test_firmware_loop.py tests/test_firmware_verification_safety.py -q -k "marker_handler_coverage or registration_recovery or runtime_sink_probe or runtime_probe_candidates or marker or candidate_iteration_uses_full_request_observation_window or marker_call_evidence_merges_broad_and_filtered_pages or command_marker_requires_command_execution_sink or duplicate_deferred_nomination" --basetemp=/home/lumu/tmp/pytest-four-fixes-final` — **21 passed, 105 deselected**。
- `python -m py_compile repair_tool/config.py repair_tool/firmware/loop.py tests/test_firmware_loop.py` — 通过。
- `git diff --check -- repair_tool/config.py repair_tool/firmware/loop.py tests/test_firmware_loop.py docs/ARCHITECTURE.md VALIDATION.md` — 通过。
- 重新执行 `python scripts/package.py` 与 `python scripts/package.py --check` — 生成并校验 **127 个文件**的 0.3.0 包；交付时以同目录 `project-vuln-repair-0.3.0.zip.sha256` 的实际值为准。

本节只证明源码逻辑和定向测试。runtime sink probe 尚未部署到 WSL 固定安装路径，尚未通过新的真实 CVE-2024-57595 run 验证，未执行全量回归，也未调用模型。

## runtime sink probe 完整场景重放修复

2026-10-23 分析真实 run `20261023-012839-580c22a7` 后修复诊断探针自身的误导性结果：

- PoC 复现计划包含 `home -> login -> authenticated_page -> valid_pin_control -> marker_trigger -> post_trigger_control` 六步；`reproduction.confirmed_ids` 只记录最终确认步骤 `marker_trigger`。旧实现错误地用该集合筛选计划，导致 runtime probe 只发送最终恶意 PIN POST，没有先捕获 `graph_id`、登录和进入认证页面。
- 三个静态 command sink 的 probe 均在 `marker_trigger` 得到 `incomplete_response`，却被记录为 `marker_blocked=false`、`marker_present=false`。模型据此把历史验证有效的 `0x004131ec` 也理解为“未拦截”，最终在 16/16 查询耗尽后诚实拒绝定位。
- probe 场景现在从已验证计划第一步切片到最后一个确认的 `marker_created` 步骤，保留 capture fields、cookies 和认证前缀；确认步骤之后的控制请求不参与诊断触发。
- `incomplete_response`、HTTP/内容/cookie/capture 字段失败现在归类为 `transport_or_session_failure`，结论为 `inconclusive`，`marker_blocked` 与 `marker_present` 均为 `null`，不再冒充“未阻断”或“marker 不存在”。
- marker 仍被创建时明确记录 `marker_present=true`、`marker_blocked=false`；场景完整且 marker 不存在才记录 `marker_blocked=true`。目标崩溃等其他候选失败仍为 `inconclusive`。
- 同一探测阶段出现 `transport_or_session_failure` 时立即停止后续 sink，写入 warning，避免把同一个无效场景重复烧完 3 个候选。
- 复查同类错误后进一步收口：传给模型的 runtime probe 投影保留 `failure_kind` 和 `failed_steps`；此前差分探针已证明 `marker_present=true` 的 site 不再进入后续候选；candidate replay 的受控传输重试若仍失败，分类使用第一次可重试失败的位置，避免第二次执行推进到更晚步骤后把诊断从 pre-trigger 误标为 trigger。

定向验证在 Ubuntu-24.04 / WSL 既有项目测试虚拟环境执行，pytest 临时目录位于 Ubuntu 原生 `/home/lumu/tmp`：

- `pytest tests/test_firmware_loop.py -q -k runtime_sink_probe --basetemp=/home/lumu/tmp/pytest-runtime-probe2` — **7 passed, 105 deselected**。
- 同类错误复查子集：
  `pytest tests/test_firmware_loop.py -q -k "runtime_sink_probe or runtime_probe_candidates" --basetemp=/home/lumu/tmp/pytest-similar-errors-a3` — **9 passed, 104 deselected**。
  `pytest tests/test_firmware_verification_safety.py -q -k "transport_retry or transport_failure or marker_still_created" --basetemp=/home/lumu/tmp/pytest-similar-errors-b3` — **4 passed, 14 deselected**。
- `python -m py_compile repair_tool/firmware/loop.py tests/test_firmware_loop.py` — 通过。
- `git diff --check -- repair_tool/firmware/loop.py tests/test_firmware_loop.py docs/ARCHITECTURE.md VALIDATION.md` — 通过。

本节修复后的包尚未部署到 WSL 固定安装路径，尚未再次调用真实 GLM-5.3，也未执行全量回归。旧 run 中“`0x004131ec` 可拦截当前 marker”的结论只保留为此前无模型诊断证据，不能当作新版真实修复成功。

## offline verify 多步 fixed-check 协议兼容

2026-10-23 真实 run `20261023-015556-7ca0e8ea` 已得到 `validated_candidate` 后，独立 `repair verify` 首次在离线校验处失败：

- run 内部证据完整：final rollback/redeploy、fixed checks、marker replay 和 4 个生成测试均通过；失败不是候选证据被篡改。
- `verify_firmware_run()` 校验存储 fixed checks 时未传入 run config 中的 `http-ascii-auth-form-multi-step-port80`，导致 `_validate_checks()` 回退到默认 `http-ascii-get-head-port80`，随后拒绝同一协议的合法多步 check。
- 现在离线 verify 会按 `firmware.protocol`（缺省才是旧 GET/HEAD 协议）校验 stored checks。

定向验证：

- Ubuntu-24.04 / WSL：
  `pytest tests/test_firmware_loop.py -q -k "verify_firmware_run or record_baseline_bytes" --basetemp=/home/lumu/tmp/pytest-verify-protocol` — **2 passed, 112 deselected**。
- `python -m py_compile repair_tool/firmware/loop.py tests/test_firmware_loop.py` — 通过。

## CVE-2024-57595 真实闭环与团队案例归档

2026-10-23 真实 run `20261023-015556-7ca0e8ea` 在 0.3.0 固定安装中完成闭环：

- PoC 复现：六步首页字段捕获、登录、认证页确认、合法 PIN、8 字节注入 PIN 和触发后控制全部通过；baseline 中 `wps_pin=';>/Q ;#` 创建 `/Q`。
- 模型定位：GLM-5.3 通过受限 ELF 查询定位 `0x004131ec` 的 `_system` 调用，并完成本会话 fresh `register_patch_site`。
- runtime sink differential probe：完整重放认证前缀和 marker 触发步骤，证明阻断该调用后 marker 消失、目标身份稳定，并成功回滚 baseline；该证据保持 diagnostic-only。
- 修复：模型提交 `mode=wrapper`，模型函数仅判定 shell 元字符；控制器生成 trampoline，合法命令重调原 `_system`，恶意命令直接返回，不再破坏合法 PIN 保存。
- 最终验证：固定检查 1/1，marker replay 稳定，生成测试 4/4，状态 `validated_candidate`。
- 独立 verify：修复 offline fixed-check 协议兼容问题后，对同一 run 复核为 `verified_with_cleanup_warnings`。回滚 baseline、基线漏洞复现、候选重部署、fixed checks、marker replay 和 4 个测试均通过；两个 warning 均为非 root 进程无法删除 root 持有的临时 `host-rootfs` 目录。

团队归档目录为 `cases/dlink/dir825b-2.03/cve-2024-57595/`，已保留声明式 PoC、输入模板、模型 proposal、`repair.c`、`repair.o`、实际 patched candidate、patch record、run 报告、生成测试、定位与差分探测结果、独立验证证据和团队摘要。已校验 candidate SHA256 为 `9045157760a96ef8b8a046b3f1d90356960e5ec05b86fda62fc445276c5798bf`，源码与对象 SHA256 分别为 `f95f9a690791818580ac55feed80f2bc2c6f325e57149622045a74cefc2976aa`、`094d18d81fc030d918ebb89b23f5e43f61a540ae739fd598e56b0d4b1d5543e6`。

归档整理已完成个人路径、挂载路径和 API key 扫描，未发现泄漏；未保存原始固件、rootfs、完整模型响应或完整 `repair-results/`。本次归档未调用模型，未执行全量回归；只保留上述真实 run 与独立 verify 证据。

## 0.3.1 专业项目文档重构

2026-10-25 参考 uv、pytest 与 Binwalk 等开源项目的文档分工，重构 0.3.1 文档但不改变程序行为：

- 新增 `docs/README.md` 文档地图、推荐阅读顺序和写作规则；
- 新增 `docs/CONTRIBUTING.md`，覆盖开发环境、定向测试策略、代码分层、提交前检查、PR 描述和案例/文档贡献；
- 新增 `docs/SECURITY.md`，覆盖安全报告流程、信任边界、运行时隔离、FirmAE wrapper、模型数据外发和关键不变量；
- 重写顶层 README：保留入口定位、当前能力、系统要求、Ubuntu 快速开始、最小工作流、命令参考、文档索引、仓库布局和验证状态；
- 重写 `docs/OPERATIONS.md`：按安装、配置、路线 A、wrapper、结果解释、更新、打包、隐私和故障处理组织；
- 修正 `docs/ARCHITECTURE.md` 末尾旧结论，明确当前真实闭环为同一 DIR-825 样本上的 CVE-2025-6291 与 CVE-2024-57595。

定向验证：

- Windows 本机：`PYTHONPATH=.test-python;.linux-python` 下执行 `python -m pytest tests/test_packaging.py tests/test_package_contents.py tests/test_config_validation.py -q --basetemp=tmp/pytest-docs-rewrite` — **16 passed, 1 skipped**；跳过原因是 Windows 缺少 POSIX `fcntl`，与既有测试说明一致。
- `python -m py_compile scripts/package.py` — 通过。
- `python scripts/package.py` 与 `python scripts/package.py --check` — 生成并校验 **141 个文件**的 0.3.1 包；发布包 SHA256 以 `dist/project-vuln-repair-0.3.1.zip.sha256` 的当前值为准。
- 对 README/docs/cases 的 Markdown 文本扫描个人路径、挂载路径和用户名，未发现泄漏；`REPAIR_API_KEY` 仅作为环境变量示例出现。

本节仅为文档与发布包检查。未修改程序代码，未部署 WSL，未执行部署后全量回归，未调用模型，也未产生新的固件修复结论。

## 0.3.1 产品定位收敛补充

2026-10-25 按项目决策将当前产品定位收敛为 **IoT 固件大模型自动漏洞修复系统**：

- README、架构说明、操作手册、贡献指南、安全策略和变更记录不再把历史源码项目修复路线作为当前能力或使用方式介绍；
- 顶层流程、系统要求、配置示例和代码组织说明改为固件路线优先；
- 0.0.x–0.1.x 仅作为控制器早期执行、测试、模型契约、报告和打包机制的历史阶段保留，不再作为当前产品卖点；
- `repair_tool/workflow.py` 及相关历史实现未删除，代码仍保留在仓库中，只是不再作为当前团队文档的推荐工作流。
- `tests/test_packaging.py` 的文档示例测试同步改为校验固件案例配置，不再强制操作手册包含源码项目 YAML。

定向验证：

- Windows 本机：`PYTHONPATH=.test-python;.linux-python` 下执行 `python -m py_compile tests/test_packaging.py` — 通过。
- `python -m pytest tests/test_packaging.py tests/test_package_contents.py tests/test_config_validation.py -q --basetemp=tmp/pytest-firmware-docs-2` — **15 passed, 1 skipped**；跳过原因仍为 Windows 缺少 POSIX `fcntl`。
- 对 README、docs、cases、本验证账本的当前产品说明和 AGENTS 执行历史源码模式关键词扫描；除本节记录本次收敛决策外，当前使用文档无匹配。

本节只改变文档与发布一致性测试，不删除历史实现，未部署 WSL，未执行全量回归，未调用模型。

## 0.3.0 未验证项

- 未执行 Greenhouse，也未验证其兼容性。
- 未验证额外固件架构、协议或 runtime 后端。
- 未验证真实 DIR-825 硬件。

后续部署必须遵循 `AGENTS.md`：安装或更新固定 Ubuntu 路径，保留用户资料，对该部署版本只执行一次全量回归，并把结果记录到本页或新的对应发布记录。
