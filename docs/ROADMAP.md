# 固件修复通用化路线图

## 最终目标

Project Vuln Repair 的长期目标是做一个面向绝大多数 IoT 固件的大模型自动漏洞修复系统：用户提供固件包、可复现 PoC 和必要的验收信息后，系统能自动完成固件识别、文件系统提取、架构识别、隔离重托管、漏洞复现、证据查询、补丁生成、候选部署、回归验证和报告输出，尽量减少手工提取 rootfs、手工适配启动脚本和手工分析架构的工作。

这是一个工程目标，不是当前已经完成的能力。每扩展一类固件，都必须补齐运行时、架构、协议、诊断、doctor、植入、回滚和真实端到端证据，不能只因为 CPU 架构或文件名相似就宣称支持。

## 当前真实能力边界

### 已经有真实闭环证据的范围

当前已有两个完成真实端到端修复验证的案例，均来自同一固件与目标：

- 设备/固件：D-Link DIR-825 B 2.03；
- CVE：CVE-2025-6291 与 CVE-2024-57595；
- CPU/ABI：MIPS32 big-endian，o32；
- 目标服务：`sbin/httpd`；
- 访问协议：80 端口受限 ASCII HTTP；CVE-2025-6291 为 GET/HEAD 崩溃路线，CVE-2024-57595 为表单 POST + 多步认证 marker 路线；
- 漏洞类型：CVE-2025-6291 为栈溢出类致命内存破坏，CVE-2024-57595 为 OS 命令注入；
- 修复路线：FirmAE diagnostic-only analysis / intake，再由 `native-proot-mips32be` 权威重托管和验收；
- 模型：智谱 GLM-5.3 的 OpenAI 兼容接口；
- 结果：真实 run 曾达到 `validated_candidate`，独立 verify 曾达到 `verified_with_cleanup_warnings`。

完整证据矩阵和解释边界见 [SUPPORTED_FIRMWARE.md](SUPPORTED_FIRMWARE.md)。

这证明的是路线 A 在 DIR-825 上可运行，不证明任意固件、任意 MIPS 固件或任意栈溢出漏洞已经可修复。

CVE-2024-57595 案例已完成六步表单 PoC、真实模型定位、wrapper 修复、4/4 最终测试和独立 verify；清理警告仅涉及 root 持有的临时目录删除权限。详见 [../cases/dlink/dir825b-2.03/cve-2024-57595/README.md](../cases/dlink/dir825b-2.03/cve-2024-57595/README.md)。

### 已实现但仍需真实验证的扩展基础

- 封闭式 runtime / architecture / protocol capability registry；
- FirmAE compatibility/analysis 的受控 root wrapper、诊断导入和报告绑定；
- Greenhouse diagnostic-only adapter 契约和安全边界；Greenhouse 真实 CLI 兼容性尚未验证；
- `repair doctor` 的 runtime、架构、协议三层能力判断；
- 通用 session 进程/隧道逻辑、runtime 装载逻辑与 DIR-825 profile 分层；
- `repair boot-plan` 的只读常见目标、init 线索和 ELF 架构候选推断；
- 受限 HTTP 表单 POST、Cookie 捕获/重放、声明式多步请求和空文件 marker 验收；
- 诊断账本、只读查询和不可信证据标记；
- schema 化 intake、rootfs 物化和目标身份绑定。

这些是通用化基础设施，不等于新固件已经可用。

### 当前明确不支持或未验证

- 未验证 MIPS32 little-endian、ARM32、AArch64、x86 或其他架构；
- 未验证 DIR-825 之外的品牌、机型和目标服务；
- 已注册的受限 POST/auth/多步协议仅在 CVE-2024-57595 的声明式表单、认证和 marker 场景完成真实闭环；HTTPS、非 80 端口、multipart、任意 header/body 和私有协议仍未支持；
- 未验证堆溢出、UAF、格式化字符串、整数溢出等其他漏洞类型的完整修复闭环；
- 未验证 Greenhouse 真实执行；
- 未验证控制器自建 QEMU runtime 的通用启动能力；
- 未验证真实硬件；
- 不承诺对所有固件都能成功提取、启动或修复。

## 技术路线

### 路线 A：FirmAE 诊断与 intake，本机权威 runtime 验收（当前路线）

FirmAE 只做 compatibility/analysis，导出转换后的映像和元数据；控制器校验产物、物化 rootfs、生成 case，然后使用自己的 `native-proot-mips32be` 运行时完成复现、定位、补丁、回滚和验收。

优点是安全边界清楚，当前 DIR-825 已有真实证据。限制是权威 runtime 和架构后端仍只有 MIPS32BE，FirmAE 的提取结果也必须通过控制器自己的身份与安全校验。

### 路线 B：Greenhouse diagnostic-only 适配（准备中）

Greenhouse 作为第二类外部诊断源，只提供 compatibility/rehost/replay/fuzz 观察结果。它不能直接授予 `validated_candidate`，所有输出仍要绑定固件 SHA、目标身份和报告 schema，并进入不可信诊断账本。

启用条件是真实 CLI 兼容性验证、真实固件样本测试、输出契约稳定，以及与 FirmAE 诊断结果的对照审查。

### 路线 C：控制器自建受控 QEMU runtime（长期路线）

为减少对 FirmAE 提取和启动行为的绑定，控制器最终需要能为更多架构生成受控 QEMU/PRoot 启动环境：自动选择机器类型、内核、网络转发、init/target 启动、admin RPC、目标退出归因和事务回滚。

这条路线难度最高，但它是“绝大多数固件通用”的关键组成部分。它不能绕过能力注册表和 doctor；每个 runtime 都必须先证明隔离性、可观测性和确定性，再参与权威验收。

## 分阶段计划

| 阶段 | 目标 | 关键交付 | 明确不做的事 |
|---|---|---|---|
| P0：DIR-825 基线 | 保持 GET/HEAD 崩溃与表单多步 marker 两条真实闭环稳定 | 0.3.0 文档/目录基线、路线 A 向导、证据边界 | 不把 DIR-825 经验夸大为通用支持 |
| P1：输入与诊断泛化 | 让“固件包 + PoC”成为常规输入 | 固件格式识别、品牌/架构线索归一化、BootPlan 候选、FirmAE 报告兼容层、失败原因分类、诊断对照 | 不授权未验证 runtime 修复 |
| P2：架构族扩展 | 从单一 MIPS32BE 扩展到常见 IoT 架构 | MIPS32LE、ARM32、AArch64 后端，ELF/ABI/调用序列/重定向/编译契约和测试 | 不支持没有交叉编译与回滚证明的架构 |
| P3：runtime 泛化 | 降低单固件手工适配 | 参数化 native runtime、数据化 profile、控制器自建 QEMU 路线、启动资产生成、网络/存储隔离模板 | 不为了启动成功放弃身份绑定和事务回滚 |
| P4：协议与服务泛化 | 覆盖常见管理面和服务面协议 | HTTP headers/body/POST/auth、HTTPS、UPnP、私有 TCP/UDP 协议驱动与录制回放 | 不允许模型自由生成任意网络脚本 |
| P5：漏洞类型扩展 | 从栈溢出扩展到更多缺陷 | 堆破坏、UAF、格式化字符串、整数溢出、注入类语义验收和证据查询 | 不把仅能复现崩溃等同于漏洞语义证明 |
| P6：批量评测 | 度量通用化成功率 | 固件语料、成功/失败分层统计、成本模型、失败库、回归基准 | 不只挑选成功样本宣传 |

## 每类新固件的完成标准

一类固件只有同时满足以下条件，才能从“实验样本”升级为“已支持”：

1. 原始固件、提取产物、rootfs、目标 ELF 和 PoC 有稳定 SHA/身份绑定；
2. 至少一个注册 runtime 能隔离启动目标并记录目标退出；
3. 注册架构后端能解析 ELF、分析调用点、编码重定向并交叉编译植入体；
4. 注册协议驱动能确定性编码请求并解析完整响应；
5. doctor 能明确报告 ready 或 unsupported 的原因；
6. PoC 能复现可归因故障，固定功能检查通过；
7. 模型定位必须产生本会话新鲜 `register_patch_site` 证据；
8. 候选部署、回滚、重部署和生成测试全部通过；
9. `repair verify` 不调用模型也能复验；
10. 至少一次真实端到端 run 达到 `validated_candidate`，并记录失败样本和成本。

## 优先扩展顺序

1. **MIPS32LE 常见路由器固件：** 与当前 MIPS32BE 最接近，能先验证架构注册表和 ABI 差异处理；
2. **ARM32 常见 IoT 固件：** 扩大设备覆盖面，检验调用约定、重定向和 runtime 模板泛化；
3. **AArch64 新一代设备：** 验证 64 位 ABI、地址空间和编译契约；
4. **HTTP POST/auth/多步管理面：** 巩固 DIR-825 B 2.03 / CVE-2024-57595 已完成的受限表单 POST、认证会话、多步请求、命令注入 marker 验收和 wrapper 修复闭环，再扩展到更多设备；
5. **UPnP/私有 TCP 协议：** 再进入非纯 HTTP 服务；
6. **堆破坏/UAF 等内存漏洞：** 在定位证据和语义验收更强后扩展；
7. **Greenhouse 与路线 C runtime：** 与架构扩展并行推进，但不得提前授予权威。

## 成功指标

- 输入侧：用户不再手工提取 rootfs 的固件比例；
- 启动侧：doctor 能给出明确原因的自动启动成功率；
- 复现侧：PoC 可归因复现率和误归因率；
- 定位侧：新鲜位点注册率、平均模型查询数和重定位率；
- 修复侧：`validated_candidate` 比例、回滚成功率、引入新故障率；
- 成本侧：每样本模型调用次数、token 用量、CPU 时间和人工干预次数；
- 安全侧：原始固件 SHA 漂移次数、越界提取拒绝率、私有路径泄漏次数。

所有指标必须同时报告失败样本和成功样本，不能只用成功案例代表整体能力。
