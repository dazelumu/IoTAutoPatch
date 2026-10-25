# Project Vuln Repair 架构说明 0.3.1

## 定位

这个系统是控制器，不是模型外层的简单 shell。控制器拥有证据、执行、验证、回滚和最终状态；模型负责调查或提案。模型输出是否可执行、候选是否被接受，均由控制器判定。

## 顶层流程

### 固件路线 A

1. 校验 intake 模板、原始固件、品牌、目标、固定检查和 PoC。
2. 通过受控 wrapper 以 diagnostic-only `compatibility` 或 `analysis` 模式运行 FirmAE。
3. 把导出产物绑定到固件 SHA，并校验报告。
4. 从导出映像物化有界、不执行脚本的 rootfs。
5. 生成 `case.generated.yaml`。
6. 对 generated case 运行 doctor。
7. 在权威原生重托管运行时中执行 `repair run`。
8. inspect，并按需独立 verify。

FirmAE 不执行固件 `run` 模式，也不是权威修复运行时。

## 固件证据模型

固件流程绑定以下身份：

- 固件和目标 ELF SHA256；
- 活动目标 PID、进程启动身份、命令行和程序 SHA；
- 请求字节和请求 SHA；
- 响应完整性与固定检查；
- 非自愿致命退出记录，或显式声明的空文件 marker 副作用；
- 模型新鲜注册的补丁位点；
- 基线/候选/回滚 SHA 转换；
- 生成测试进度和结果；
- supervisor 事件与清理诊断。

只有退出是非自愿、致命且绑定到当前目标身份时，才能作为故障证据。服务管理类 SIGTERM/SIGKILL 不是候选证据。

## 路线 A 物化

`repair_tool.firmware.intake` 接受成功的 FirmAE analysis run，在不挂载映像、不执行映像脚本的前提下物化导出结果。物化器应用条目数、总字节数和符号链接数量限制，拒绝不安全文件类型，并记录转换映像中绝对链接的归一化结果。

生成的 case 独立于原始固件文件，指向物化 rootfs、已校验目标、PoC、固定检查、诊断导入和输出目录。

## 设备接入分层

固件运行时不再把 DIR-825 逻辑放在核心路径中。当前分层是：

| 层 | 职责 | 当前内容 |
|---|---|---|
| `firmware/session/` | 通用 Linux 进程身份、PID 复用防护、listener owner、清理、rootfs 复制和会话私有 HTTP Unix socket 隧道 | 与设备无关 |
| `firmware/runtimes/` | 执行运行时自己的装载事实 | `native-proot-mips32be` 的 ELF32 MIPS32BE LOAD 解析和 QEMU 日志处理 |
| `firmware/profiles/` | 某设备/固件版本的启动契约 | 封闭注册表当前仅注册 `dlink/dir825b-2.03`；`dir825` 是兼容别名 |
| `firmware/profiles/boot_plan.py` | 新固件的只读候选启动推断 | 常见 HTTP 服务路径、init 线索、ELF 架构、置信度和候选 launch mode |

`repair boot-plan --rootfs <rootfs>` 只读取物化 rootfs，输出候选目标、架构和 init 证据。它会标注架构/协议是否已在封闭注册表中注册，并显式声明 `candidate-only`。未知候选不能启动 `repair run`；只有被验证并注册为 profile 后，doctor 才可能给出 `ready`。

设备专属知识不能完全消灭：私有 NVRAM backend、厂商 rc 语义、特殊守护进程包装器或非 HTTP 协议仍需要 profile。目标是把这类知识从核心程序降到 profile 层；未来常见设备优先使用数据化 profile 和 BootPlan 候选，只有确实无法通用表达的私有行为才新增少量 profile 代码。

## 能力注册表

### 运行时

当前只有 `native-proot-mips32be` 是权威运行时。它创建隔离 user/net/pid/mount namespace，复制固件 root，通过 PRoot/QEMU 启动 rc 和目标，暴露 admin RPC socket 与私有 HTTP 隧道，并记录目标退出与 supervisor 事件。

FirmAE 与 Greenhouse 是诊断后端。它们可以提供事实，但当前不能授权 `validated_candidate`。

### 架构

当前只注册 `mips32be`。它报告 ELF32/big-endian/MIPS/o32 解析、分析操作、调用序列编码、重定向编码、编译器 target/flags、植入区和 ABI 假设。未支持架构在补丁生成前失败。

### 协议

当前注册两个封闭协议：

- `http-ascii-get-head-port80`：有界 ASCII GET/HEAD，无请求体，已有 CVE-2025-6291 真实修复闭环证据。
- `http-ascii-auth-form-multi-step-port80`：有界 ASCII GET/POST、表单编码、有限 Cookie/字段捕获和多步认证，已有 CVE-2024-57595 真实修复闭环证据。

该协议固定 `application/x-www-form-urlencoded` 表单、有限 Cookie 捕获/重放、声明式隐藏字段捕获和多步请求。POST 表单由驱动统一 URL 编码并计算 `Content-Length`；模型和 operator 都不能提供原始 body、任意 header 或网络脚本。多步执行器只捕获显式声明的 HTML input 字段和 Set-Cookie，后续请求只能引用这些已捕获值。

命令注入 marker 验收只允许一个预声明 guest 绝对路径、空普通文件。执行器检查路径无 `..`、无符号链接、父目录均位于 session rootfs 内；清理也只针对这个声明文件。基线必须证明合法控制请求不创建 marker、注入请求创建空 marker、目标身份稳定；候选必须证明登录/控制请求仍正常、注入请求不再创建 marker。

## 模型循环

控制器支持 OpenAI 兼容 Chat Completions 服务。当前真实证据使用智谱 GLM-5.3。

契约如下：

- 输出必须解析为请求的 JSON 对象；
- 定位查询是中性且只读的；
- 诊断是不可信事实，永远不会变成权威答案；
- 查询预算和阶段截止时间由本地执行；
- 未完成生成 POST 不重放；
- 截断输出使用有界恢复；
- 修复提案必须引用已接受证据和已注册位点；
- 每个定位/重定位会话都要求新鲜注册。

控制器不会在定位中注入已知答案、候选地址列表、函数名或补丁模板。

### Runtime sink differential probe

当一个已确认的命令注入 marker 存在多个候选 command sink 时，控制器可以在私有 session 副本上执行有界差分探测。候选只来自模型已经收到并保存在 evidence ledger 中的 `function_calls` 答案，且必须是 redirectable command-execution 调用；真实候选反馈或此前差分探针已证明 marker 未被拦截的 wrapper site 会被排除。首轮定位阶段会在 marker handler 覆盖完成且模型已看到至少两个候选 sink 后动态执行一次；重定位阶段仍可在候选失败后使用剩余候选继续探测。

每个探测使用控制器固定生成的诊断 wrapper，不接受模型提供的判定代码。控制器部署该 wrapper 后，从已验证计划的第一步开始重放认证、字段捕获、cookie 等前置状态，直到确认的 marker 触发步骤；不能只发送最终触发请求。探测观察 marker 是否消失、目标身份是否稳定，然后立即回滚 baseline。回滚失败按基础设施失败处理，不能被后续探测掩盖。

探测结论分为三类：`marker_blocked=true` 是决定性诊断证据；`marker_present=true` 表示该 wrapper 未拦截当前触发流；认证、传输或会话建立失败属于 `transport_or_session_failure`，结果必须记录为 `inconclusive`，不能被表述为“未阻断”。同一探测阶段出现这种场景失败时停止消耗后续候选 sink。提供给模型和写入 evidence 的结论都包含 `failure_kind` 与具体失败步骤，不能只传布尔值。探测结果写入 evidence ledger 和 run 工件，并作为诊断事实提供给模型；它不是修复候选，也不能替代模型在同一会话中新鲜执行 `register_patch_site`。默认每个探测阶段最多探测 3 个 site，找到有效拦截点后停止。

## 验证

生成测试先规范化为 public tests 后接 holdout tests。修复前，原始基线必须满足回归行为，并对漏洞测试表现出声明的外部可观察行为：崩溃类测试绑定非自愿致命退出；命令注入类测试绑定声明 marker 的出现/消失。HTTP 状态码本身不是命令注入证据。

候选被接受前，必须在重放中保持稳定身份、通过固定检查、通过生成测试，并通过回滚/重部署检查。最终清单绑定接受轮次、基线/候选 SHA、PoC 快照、测试、检查、rootfs 清单和产物。

`repair verify` 执行离线完整性检查，并在不调用模型的情况下重托管 run。清理警告本身不会让候选验证失效，但会被完整保留。

## 安全边界

- 原始固件不会被原地修改。
- 外部工具收到固件副本，不收到原始路径。
- 外部诊断执行前后都会校验原始固件 SHA。
- 外部 stdout/stderr 和生成报告有界保存。
- 受控 wrapper 使用显式 argv 和最小化环境。
- 物化拒绝挂载、设备节点、socket、setuid/setgid 文件和不安全链接。
- 会话变更必须持有活动事务锁。
- 凭据通过 `model_secret` 装载，并在报告中脱敏。
- 私有本地路径和原始诊断载荷在进入模型反馈前会被过滤。

## 扩展要求

新增一类固件必须同时补齐：

1. `repair boot-plan` 的静态候选证据；
2. 运行时能力与隔离证明；
3. 架构后端和编译器/ABI 契约；
4. 协议驱动和请求编码器；
5. 诊断规范化与身份绑定；
6. profile 注册和 doctor 能力门禁；
7. 定位/查询语义；
8. 植入与回滚行为；
9. 确定性测试和真实端到端运行。

Greenhouse 与额外架构属于后续扩展路径。不能只因为文件名或 CPU 架构相似就启用它们。

## 通用化演进

项目长期目标是支持绝大多数 IoT 固件的自动漏洞修复，当前路线按 [ROADMAP.md](ROADMAP.md) 推进：

- **P1 输入与诊断泛化：** 让 `.bin/.zip + PoC` 成为常规输入，自动识别固件格式、品牌线索和架构线索，并归一化外部诊断报告；`repair boot-plan` 已提供只读候选启动推断，但还不代表可运行；
- **P2 架构族扩展：** 从 MIPS32BE 扩展到 MIPS32LE、ARM32、AArch64 等常见 IoT 架构，补齐 ELF/ABI、调用序列、重定向和交叉编译契约；
- **P3 runtime 泛化：** 参数化现有 native runtime，并长期发展控制器自建受控 QEMU 路线；
- **P4 协议与服务泛化：** 已落地的受限表单 POST/auth/多步 HTTP 是第一小步，后续继续扩展 HTTPS、UPnP 和录制回放的私有协议；
- **P5 漏洞类型扩展：** 从栈溢出类内存破坏扩展到堆破坏、UAF、格式化字符串、整数溢出和注入类缺陷；
- **P6 批量评测：** 用成功、失败、成本和人工干预指标度量真实通用化程度。

当前真实闭环证据来自同一 DIR-825 B 2.03 / MIPS32 big-endian / `sbin/httpd` 样本：CVE-2025-6291 栈溢出与 CVE-2024-57595 命令注入。完整矩阵见 [SUPPORTED_FIRMWARE.md](SUPPORTED_FIRMWARE.md)。以上演进项都不能把这两个样本的历史结果当作通用能力完成证明。

## 当前限制

- 权威运行时和架构仍各只有一个；协议已有 GET/HEAD 与受限表单 POST/多步两个注册项，且均已具备各自声明场景内的真实闭环证据。
- profile 注册表当前只有 DIR-825 B 2.03；BootPlan 可报告未来架构候选，但不改变该封闭边界。
- 已验证固件工作仍限定 DIR-825 B 2.03、MIPS32 big-endian/o32 和 `sbin/httpd`；漏洞类型覆盖 CVE-2025-6291 栈溢出与 CVE-2024-57595 命令注入，均为单设备样本。
- FirmAE 只承担 analysis/intake。
- Greenhouse 真实 CLI 兼容性未验证。
- 不声称物理硬件验证。
- 不支持任意 HTTP header/body、HTTPS、非 80 端口、multipart、文件上传和原始 TCP/UDP。
