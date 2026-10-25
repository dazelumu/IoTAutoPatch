# 变更记录

本文件保留压缩后的版本历史。详细历史证据和旧发布记录保存在被忽略的本机归档中，不进入团队源码树。

## 0.3.1 - 2026-10-25

- 新增 runtime sink differential probe 和 wrapper 修复模式，完成 CVE-2024-57595 表单多步命令注入路线的真实模型修复闭环与独立 verify。
- 加强 marker handler 覆盖门禁、`function_calls` 分页 `next_offset`、过滤查询优先级、同 site 修正和 relocalize 预算控制。
- 修复 baseline 冗余重启，支持 `target_start_failed` 受控重试一次；修复离线 verify 对多步 fixed-check 的协议兼容问题。
- 归档 CVE-2024-57595 团队案例（PoC、proposal、patch record、候选摘要、run 报告 JSON 与独立验证 JSON），调整 `.gitignore` 放行案例 JSON 证据。
- 新增文档索引、贡献指南和安全策略；重写 README 与操作手册，形成入口文档、用户手册、开发者参考和验证账本的分层结构。
- 同步全部中文文档至两条真实闭环路线状态；权威运行时与架构范围未扩展。

## 0.3.0 - 2026-10-23

- 建立当前固件管线的 0.3.0 文档和源码树基线。
- 重构产品说明，将项目定位收敛为 IoT 固件自动漏洞修复系统。
- 新增中文架构说明、操作手册、变更记录和 0.3.0 发布记录。
- 新增已验证固件/CVE 清单，登记 DIR-825 B 2.03 的 CVE-2025-6291 栈溢出和 CVE-2024-57595 命令注入两个真实闭环样本。
- 新增可迁移的固件案例卡：CVE-2025-6291 登记为 `validated`；CVE-2024-57595 完成六步表单 PoC、真实模型定位、wrapper 修复、候选验证和独立 verify，登记为 `validated`。
- 新增中文固件通用化路线图，明确最终目标、当前 DIR-825/MIPS32BE/栈溢出边界、路线 A/B/C 和 P1–P6 扩展计划。
- 将固件运行时重构为 session / runtime / profile 三层：通用进程、HTTP 隧道和 MIPS32BE ELF 装载逻辑移出 DIR-825；DIR-825 设备知识移入 `profiles/dlink/dir825b_2_03/`，并通过封闭 profile 注册表解析。
- 新增只读 `repair boot-plan`：扫描物化 rootfs 的常见 HTTP 服务、init 线索和 ELF 架构，输出 candidate-only 启动计划；未知设备仍不能进入权威修复。
- 新增受限 `http-ascii-auth-form-multi-step-port80` 协议：固定表单 Content-Type、有界字段/body、有限 Cookie 捕获/重放、声明式隐藏字段捕获和多步请求；doctor、复现、固定检查、生成测试和 verify 支持命令注入空文件 marker 差异验收。旧 GET/HEAD 协议和崩溃验收语义保持兼容。
- 部署到 Ubuntu 24.04 WSL 固定路径后完成一次全量回归，并完成真实 DIR-825 路线 A `validated_candidate` 与独立 `verified_with_cleanup_warnings` 验证。
- 在同一固件上完成 CVE-2024-57595 真实闭环：新增 runtime sink differential probe、wrapper proposal/trampoline 植入、relocalize 分页与预算控制、baseline 重启复用与受控重试、离线 verify 多步协议兼容修复；最终 run `20261023-015556-7ca0e8ea` 达到 `validated_candidate`，独立 verify 为 `verified_with_cleanup_warnings`。
- 发布包纳入精选文档；归档过期过程资料、历史 ZIP、旧任务书、实验和历史结果。
- 优化路线 A 向导：进度面板更紧凑，菜单标注推荐项和风险项，回车执行推荐操作，inspect 完成状态可持久化；真实模型外发确认不再显示 `Y/N`，只接受大写 `YES`。
- 权威 runtime 与架构未扩展；新表单/多步协议已在 CVE-2024-57595 上完成真实模型修复闭环和独立 verify。Greenhouse、额外架构、HTTPS/非 80 端口和真实硬件仍未验证。

## 0.2.x

| 版本 | 简要说明 |
|---|---|
| 0.2.0 | 引入 DIR-825 固件模式：固件配置与 doctor、隔离原生重托管、PoC 复现、MIPS32BE 定位与植入、候选验证和固件报告。 |
| 0.2.1 | 共用模型配置校验，收紧重放身份、独立测试接受条件、配置错误处理和源码/包一致性检查。 |
| 0.2.2 | 测试生成携带真实触发输入，保留定位与反汇编证据，修复多植入路由，并要求 HTTP 测试断言有实际语义。 |
| 0.2.3 | 规范 public/holdout 测试顺序，引入更强结果清单，校验完整基线身份，改进失败记录和反馈隐私。 |
| 0.2.4 | 增加阶段级时限和有界模型上下文，随后加强 doctor namespace 检查、模型前基线检查、80 端口/HTTP body 语义、rootfs 清单和包校验。 |
| 0.2.5 | 让定位查询/轮次预算可见，并把定位失败与真实复现失败分开。 |
| 0.2.6 | 保留结构化 `finish_reason=length`，增加有界一次性恢复，避免重复重放超限截断请求。 |
| 0.2.7 | 位点注册后增加语义提名，强制新的 conclusion-only 轮，并在重定位前分类候选失败。 |
| 0.2.8 | 增加决定性位点检查、紧凑注册 prompt，以及可选长度差分 PoC 证据；无法归因的探测也会保留为 inconclusive。 |
| 0.2.9 | 修复注册后状态机，让待完成结论优先于再次注册决策。 |
| 0.2.10 | 增加发现位点检查点，让模型找到的调用点进入聚焦复查，而不是继续泛搜。 |
| 0.2.11 | 增加十进制/十六进制地址别名和连接/首字节/接收字节观测，用于区分模型传输失败与生成失败。 |
| 0.2.12 | 正式长耗时案例启用流式请求并提高请求超时，增加固件专用 reasoning 配置，同时保留固件生成 POST 不重放规则。 |
| 0.2.13 | 修正智谱 GLM 固件定位 reasoning 为 `low`，拒绝 `medium` 等不支持值。 |
| 0.2.14 | 把宽泛发现降级为聚焦检查，要求反汇编支撑决策，把 PoC 源码视为不可信证据，并保留分页缺口。 |
| 0.2.15 | 证据账本隔离提名决策，分页合并已见区间，重定位要求新鲜证据，并增加离线证据审计。 |
| 0.2.16 | 增加受控 root FirmAE analysis wrapper、`repair intake` 和有界 rootfs 物化。 |
| 0.2.17 | 增加交互式路线 A 向导、阶段进度状态、显式模型确认、失败诊断和单模板 FirmAE execute 装载。 |
| 0.2.18 | 修复私有 namespace 中崩溃后端口占用者清理，保留结构化失败/会话诊断。 |

## 0.2.0 之前

0.0.x 与 0.1.x 建立了控制器早期执行、测试、模型契约、报告和打包机制。该阶段已结束，当前产品路线只面向 IoT 固件修复。
