# 固件案例索引

本目录既是团队案例说明，也是实验结束后的文件整理契约。案例卡说明漏洞触发、PoC 语义、模型可获得的证据、修复思路、候选验收和未验证边界；标准目录则规定哪些产物进入团队仓库，避免一次实验结束后证据散落在临时工作区。

可分享的 PoC、示例配置、模型生成的修复源码和脱敏结果摘要进入 Git。原始固件、rootfs、生成配置、模型响应、诊断输出和 `repair-results/` 不进入 Git。官方固件 ZIP 可以保存在同案例的 `archive/inputs/` 中作本地复核输入，但该目录被 Git 忽略。案例卡必须记录固件版本、官方下载地址、大小和 SHA256，团队成员按需下载并校验；成功 run 只保留脱敏摘要、候选身份和关键结论，不在团队文档中记录个人电脑路径。

权威的“已支持固件/CVE”结论只看 [../docs/SUPPORTED_FIRMWARE.md](../docs/SUPPORTED_FIRMWARE.md)。本页负责案例卡分类和写作规范，两份文档不得互相替代。

## 分类定义

| 分类 | 含义 | 是否可进入已支持清单 |
|---|---|---|
| `validated` | 已完成受控重托管复现、模型修复、候选验证和独立验证 | 满足全部入库标准后可以 |
| `poc-validated` | 已完成受控 PoC 复现，但协议、模型修复或候选验证仍未闭环 | 不可以 |
| `planned` | 已确定目标固件和漏洞，但缺少协议、验收或运行时能力 | 不可以 |
| `test-only` | pytest、向导或合成固件生成的测试数据 | 不可以 |
| `diagnostic-only` | FirmAE/Greenhouse 等外部工具的诊断输出，未完成修复闭环 | 不可以 |

## 案例卡

| 案例 | 固件 / CVE | 当前分类 | 状态 |
|---|---|---|---|
| [dlink/dir825b-2.03/cve-2025-6291/](dlink/dir825b-2.03/cve-2025-6291/README.md) | D-Link DIR-825 B 2.03 / CVE-2025-6291 | `validated` | 0.3.0 真实路线 A 已达到 `validated_candidate` |
| [dlink/dir825b-2.03/cve-2024-57595/](dlink/dir825b-2.03/cve-2024-57595/README.md) | D-Link DIR-825 B 2.03 / CVE-2024-57595 | `validated` | 0.3.0 真实模型定位 + wrapper 修复达到 `validated_candidate`，独立 verify 为 `verified_with_cleanup_warnings` |

## 案例卡写作规范

每个案例至少说明：

1. 固件版本、官方下载地址、大小、SHA256、目标 ELF、架构、协议和漏洞类型；
2. PoC 的输入结构、控制请求、触发请求和期望的外部可观察结果；
3. 控制器绑定请求、目标进程和 ELF 身份的方式；
4. 模型可查询的证据、必须完成的新鲜位点注册和禁止事项；
5. 修复提案的语义目标、植入方式和 deterministic 校验；
6. 候选接受条件、回滚/重部署要求和已知清理警告；
7. 未验证边界。

案例卡不得包含个人电脑绝对路径、用户名、密钥、Cookie、凭据或模型原始响应，也不登记旧版本成功 run。当前案例只记录用于得出结论的最新控制器版本；需要审计旧过程时由操作者在本地私有记录中追溯，不把它混入团队案例卡。

## 标准目录结构

```text
<brand>/<model-version>/<cve>/
  README.md                 团队案例卡与复现步骤
  poc/                      可分享的声明式 PoC 输入
  config/                   可分享的 case/intake 模板
  patches/                  模型生成的修复源码、proposal、patch record、候选摘要与补丁身份
  results/                  脱敏 JSON 摘要：PoC 计划、生成测试、定位、候选验证、run 报告与独立验证
```

整理完成的 case 不把原始固件、完整 rootfs、生成配置、HTML 报告、个人路径或 `repair-results/` 提交到 Git；patches 和 results 中只保留 JSON 摘要与文本证据，不提交补丁二进制或对象文件。官方 ZIP 可留在被忽略的 `archive/inputs/`；完整 rootfs 和大型过程产物应在结果摘要整理完成后清理。确认 `results/result-summary.json` 已记录最新成功 run ID、控制器版本、候选 SHA256、测试结果和独立验证结论后，即可清理对应的临时实验目录；固件需要复核时按案例卡给出的官方地址重新下载并校验 SHA256。
