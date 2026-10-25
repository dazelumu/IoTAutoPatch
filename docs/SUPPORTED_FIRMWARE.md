# 已验证固件与 CVE 清单

本文是固件真实验证结果的唯一入口。这里只登记已经完成受控重托管复现、模型修复、候选验证和独立验证的固件/CVE 组合；BootPlan 候选、单元测试、合成样本、计划中的 CVE 和历史手工分析都不会进入本清单。可迁移的案例卡见 [../cases/README.md](../cases/README.md)。

## 入库标准

新增一行必须同时具备：

1. 原始固件、rootfs、目标 ELF、PoC 和候选产物的 SHA/身份绑定；
2. 原始固件在重托管中可稳定复现可归因故障；
3. 已注册 runtime、架构和协议能力均通过 `repair doctor`；
4. 真实 `repair run` 返回 `validated_candidate`；
5. 独立 `repair verify` 记录最终验证结论；
6. 清楚列出未验证边界，不把受控实验扩大成硬件或官方 CVE 全场景验证。

## 当前已验证矩阵

当前已验证 **2** 个固件/CVE 组合。

| CVE | 设备与固件 | 目标 | 架构 | 协议 | 漏洞类型 | 修复路线 | 真实 run | run 结果 | 独立验证 |
|---|---|---|---|---|---|---|---|---|---|
| CVE-2025-6291 | D-Link DIR-825 Rev. B 2.03 NA | `sbin/httpd` | MIPS32 big-endian / o32 | 80 端口 ASCII HTTP GET/HEAD | `do_file` 请求路径栈溢出 | FirmAE analysis/intake + `native-proot-mips32be` | `20261021-024629-b18f2722` | `validated_candidate` | `verified_with_cleanup_warnings` |
| CVE-2024-57595 | D-Link DIR-825 Rev. B 2.03 NA | `sbin/httpd` | MIPS32 big-endian / o32 | 80 端口受限 ASCII GET/POST 表单与多步认证 | `apc_client_pin.cgi` `wps_pin` 命令注入 | FirmAE analysis/intake + `native-proot-mips32be` | `20261023-015556-7ca0e8ea` | `validated_candidate` | `verified_with_cleanup_warnings` |

## CVE-2025-6291 证据摘要

- 原始固件：`dir825_revB_fw_203NA.bin`，SHA256 `379836b8625f32fb3c2642656f056e9bf43f929101e2ff758bb5049c5373ef2d`。
- 目标 `sbin/httpd` SHA256：`a7b4741736dd3f5572da480deb3a785fb17d3b5b60e7bf82f686b9844b5097b7`。
- 崩溃位置对应 `do_file` 路径拼接的无界 `strcat`；修复定位点为十进制 `4236836`（`0x40A624`）。
- 受控 PoC 使用长 URI 加 `.gif` 后缀的 ASCII GET 请求触发栈溢出，并在修复后通过固定检查和生成测试。
- 0.3.0 真实 run：`20261021-024629-b18f2722`，耗时 855.539 秒，基线固定检查 1/1，最终生成测试 3/3。
- 修复候选 `sbin/httpd` SHA256：`464832db54db8c4dec28c3d7ef335a2313d172a3144bf50a52db92ce6f1d8ddd`。
- 独立验证：`verified_with_cleanup_warnings`；警告仅为 root 持有的临时 `host-rootfs` 目录无法由非 root 控制器删除，不否定候选验证。
- 详细部署、全量回归和报告路径见 [../VALIDATION.md](../VALIDATION.md)。

## CVE-2024-57595 证据摘要

- 原始固件与目标 `sbin/httpd` SHA256 与 CVE-2025-6291 案例一致，均来自 DIR-825 Rev. B 2.03 NA 官方 ZIP。
- 受控 PoC 是六步声明式流程：首页字段捕获、登录、认证页确认、合法 PIN `12345670`、8 字节注入 PIN `';>/Q ;#`、触发后再提交合法 PIN。基线证据以 `/Q` marker 差异、请求字节 SHA、目标身份和目标存活绑定。
- 模型定位到 `apc_client_pin.cgi` handler 的 `_system` 调用点 `4272620`（`0x004131ec`）；runtime sink differential probe 显示阻断该调用后 marker 消失并成功回滚 baseline。
- 候选使用 wrapper 语义：命令含 shell 控制元字符时不调用原 `_system`；合法命令返回 0 并由控制器生成 trampoline 重新调用原函数，保留合法 PIN 保存功能。
- 0.3.0 真实 run：`20261023-015556-7ca0e8ea`，耗时 1702.185 秒，基线固定检查 1/1，最终生成测试 4/4。
- 修复候选 `sbin/httpd` SHA256：`9045157760a96ef8b8a046b3f1d90356960e5ec05b86fda62fc445276c5798bf`；模型源码 SHA256：`f95f9a690791818580ac55feed80f2bc2c6f325e57149622045a74cefc2976aa`。
- 独立验证：`verified_with_cleanup_warnings`；警告仅为 root 持有的临时 `host-rootfs` 目录无法由非 root 控制器删除，不否定回滚、重部署和候选验证。
- 团队案例卡、PoC、补丁工件和脱敏报告见 [../cases/dlink/dir825b-2.03/cve-2024-57595/README.md](../cases/dlink/dir825b-2.03/cve-2024-57595/README.md)。

## 边界与解释限制

- 公开 CVE 描述或第三方资料可能提到 HTTP POST；本项目实测和当前注册协议能力针对该 2.03NA 样本中的无鉴权 `.gif` GET 分支完成复现与修复验证。
- 本清单证明的是受控 PRoot/QEMU 环境中的漏洞复现与修复，不证明物理 DIR-825 硬件、官方固件升级流程或完整官方 CVE 利用面已经验证。
- 受限表单 POST 和多步 HTTP 协议仅在 CVE-2024-57595 的已声明认证流程、表单字段和 marker 场景中验证，不能推广为任意 HTTP 或 Web 漏洞支持。
- ARM、AArch64、MIPS32LE、其他品牌、其他目标服务和 Greenhouse 权威路线仍未验证。

## 外部参考

- [CVE-2025-6291 CVE 记录](https://www.cve.org/CVERecord?id=CVE-2025-6291)
- [VulDB 313293](https://vuldb.com/vuln/313293)
