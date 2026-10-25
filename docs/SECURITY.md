# 安全策略

Project Vuln Repair 会执行不可信固件、调用外部模型服务并以受控方式运行诊断工具。使用前请理解以下边界。

## 支持版本

安全修复只针对最新发布分支。当前发布版本见 [README](../README.md) 和 [变更记录](CHANGELOG.md)。

## 报告安全漏洞

仓库公开后，请优先使用 GitHub Security Advisory 私密报告。公开前阶段请直接联系维护者，不要在 issue、PR 或案例文档中发布未处理的利用细节。

报告应包含：

1. 项目版本和运行环境；
2. 受影响命令与最小配置结构；
3. 复现步骤或失败工件；
4. 影响评估，例如沙箱逃逸、原始固件篡改、凭据泄漏或错误验证；
5. 是否已经外发给模型服务商。

## 信任边界

### 原始输入

固件、第三方 PoC、外部诊断报告和模型输出都按不可信输入处理。原始固件不会被原地修改；实验使用私有副本。

### 运行时隔离

权威运行时当前是 `native-proot-mips32be`，使用隔离 namespace、PRoot/QEMU、私有网络和会话锁。这个环境用于受控实验，不等于硬件级安全边界，也不适合运行未知恶意固件。

如果固件来源不明，建议在专用虚拟机和快照中执行，并限制网络访问。

### 外部工具

FirmAE 只通过受控 wrapper 执行 compatibility/analysis。wrapper：

- 使用显式 argv，不经过 shell；
- 复制固件而不是暴露原始路径；
- 执行前后校验固件 SHA；
- 有界捕获 stdout/stderr；
- 拒绝 `run/-r` 等权威执行模式。

Greenhouse 目前只有 diagnostic-only 适配契约，真实 CLI 兼容性未验证。

### 模型数据外发

真实 `repair run` 会向配置的模型服务商发送目标证据、PoC、诊断和分析数据。操作者必须确认：

1. 拥有固件和漏洞数据的合法授权；
2. 模型服务商的数据政策满足项目要求；
3. 案例中没有不能外发的第三方机密；
4. 向导第 5 步的显式 `YES` 只代表当次授权。

API key 通过环境变量或本地被忽略的 `config.yaml` 装载，不进入报告、案例或 Git。

## 关键不变量

- 未注册 runtime、架构、协议或 profile 时，doctor 必须拒绝；
- 模型必须本会话执行 `register_patch_site`；
- 候选 pre-ready 崩溃不能被 baseline 重试掩盖；
- 回滚失败必须中断并报告；
- 未完成的模型生成 POST 不自动重放；
- HTTP 状态码不是命令注入证据；
- 清理警告不能被隐藏，但只有确认不影响验证证据时才允许 `verified_with_cleanup_warnings`。

## 安全相关代码审查点

修改以下模块时必须补充定向测试：

- `repair_tool/firmware/session/`
- `repair_tool/firmware/runtime.py`
- `repair_tool/firmware/protocol.py`
- `repair_tool/firmware/intake.py`
- `repair_tool/firmware/triage*.py`
- `repair_tool/arch/`
- `repair_tool/firmware/implant.py`
- `repair_tool/model.py`

这些模块的变更需要在 PR 中明确说明失败分类、回滚行为、数据外发和权限边界。
