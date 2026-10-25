# 贡献指南

感谢你参与 Project Vuln Repair。这个项目的核心价值在于证据边界清晰，所以贡献不只是“代码能跑”，还必须说明验证环境、证据来源和未验证范围。

## 开发环境

已验证的开发系统是 Ubuntu 24.04：

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip build-essential cmake clang llvm strace unzip qemu-user proot util-linux iproute2
git clone <repository-url>
cd project-vuln-repair
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

Windows 可以运行一部分纯单元测试，但 POSIX 锁、Unix socket、PRoot/QEMU 和交叉编译集成测试必须在 Linux 环境执行。

## 测试策略

项目采用“变更相关的定向测试优先”的策略：

```bash
python -m pytest tests/test_config_validation.py -q
python -m pytest tests/test_firmware_loop.py -q -k "runtime_sink_probe or marker"
python -m py_compile repair_tool/firmware/loop.py
```

规则如下：

1. 小改动运行受影响模块的定向测试和 `python -m py_compile`；
2. 打包或文档清单改动运行 `tests/test_packaging.py` 与 `tests/test_package_contents.py`；
3. 每个部署版本只执行一次 Ubuntu 全量回归，除非维护者明确要求重复；
4. 真实模型、真实固件和 WSL 部署测试成本高，贡献者不必自行执行，但不得虚构结果；
5. 测试跳过必须写明环境原因，例如缺少 POSIX `fcntl` 或交叉编译器。

## 代码组织

```text
repair_tool/config.py             配置装载、合并和 schema 校验
repair_tool/cli.py                命令入口
repair_tool/firmware/loop.py      固件修复状态机
repair_tool/firmware/session/     进程身份、清理和私有 HTTP 隧道
repair_tool/firmware/runtimes/    权威运行时装载事实
repair_tool/firmware/profiles/    设备 profile 和 BootPlan 候选
repair_tool/firmware/protocol.py  封闭协议注册表
repair_tool/arch/                 架构后端注册表
repair_tool/firmware/implant.py   候选编译、植入和身份记录
```

新增能力时优先扩展现有注册表和契约测试，不要在 `loop.py` 中加入设备专属分支。设备知识应进入 profile，架构事实进入 arch backend，协议编码进入 protocol driver。

## 提交前检查

- [ ] `python -m py_compile` 覆盖修改的 Python 文件；
- [ ] 定向测试通过，失败如果是环境限制要写清楚；
- [ ] `git diff --check` 无空白错误；
- [ ] 没有提交 `config.yaml`、API key、固件、rootfs、模型原始响应或完整 run；
- [ ] 文档没有个人路径、用户名、凭据或私有日志；
- [ ] 能力声明没有超出真实验证范围；
- [ ] 新配置项有校验和测试；
- [ ] 新协议或架构有明确 unsupported 行为；
- [ ] 打包清单变化已同步 `tests/test_package_contents.py`。

## Pull Request 说明格式

PR 描述建议包含：

```markdown
## 问题
说明触发场景和修改前的错误行为。

## 变更
列出核心行为、接口和文档变化。

## 验证
列出命令、环境、结果和跳过原因。

## 边界
说明未验证的架构、协议、真实硬件或外部工具。
```

维护者会优先审查证据链、失败分类和回滚行为。只给出“测试通过”但缺少环境信息的 PR 可能被要求补充。

## 案例贡献

案例必须放在：

```text
cases/<brand>/<model-version>/<cve>/
```

可提交内容：

- 案例卡 `README.md`；
- 声明式 PoC；
- `config/*.example.yaml`；
- `patches/*.c` 与 JSON 提案/补丁记录；
- `results/**/*.json` 脱敏摘要。

不要提交原始固件、解包 BIN、rootfs、patched 二进制、对象文件、HTML 报告、完整模型响应或 `repair-results/`。

详细要求见 [案例规范](../cases/README.md)。

## 文档贡献

文档是产品的一部分。修改文档时：

1. 保持读者明确：用户、开发者、审计者或发布维护者；
2. 命令可复制，路径用占位符；
3. 不用“支持某架构/协议”这类泛化说法，除非支持矩阵已有证据；
4. 不改写 `VALIDATION.md` 的历史记录；
5. 新版本只修改当前文档和对应 release 记录。

## 行为准则

请保持技术讨论聚焦、尊重事实、不夸大能力。涉及漏洞数据和第三方固件时，优先保护用户环境与供应商权益，不发布不可复现的利用细节。
