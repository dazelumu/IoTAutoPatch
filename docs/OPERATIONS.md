# Project Vuln Repair 操作手册 0.3.0

## 安装

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip build-essential cmake clang llvm strace unzip qemu-user proot util-linux iproute2
```

固件测试还需要 clang 的 MIPS 交叉目标和 `qemu-mips`。源码模式测试使用 gcc/g++、make、strace、cmake、ctest 和 llvm-symbolizer。

安装 Python 项目：

```bash
mkdir -p ~/tools
unzip project-vuln-repair-0.3.0.zip -d ~/tools
cd ~/tools/project-vuln-repair
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m pip check
python -c 'import repair_tool; print(repair_tool.__version__)'
```

## 配置层次

### 软件级模型配置

在安装目录创建被忽略的 `config.yaml`。它可以包含凭据和共享默认值，不得提交。

```yaml
model:
  provider: openai_compatible
  base_url: https://model-provider.example/v1
  name: your-model
  api_key_env: REPAIR_API_KEY
  stream: true
  request_timeout_seconds: 120
  total_timeout_seconds: 600
  max_output_tokens: 32768
  retries: 2
```

推荐省略 `api_key`，导出 `api_key_env` 指定的环境变量：

```bash
read -s REPAIR_API_KEY
export REPAIR_API_KEY
```

智谱 GLM 使用账号提供的 OpenAI 兼容端点和模型名。控制器不内置密钥或端点。

### 已准备 rootfs 的固件案例

```yaml
firmware:
  mode: true
  adapter: dir825
  rootfs: /absolute/path/to/rootfs
  target: sbin/httpd
  poc_request_timeout: 10
  checks:
    - request: {method: GET, path: /}
      statuses: [200]
      contains: "WIRELESS ROUTER | LOGIN"
  diagnostics:
    expose_to_model: true
    imports: []
poc:
  path: /absolute/path/to/poc.py
output:
  directory: /absolute/path/to/repair-results
```

### 路线 A intake 模板

路线 A 故意不设置 `firmware.rootfs`：

```yaml
firmware:
  mode: true
  adapter: dir825
  rootfs: null
  target: sbin/httpd
  checks:
    - request: {method: GET, path: /}
      statuses: [200]
      contains: "WIRELESS ROUTER | LOGIN"
  diagnostics:
    expose_to_model: true
    imports: []
poc:
  path: /absolute/path/to/poc.py
triage:
  output_root: /absolute/path/to/triage-results
  firmae:
    enabled: true
    executable: /usr/local/lib/firmae-controller/firmae-root-wrapper
    work_root: /absolute/path/to/firmae-work
    timeout_seconds: 3600
output:
  directory: /absolute/path/to/generated-case/repair-results
```

case 中的相对路径以该 YAML 文件所在目录为基准。

`firmware.adapter: dir825` 是当前 0.3.0 的兼容输入名。doctor 会显示解析后的正式 profile：`dlink/dir825b-2.03`。后续引入多 profile 时，配置字段会按迁移说明过渡，未注册名字会被拒绝。

### 受限表单 POST 与多步固定检查

CVE-2025-6291 这类 GET 崩溃案例保持默认 `firmware.protocol: http-ascii-get-head-port80`，原 `request/statuses/contains` 写法不需要修改。CVE-2024-57595 这类登录后表单命令注入案例显式选择：

```yaml
firmware:
  protocol: http-ascii-auth-form-multi-step-port80
  checks:
    - protocol: http-ascii-auth-form-multi-step-port80
      steps:
        - id: home
          method: GET
          path: /
          statuses: [200]
          capture_cookies: true
          capture_fields: [html_response_page, graph_id, alert_id]
        - id: login
          method: POST
          path: /login.cgi
          form:
            login_name: YWRtaW4=
            html_response_page: {capture: html_response_page}
          statuses: [200]
      statuses: [200]
```

固定检查负责证明登录和管理页功能仍可用。PoC 复现计划由模型根据声明式 PoC 生成，再由控制器校验；触发步骤必须声明 `marker` 和 `expect: marker_created`。控制器只允许 80 端口、固定表单 Content-Type、有限字段/Cookie 和声明捕获值，不执行模型提供的网络脚本。命令注入候选验收要求合法控制请求正常、注入请求不再创建预声明空文件 marker、目标身份稳定。

### 案例目录与证据整理

案例说明、可分享 PoC、示例配置、修复源码、PoC 计划、生成测试和脱敏结果摘要放在 `cases/`，当前索引见 [cases/README.md](../cases/README.md)。原始固件、rootfs、生成配置、模型响应、诊断输出和 `repair-results/` 不进入团队仓库，也不要求长期保存在案例目录；案例卡记录官方下载地址、大小和 SHA256，需要复核时按需下载。确认结果摘要记录 run ID、控制器版本、候选 SHA256、测试和独立验证结论后，可以清理临时实验目录。

已完成真实闭环的案例才能同步到 `docs/SUPPORTED_FIRMWARE.md`；`planned`、`test-only`、`diagnostic-only` 和手工历史证据都不能写成已支持能力。

### 源码案例

```yaml
project:
  path: /absolute/path/to/source-project
poc:
  path: /absolute/path/to/poc
build:
  command: [cmake, --build, build, --parallel, "2"]
  timeout_seconds: 180
tests:
  external_command: [pytest, -q]
output:
  directory: /absolute/path/to/repair-results
```

## 固件路线 A

### 交互式向导

```bash
cd ~/tools/project-vuln-repair
source .venv/bin/activate
python scripts/firmae_route_a_wizard.py \
  --config /path/to/intake.yaml \
  --firmware /path/to/dir825.bin \
  --brand dlink \
  --output-root /path/to/new-generated-case
```

向导菜单：

1. 检查/填写输入；
2. FirmAE analysis；
3. intake/rootfs 物化；
4. doctor；
5. 真实模型 repair run；
6. inspect；
7. 可选独立 verify；
`d` 诊断当前或指定 run；
`s` 显示进度；
`n` 执行推荐下一步；
回车执行当前推荐项；
`q` 退出。

菜单会标注当前推荐项和第 5 步风险。第 5 步启动前会列出将外发的数据和将消耗的额度，并要求输入大写 `YES`；输入 `Y`、`y`、`yes` 或其他内容都会取消。失败后向导优先推荐诊断，不会自动重跑真实模型。

### 显式命令

如果已经有物化 rootfs，可以先做只读启动计划探测：

```bash
repair boot-plan \
  --rootfs /absolute/path/to/rootfs \
  --target sbin/httpd
```

输出中的 `targets` 是按静态证据排序的候选目标，`init_candidates` 是 init 线索，`launch_modes` 只是两种待验证策略。`authorization` 始终是 candidate-only；即使命令发现 ARM32 或 MIPS32LE，也不表示对应架构后端已注册，更不能据此运行 `repair run`。

```bash
repair triage \
  --config /path/to/intake.yaml \
  --backend firmae \
  --mode analysis \
  --firmware /path/to/firmware.bin \
  --brand dlink
```

记录返回的 triage 目录：

```bash
repair intake \
  --config /path/to/intake.yaml \
  --triage-run /absolute/path/to/triage-results/run-id \
  --output-root /absolute/path/to/new-generated-case

repair doctor --config /absolute/path/to/generated-case/case.generated.yaml
repair run --config /absolute/path/to/generated-case/case.generated.yaml
```

只有 doctor 报告 `ready` 后才启动 `repair run`。

## 受控 FirmAE wrapper

路线 A wrapper 由 root 持有，只暴露 compatibility/analysis。它复制输入、调用配置的 FirmAE 安装、捕获有界输出、在执行前后校验原始固件、导出只读映像和 SHA 清单，并拒绝 `run/-r`。

使用 `scripts/install_firmae_root_wrapper.sh` 安装或更新；执行 sudo 前请先阅读脚本。控制器始终以显式 argv 调用 wrapper。

## 结果解释

| 状态 | 含义 |
|---|---|
| `validated_candidate` | 控制器在已支持模式上接受全部必要运行时证据 |
| `infrastructure_failed` | 本地运行时、传输、超时或清理失败；不是候选 verdict |
| `reproduction_failed` | PoC 未取得必需证据的复现 |
| `localization_failed` | 模型未注册有效的新鲜补丁位点 |
| `contract_information_required` | 模型输出或测试不满足契约 |
| `rounds_exhausted` | 修复预算耗尽且没有接受候选 |
| `rollback_failed` | 无法确认安全回滚 |
| `verified_with_cleanup_warnings` | 独立验证通过，但临时清理存在警告 |

查看和验证：

```bash
repair inspect --run <run-id-or-directory>
repair verify --run <run-id-or-directory>
```

## 更新安装

继续使用既有安装目录；不要每个版本新建带版本号的目录。标准路径是 `/home/<user>/tools/project-vuln-repair/`。

1. 停止活动任务。
2. 把新 ZIP 和 `.sha256` 复制到 `~/Downloads`。
3. 校验压缩包。
4. 解压到暂存目录。
5. 备份当前 `repair_tool/`、`tests/`、`scripts/`。
6. 替换程序管理的源码目录和顶层项目文件。
7. 保留 `.venv`、案例、诊断和 `repair-results/`。
8. 激活原 `.venv`。
9. 执行 `python -m pip install -e '.[dev]'` 与 `python -m pip check`。
10. 核对版本和实际加载模块路径。
11. 对该部署版本只执行一次全量回归。

部署测试必须运行在 Ubuntu 安装目录，不能从 Windows 源码目录的挂载路径运行。

## 打包

```bash
python scripts/package.py
python scripts/package.py --check
```

输出：

```text
dist/project-vuln-repair-0.3.0.zip
dist/project-vuln-repair-0.3.0.zip.sha256
```

发布包只有 `project-vuln-repair/` 一个固定内层根目录，包含源码、测试、脚本、正式夹具、精选文档和案例说明。

## 共享前隐私检查

- 移除模型密钥；
- 不附带私有软件配置；
- 明确固件、PoC 和诊断是否可以共享；
- 不提交固件、rootfs、生成配置、模型原始响应和完整运行结果，只检查案例 README、PoC、模板、修复源码和脱敏结果是否泄露路径、凭据或私有证据；
- 优先共享脱敏报告和 SHA 引用，而不是原始会话日志；
- 检查 `/tmp` 会话目录；
- 记住 `repair run` 已把目标证据和 PoC 材料发送给模型服务商。

## 故障处理

### doctor 报告能力不支持

对未支持运行时、架构、协议或目标这是预期行为。不要绕过 doctor；应先实现并测试缺失后端。

### FirmAE 未配置

检查 `triage.firmae.enabled`、`executable` 和 `work_root`；确认受控 wrapper 存在且可执行。控制器不会静默回退到其他命令。

### 重启时 `infrastructure_failed`

查看 run 的 `failure`、`session-report.json` 和 `target_cleanup_failed` 事件。当前清理会把私有 namespace 内所有 80 端口 owner 视为会话资产；清理失败时记录残留进程身份。

### `verified_with_cleanup_warnings`

候选验证通过，但会话清理留下警告。阅读 `verification/<id>/cleanup.json`。常见原因是非 root 控制器无法删除 root 持有的临时 `host-rootfs` 目录。

### 模型截止时间

真实工作流 deadline 是 `infrastructure_failed`，不是候选失败。查看调用进度，不要手工恢复未完成的生成 POST。
