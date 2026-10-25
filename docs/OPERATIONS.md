# Project Vuln Repair 操作指南

本指南面向在 Ubuntu Linux 上安装、配置和运行控制器的操作者。它按一次任务的生命周期组织：安装、配置、诊断/物化、运行、解释结果、更新和排障。所有命令都使用可替换的 `/path/to/...`、`<case.yaml>` 占位符；不要把个人机器路径写入团队配置或案例归档。

## 1. 安装

### 1.1 系统依赖

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip build-essential cmake clang llvm strace unzip qemu-user proot util-linux iproute2
```

固件路线还需要 clang 的 MIPS 交叉目标（`--target=mips-linux-gnu`）和 `qemu-mips`。FirmAE 路线 A 通过受控 wrapper 调用既有安装，本指南不要求把 FirmAE 作为权威 runtime。

### 1.2 安装发布包

发布包必须与 `.sha256` 一起分发。安装前先校验：

```bash
cd /path/to/release-download
sha256sum -c project-vuln-repair-0.3.1.zip.sha256

mkdir -p ~/tools
unzip project-vuln-repair-0.3.1.zip -d ~/tools
cd ~/tools/project-vuln-repair

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m pip check
python -c 'import repair_tool; print(repair_tool.__version__)'
```

版本必须输出 `0.3.1`。安装路径固定为 `~/tools/project-vuln-repair/`；后续升级继续使用这个目录，不要为每个版本新建带版本号的目录。

## 2. 配置

### 2.1 配置层级

| 文件 | 是否进入 Git | 用途 |
|---|---:|---|
| 安装目录 `config.yaml` | 否 | 软件级模型配置，可包含共享默认值或凭据引用 |
| 案例目录 `case.yaml` | 视内容 | 单个源码/固件任务的输入、输出和验收配置 |
| 路线 A `intake.yaml` | 模板可进入 | 原始固件、诊断工具和生成案例位置 |
| 环境变量 | 否 | 推荐的 API key 装载方式 |

YAML 中的相对路径以该 YAML 文件所在目录为基准。API key 不应写入案例文件或任何会提交的配置。

### 2.2 软件级模型配置

在安装目录创建被 Git 忽略的 `config.yaml`：

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

推荐省略 `api_key`，导出 `api_key_env` 指定的变量：

```bash
read -s REPAIR_API_KEY
export REPAIR_API_KEY
```

控制器不内置模型端点、模型名或密钥。智谱 GLM 使用账号提供的 OpenAI 兼容端点和模型名。

### 2.3 已准备 rootfs 的固件案例

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

`firmware.adapter: dir825` 是当前版本的兼容输入名。doctor 会显示解析后的正式 profile：`dlink/dir825b-2.03`。

### 2.4 路线 A intake 模板

路线 A 模板故意不设置 `firmware.rootfs`，由 `repair intake` 物化后生成：

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

### 2.5 受限表单 POST 与多步 HTTP

CVE-2025-6291 这类 GET 崩溃案例保持默认 `http-ascii-get-head-port80`，原 `request/statuses/contains` 写法不变。CVE-2024-57595 这类登录后表单命令注入案例显式选择：

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

该驱动只允许 80 端口、固定表单 Content-Type、有限字段/Cookie 和显式捕获值。POST body、Cookie 和 `Content-Length` 由控制器编码；模型和操作者不能提供原始 body、任意 header 或网络脚本。命令注入触发步骤必须声明 marker 和 `expect: marker_created`。marker 只能是预声明的 guest 绝对路径空文件；HTTP 状态码不是命令注入证据。

## 3. 固件路线 A

### 3.1 交互式向导

推荐新实验使用向导：

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

| 键 | 动作 |
|---|---|
| `1`–`7` | 输入检查、FirmAE analysis、intake、doctor、repair run、inspect、verify |
| `d` | 诊断当前或指定 run |
| `s` | 显示进度 |
| `n` | 执行推荐下一步 |
| 回车 | 执行当前推荐项 |
| `q` | 退出 |

第 5 步会列出将外发的数据、模型名和成本影响，只接受大写 `YES`。`Y`、`y`、`yes` 和其他输入都会取消。失败后向导推荐先诊断，不会自动重跑真实模型。

### 3.2 显式命令

如果已有物化 rootfs，先做只读启动计划探测：

```bash
repair boot-plan \
  --rootfs /absolute/path/to/rootfs \
  --target sbin/httpd
```

`targets` 是按静态证据排序的候选目标，`init_candidates` 是 init 线索，`launch_modes` 是待验证策略。输出始终是 `candidate-only`；发现 ARM32 或 MIPS32LE 不表示对应架构后端已注册，更不能启动 `repair run`。

从原始固件执行路线 A：

```bash
repair triage \
  --config /path/to/intake.yaml \
  --backend firmae \
  --mode analysis \
  --firmware /path/to/firmware.bin \
  --brand dlink

repair intake \
  --config /path/to/intake.yaml \
  --triage-run /absolute/path/to/triage-results/run-id \
  --output-root /absolute/path/to/new-generated-case

repair doctor --config /absolute/path/to/generated-case/case.generated.yaml
repair run --config /absolute/path/to/generated-case/case.generated.yaml
```

只有 doctor 返回 `ready` 后才执行 `repair run`。

## 4. 受控 FirmAE wrapper

路线 A wrapper 由 root 持有，只暴露 compatibility/analysis。它会复制输入、调用配置的 FirmAE 安装、有界捕获输出、在执行前后校验原始固件 SHA、导出只读映像和 SHA 清单，并拒绝 `run/-r`。控制器始终用显式 argv 调用 wrapper，不经过 shell。

安装或更新 wrapper：

```bash
sudo bash scripts/install_firmae_root_wrapper.sh
```

执行 sudo 前请先阅读脚本内容，并确认它配置的 FirmAE 路径符合团队约定。

## 5. 结果解释

| 状态 | 含义 | 下一步 |
|---|---|---|
| `validated_candidate` | 控制器在已支持模式上接受全部必要运行时证据 | 执行 `repair inspect`，必要时 `repair verify` |
| `verified_with_cleanup_warnings` | 独立验证通过，但临时清理有警告 | 阅读 cleanup 记录并手动处理残留 |
| `infrastructure_failed` | 本地运行时、传输、超时或清理失败 | 查看失败分类和 session 诊断，不是候选 verdict |
| `reproduction_failed` | PoC 未取得必需证据的复现 | 检查 PoC、协议和 baseline 身份 |
| `localization_failed` | 模型未注册有效的新鲜补丁位点 | 查看查询预算、证据和模型结论 |
| `contract_information_required` | 模型输出或测试不满足契约 | 按报告补契约信息，不直接改程序 |
| `rounds_exhausted` | 修复预算耗尽且没有接受候选 | 审查失败轮次和候选反馈 |
| `rollback_failed` | 无法确认安全回滚 | 停止继续实验，优先恢复基线 |

查看和独立验证：

```bash
repair inspect --run /path/to/repair-results/run-id
repair verify --run /path/to/repair-results/run-id
```

`repair verify` 不调用模型，会重新执行离线完整性检查、回滚、复现、候选重部署和最终验证。

## 6. 更新已安装版本

1. 停止正在运行的 `repair`/向导任务；
2. 把新 ZIP 和 `.sha256` 复制到本机下载目录；
3. 校验压缩包；
4. 解压到暂存目录；
5. 备份当前 `repair_tool/`、`tests/`、`scripts/` 和顶层项目文件；
6. 替换程序管理的源码目录和项目文件；
7. 保留 `.venv`、案例、诊断和 `repair-results/`；
8. 在原安装目录激活 `.venv`；
9. 执行 `python -m pip install -e '.[dev]'` 和 `python -m pip check`；
10. 核对版本与模块加载路径；
11. 该部署版本只执行一次全量回归。

不要删除安装目录来更新，也不要把 `.venv` 移动到其他路径。部署测试必须运行在 Ubuntu 安装目录，不能从 Windows 源码挂载路径借用安装环境并称为部署测试。

## 7. 打包

```bash
python scripts/package.py
python scripts/package.py --check
```

输出：

```text
dist/project-vuln-repair-0.3.1.zip
dist/project-vuln-repair-0.3.1.zip.sha256
```

发布包只有 `project-vuln-repair/` 一个内层根目录，包含源码、测试、脚本、正式夹具、文档和团队案例说明，不包含本地配置、固件、rootfs、模型响应或历史运行结果。

## 8. 共享前隐私检查

- 确认模型密钥没有出现在配置、报告、日志或案例文件；
- 不附带私有软件配置；
- 确认固件、PoC、诊断和厂商数据的共享授权；
- 不提交固件、rootfs、生成配置、模型原始响应和完整 `repair-results/`；
- 检查案例 README、PoC、模板、修复源码和脱敏结果中是否泄漏个人路径、用户名、Cookie 或会话数据；
- 优先共享脱敏摘要和 SHA 引用；
- 检查 `/tmp` 会话目录是否残留敏感内容；
- 记住真实 run 已把目标证据和 PoC 材料发送给模型服务商。

案例归档契约见 [案例规范](../cases/README.md)。

## 9. 故障处理

### doctor 报告能力不支持

对未支持 runtime、架构、协议、profile 或目标，这是预期行为。不要绕过 doctor；应先实现并测试缺失后端，再注册能力。

### FirmAE 未配置

检查 `triage.firmae.enabled`、`executable` 和 `work_root`，确认受控 wrapper 存在且可执行。控制器不会静默回退到其他命令。

### baseline 重启或目标退出

查看 run 的 `failure`、`session-report.json` 和 `target_cleanup_failed` 事件。baseline `target_start_failed` 最多受控重试一次；候选 pre-ready 崩溃不会被重试掩盖，会保留为候选失败证据。

### `infrastructure_failed`

先确认这是本地执行环境失败，不是漏洞行为或候选失败。查看请求进度、namespace、QEMU/PRoot、模型调用和清理记录。未完成的生成 POST 不会自动重放。

### `verified_with_cleanup_warnings`

候选验证通过，但会话清理留下警告。阅读 `verification/<id>/cleanup.json`。常见原因是非 root 控制器无法删除 root 持有的临时 `host-rootfs` 目录。

## 10. 获取帮助

先阅读 [架构说明](ARCHITECTURE.md) 判断问题属于控制器、runtime、协议、模型契约还是环境；再查看 [验证账本](../VALIDATION.md) 中同类问题的历史证据。提交问题时请提供控制器版本、操作系统、doctor 输出、run 目录名、失败状态和是否发生模型外发；不要直接粘贴密钥、完整固件或原始模型响应。
