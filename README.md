# CSP Scanner Skill

一个面向 Claude Code、Codex 和 OpenCode 的 Content Security Policy（CSP）静态扫描与安全修复 Skill。

它可以在项目代码、Web 服务器配置和托管平台配置中定位 CSP，识别常见风险，并生成保守的修复预览。所有核心指令只维护一份，避免不同 Agent 使用不同的扫描或修复逻辑。

## 功能

- 递归扫描项目中的 CSP 响应头、HTML Meta CSP 和基础设施配置。
- 识别 `unsafe-inline`、`unsafe-eval`、裸 `*`、缺失 `object-src`、缺失 `frame-ancestors`、不安全 `base-uri` 等问题。
- 项目完全没有 CSP 时明确报告“未检测到 CSP 配置”。
- 生成包含文件、行号、风险等级、问题说明和修复建议的 Markdown 报告。
- 将结构化结果写入 `.csp-scan-report.json`，供后续修复使用。
- 默认只预览 unified diff，不修改源码。
- 应用模式只处理确定性修复，并在写入前创建备份。
- 对需要业务判断的改动单独标记为“需人工确认”。

## 项目结构

```text
.
├── README.md
└── csp-scanner/
    ├── SKILL.md
    ├── agents/
    │   └── openai.yaml
    ├── commands/
    │   ├── csp-scan.md
    │   └── csp-fix.md
    ├── references/
    │   ├── directives.md
    │   ├── fix-patterns.md
    │   ├── installation.md
    │   ├── pitfalls.md
    │   └── scan-targets.md
    ├── scripts/
    │   ├── scan_csp.py
    │   └── fix_csp.py
    └── tests/
        └── test_cli.py
```

`csp-scanner/` 是完整的可分发 Skill 包。

## 安装

建议将 `csp-scanner/` 复制到项目的供应商中立目录：

```bash
mkdir -p <目标项目>/.agents/skills
cp -R csp-scanner <目标项目>/.agents/skills/csp-scanner
```

安装后的结构应为：

```text
<目标项目>/.agents/skills/csp-scanner/SKILL.md
```

### Codex

Codex 可以从项目的 `.agents/skills/` 目录发现 Skill。本项目已通过 Codex 的模型输入调试命令验证发现结果。

### OpenCode

OpenCode 当前官方文档支持以下项目目录：

- `.opencode/skills/`
- `.agents/skills/`
- `.claude/skills/`

因此通常可以直接复用 `.agents/skills/csp-scanner/`。升级 OpenCode 后建议重新检查发现结果：

```bash
opencode debug skill
```

参考：[OpenCode Agent Skills](https://opencode.ai/docs/skills/)

### Claude Code

如果使用的 Claude Code 版本没有读取 `.agents/skills/`，可以复制一份或建立相对符号链接：

```bash
mkdir -p <目标项目>/.claude/skills
ln -s ../../.agents/skills/csp-scanner \
  <目标项目>/.claude/skills/csp-scanner
```

不建议分别维护多份 Skill 内容。应以 `.agents/skills/csp-scanner/` 为权威副本，其他目录只做复制或链接分发。

## 使用方法

安装后，可以使用自然语言触发：

```text
扫描一下这个项目的 CSP 问题
检查项目里的 Content Security Policy 配置
帮我修复刚才发现的 CSP 安全问题
```

也可以使用 Skill 定义的命令形式。

### 扫描

```text
/csp-scan
/csp-scan ./apps/web
```

默认扫描当前项目根目录，执行过程不会修改应用或基础设施源码。默认会生成：

```text
.csp-scan-report.json
```

如果连报告文件也不允许创建，可以要求 Agent 使用扫描脚本的 `--no-write` 参数。

### 修复预览

```text
/csp-fix
/csp-fix --only high
```

默认只输出 unified diff 和改动原因，不修改源码。

### 应用确定性修复

```text
/csp-fix --apply
/csp-fix --apply --only medium
```

应用模式会：

1. 验证扫描报告中的源码位置仍然有效。
2. 为待修改文件创建 `.bak` 备份。
3. 只应用可以确定生成的修改。
4. 跳过所有需要业务或架构判断的问题。
5. 提示重新扫描验证结果。

目前内置修复器只自动补充缺失的：

```text
object-src 'none';
```

这是刻意设置的安全边界。错误地自动收紧 CSP 可能直接导致生产页面、第三方集成或嵌入功能不可用。

## 直接运行脚本

Skill 中的脚本只依赖 Python 标准库，不需要安装第三方依赖。

### 扫描器

```bash
python3 csp-scanner/scripts/scan_csp.py <项目路径>
```

常用参数：

```text
--output <path>              指定 JSON 报告路径
--format markdown|json|both  控制终端输出格式
--no-write                   不生成 JSON 报告文件
--max-file-bytes <bytes>     设置单文件扫描大小上限
```

示例：

```bash
python3 csp-scanner/scripts/scan_csp.py ./example --format both
```

### 修复器

```bash
python3 csp-scanner/scripts/fix_csp.py \
  --report <项目路径>/.csp-scan-report.json
```

常用参数：

```text
--apply                      应用确定性修改
--only high|medium|low       只处理指定风险等级
--diff-output <path>         将 unified diff 写入文件
```

## 扫描范围

扫描器支持常见的：

- Node.js、Next.js、Python、Ruby、PHP、Java、Go 等后端源码。
- HTML、模板、Vue、Svelte 等前端文件。
- `Content-Security-Policy` 响应头设置代码。
- Helmet 和 `contentSecurityPolicy` 等框架配置标记。
- HTML `<meta http-equiv="Content-Security-Policy">`。
- `nginx.conf`、Apache 配置和 `.htaccess`。
- Vercel `vercel.json`。
- Netlify `_headers` 和 `netlify.toml`。
- JSON、YAML、TOML、Terraform 和 Kubernetes 配置。

扫描器默认跳过 `.git`、`node_modules`、`vendor`、`dist`、`build`、`.next`、缓存目录和大于 2 MiB 的文件。

## 风险规则

| 规则 | 默认等级 | 自动修改 |
|---|---|---|
| `unsafe-inline` | 高；仅样式场景默认为中 | 否 |
| `unsafe-eval` | 高 | 否 |
| 裸 `*` 来源 | 高 | 否 |
| 缺失 `object-src 'none'` | 中 | 是 |
| `object-src` 未限制为 `'none'` | 高 | 否 |
| 缺失 `frame-ancestors` | 中 | 否 |
| 缺失 `base-uri` | 中 | 否 |
| 宽泛 `base-uri` | 高 | 否 |
| Meta CSP 无法执行 `frame-ancestors` | 高 | 否 |
| 仅 Report-Only | 低 | 否 |
| 无法解析的框架配置 | 低 | 否 |

完整说明见 `csp-scanner/references/pitfalls.md`。

## 安全原则

- 优先使用 HTTP 响应头，而不是 HTML Meta CSP。
- 不自动删除 `unsafe-inline` 或 `unsafe-eval`。
- 不根据猜测自动替换通配符来源。
- 不自动决定页面是否允许被第三方嵌入。
- 内联代码优先外链化，其次使用逐响应 nonce，稳定内容才考虑 hash。
- nonce 必须不可预测、每个响应唯一，并同时写入响应头和对应元素。
- 预览是默认行为，只有明确授权后才写入源码。
- 无法确定的配置必须保留为人工处理项。

## 静态扫描限制

扫描结果不能证明浏览器实际收到的最终 CSP。以下情况仍需人工或运行时验证：

- CSP 由 CDN、API 网关或仓库外的代理注入。
- 策略通过环境变量、字符串拼接或模板动态生成。
- 不同路由使用不同中间件或响应头。
- 同时存在多个 CSP 响应头。
- 仅生产环境启用 CSP。
- 需要分析浏览器 CSP violation report。

运行时 CSP 违规日志分析、Electron 和移动端 WebView 不属于当前版本的范围。

## 开发与测试

运行全部测试：

```bash
python3 -B -m unittest discover -s csp-scanner/tests -v
```

如果本机安装了 Codex 的 `skill-creator`，可以校验 Skill 结构：

```bash
python3 "${CODEX_HOME:-$HOME/.codex}/skills/.system/skill-creator/scripts/quick_validate.py" \
  csp-scanner
```

当前自动化测试覆盖：

- 至少五类典型 CSP 风险识别。
- 完全没有 CSP 时的明确提示。
- 无法解析的框架配置保守处理。
- 修复预览不修改源文件。
- 应用修复时创建备份并保留人工处理项。
- 拒绝使用已经过期的扫描报告。

## 兼容性状态

| 环境 | 状态 |
|---|---|
| Agent Skills 基础格式 | 已通过 `quick_validate.py` |
| Codex `.agents/skills/` 发现 | 已在本机验证 |
| OpenCode `.agents/skills/` 规范 | 官方文档确认；建议在目标版本复测 |
| Claude Code | 提供 `.claude/skills/` 复制或符号链接方案 |

## License

当前项目尚未指定许可证。对外分发前请根据团队或组织要求补充许可证文件。
