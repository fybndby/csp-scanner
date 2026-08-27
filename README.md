# CSP Scanner Skill

用于扫描和修复项目中 Content Security Policy（CSP）安全问题的 Agent Skill，支持 Codex、Claude Code 和 OpenCode。

## 功能

- 扫描项目中的 CSP 响应头、HTML Meta 标签和部署配置。
- 检测 `unsafe-inline`、`unsafe-eval`、裸 `*` 等危险配置。
- 检测缺失的 `object-src`、`frame-ancestors` 和 `base-uri`。
- 输出包含文件、行号、风险等级和修复建议的扫描报告。
- 默认预览修复 diff，不直接修改源码。
- 应用确定性修复前自动创建备份；不确定的改动会保留给人工确认。

## 安装

进入需要使用该 Skill 的项目：

```bash
cd <你的项目目录>
```

运行安装命令：

```bash
npx skills@latest add fybndby/csp-scanner
```

根据提示选择 `csp-scanner`，再选择需要安装到的 Agent。

如果安装选项中没有显示 Codex 或 OpenCode，可以直接指定这两个 Agent：

```bash
npx skills@latest add fybndby/csp-scanner \
  --skill csp-scanner \
  --agent codex \
  --agent opencode \
  --yes
```

Codex 和 OpenCode 的项目级 Skill 都安装在：

```text
.agents/skills/csp-scanner/
```

因此只需要一份文件，两个 Agent 都可以使用。

全局安装时添加 `--global`：

```bash
npx skills@latest add fybndby/csp-scanner \
  --skill csp-scanner \
  --agent codex \
  --agent opencode \
  --global \
  --yes
```

安装完成后，请重新启动对应的 Agent。

## 使用

在 Agent 中输入：

```text
使用 $csp-scanner 扫描这个项目的 CSP 问题
```

也可以直接使用自然语言：

```text
扫描一下这个项目的 CSP 问题
```

扫描完成后预览修复：

```text
使用 $csp-scanner，根据扫描结果预览 CSP 修复
```

明确应用确定性修复：

```text
使用 $csp-scanner，应用扫描结果中的确定性 CSP 修复
```

扫描报告默认保存在项目根目录：

```text
.csp-scan-report.json
```
