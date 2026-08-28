# CSP Scanner Skill

用于扫描和修复项目中 Content Security Policy（CSP）安全问题的 Agent Skill，支持 Codex、Claude Code 和 OpenCode。

## 功能

- 扫描 CSP 响应头、HTML Meta、部署配置及 Webpack、Vite、Rspack 配置，并区分开发/预览与生产环境。
- 检测 `unsafe-inline`、`unsafe-eval`、裸 `*` 等危险配置。
- 检测缺失的 `object-src`、`frame-ancestors` 和 `base-uri`。
- 输出包含文件、行号、风险等级和修复建议的扫描报告。
- 修复请求默认直接应用确定性改动，并输出 diff 供人工审核；也支持预览模式。
- 应用确定性修复后输出 diff 供人工审核；不确定的改动会保留给人工确认，不创建额外备份文件。

## 可检测的问题

| 检测规则 | 问题 | 默认风险等级 |
|---|---|---|
| `unsafe-inline` | 使用 `'unsafe-inline'`，允许内联脚本、事件或样式 | 脚本高风险，样式中风险 |
| `unsafe-eval` | 使用 `'unsafe-eval'`，允许 `eval()`、`Function()` 等动态执行 | 高风险 |
| `wildcard-source` | CSP 指令中使用裸 `*` | 高风险 |
| `missing-object-src` | 缺少显式的 `object-src 'none'` | 中风险 |
| `object-src-not-none` | `object-src` 允许了 `'none'` 以外的来源 | 高风险 |
| `missing-frame-ancestors` | 缺少页面嵌入限制 | 中风险 |
| `missing-base-uri` | 缺少 `<base>` 地址限制 | 中风险 |
| `weak-base-uri` | `base-uri` 不是严格的 `'self'` 或 `'none'` | 高风险 |
| `meta-frame-ancestors` | CSP 写在 HTML Meta 中，无法执行 `frame-ancestors` | 高风险 |
| `development-only-csp` | CSP 只存在于 Webpack、Vite 或 Rspack 开发/预览服务器 | 中风险 |
| `report-only` | 只有 Report-Only 策略，不会真正阻止违规资源 | 低风险 |
| `unparsed-configuration` | CSP 通过变量、模板或框架动态生成，无法静态确认 | 低风险 |

Skill 还会识别以下配置状态：

- 项目中未检测到 CSP 配置。
- 只有 HTML Meta CSP，未确认生产 HTTP 响应头。
- 只有开发或预览环境 CSP，未确认生产环境 CSP。
- Webpack/Rspack `devServer.headers`。
- Vite `server.headers` 和 `preview.headers`。
- Nginx、Apache、`_headers`、Vercel 等部署配置。
- 常见服务端代码中的 `Content-Security-Policy` 响应头。
- 强制执行策略和 `Content-Security-Policy-Report-Only` 策略。

## 自动修复范围

当前只会自动处理能够确定安全的修改：为生产候选配置补充缺失的 `object-src 'none'`。

以下修改需要结合业务资源和部署方式判断，因此只提供建议，不会自动应用：

- 删除 `'unsafe-inline'` 或 `'unsafe-eval'`。
- 将 `*` 替换成具体来源。
- 决定 `frame-ancestors` 使用 `'none'`、`'self'` 还是合作方来源。
- 将 HTML Meta CSP 迁移到生产 HTTP 响应头。
- 添加 nonce、hash 或 `'strict-dynamic'`。

## 当前边界

这是静态配置扫描 Skill，暂时不会验证：

- `script-src`、`connect-src`、`img-src` 等具体来源是否符合业务需求。
- `https:`、`data:`、`blob:`、`*.example.com` 等来源是否过宽。
- `form-action`、`worker-src`、`media-src` 等更多指令是否缺失。
- nonce 是否随机、重复或硬编码，hash 是否匹配实际内容。
- 第三方脚本和样式是否配置 SRI 完整性校验。
- `innerHTML`、`document.write` 等 DOM XSS 危险代码。
- 浏览器在生产环境实际收到并执行的 CSP 响应头。

## CSP 应该配置在哪里

生产环境优先通过 HTTP 响应头发送 CSP，由实际返回页面的应用服务器、Nginx、网关、CDN 或静态托管平台配置。例如在 Nginx 中限制页面只能被同源页面嵌入：

```nginx
add_header Content-Security-Policy "frame-ancestors 'self';" always;
```

`frame-ancestors` 不能写在 HTML `<meta>` 中，浏览器会忽略它。如果项目已经存在 CSP，应把 `frame-ancestors` 合并进现有策略，不要随意创建互相冲突或重复的策略。例如：

```nginx
add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';" always;
```

`'self'` 表示允许同源页面嵌入。如果页面完全不允许被 iframe 嵌入，应根据业务确认后使用：

```text
frame-ancestors 'none';
```

Webpack/Rspack `devServer.headers`、Vite `server.headers` 和 `preview.headers` 只影响开发或本地预览服务器，不能代替生产环境的 Nginx、CDN 或应用服务器配置。

## 前端与服务端职责

前端代码可以完成：

- 移除内联脚本、内联事件和对 `eval()`、`Function()` 的依赖。
- 将脚本和样式迁移到受控的外部文件。
- 盘点页面实际需要的脚本、接口、图片、字体、iframe 和其他资源来源。
- 为稳定的内联脚本或样式维护 CSP hash。
- 为第三方脚本和样式添加 SRI `integrity` 校验。
- 配合服务端，把每个响应生成的 nonce 添加到对应的 `<script>` 或 `<style>` 标签。

以下能力不能只修改前端源码完成，需要服务端或部署平台配合：

- 通过生产 HTTP 响应头发送完整的 `Content-Security-Policy`。
- 使用 `frame-ancestors` 防止点击劫持；该指令不支持 HTML Meta。
- 使用 `Content-Security-Policy-Report-Only` 灰度验证策略和收集违规报告。
- 使用 `report-to`、`report-uri` 等 CSP 上报能力；HTML Meta 不提供等效能力。
- 使用 CSP `sandbox` 响应头能力；该指令在 HTML Meta CSP 中不生效。
- 为动态页面生成不可预测、每个响应唯一的 nonce，并同时写入 CSP Header 和页面标签。
- 确保所有生产页面、错误页和不同路由都返回一致且有效的 CSP Header。
- 防止 Nginx、网关或 CDN 覆盖、删除或重复添加 CSP Header。
- 配置 `X-Frame-Options`、HSTS 等其他 HTTP 安全响应头。
- 验证生产环境最终响应头以及 CDN、缓存和代理后的真实效果。

纯静态前端如果无法控制服务器响应头，可以使用托管平台提供的 `_headers`、`vercel.json` 或类似配置。HTML Meta CSP 只能作为无法控制响应头时的受限方案，不能提供完整 CSP 能力。

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

### 修复方式

`/csp-fix` 是 Skill 内定义的工作流名，不一定会被 Agent 注册成可直接输入的斜杠命令。默认会直接应用确定性的 CSP 修复，并输出 diff 供你人工审核。只有宿主支持自定义斜杠命令时，才可以直接使用：

```text
/csp-fix                         # 直接应用确定性修复，不创建备份
/csp-fix --preview               # 只预览修复 diff，不修改文件
/csp-fix --apply                 # 明确应用确定性修复，不创建备份
/csp-fix --only high             # 只应用 high 中的确定性修复
/csp-fix --only medium           # 只应用 medium 中的确定性修复
/csp-fix --only low              # 只应用 low 中的确定性修复
/csp-fix --apply --only medium   # 只应用中风险中的确定性修复
```

如果当前 Agent 只有 `$csp-scanner` 入口，请使用自然语言传达同样的参数：

```text
使用 $csp-scanner，直接修复 CSP 漏洞，然后输出 diff 供我人工审核
使用 $csp-scanner，只预览 CSP 修复，不要修改文件
使用 $csp-scanner，应用确定性的 CSP 修复，不要创建备份
使用 $csp-scanner，只修复 high 风险中的确定性 CSP 问题
使用 $csp-scanner，只修复 medium 风险中的确定性 CSP 问题
使用 $csp-scanner，只修复 low 风险中的确定性 CSP 问题
使用 $csp-scanner，只应用 medium 风险中的确定性 CSP 修复
```

涉及 `unsafe-inline`、通配符、nonce 和 `frame-ancestors` 等需要业务判断的问题，即使执行默认修复也不会强制修改，会保留给你人工审核。

扫描默认不在项目中生成报告文件。修复流程需要机器可读结果时，会使用项目目录之外的临时文件，并在流程结束后删除。
