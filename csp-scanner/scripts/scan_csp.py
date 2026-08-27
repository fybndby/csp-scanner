#!/usr/bin/env python3
"""Static Content Security Policy configuration scanner.

The scanner intentionally uses only the Python standard library. It extracts
literal policies deterministically and marks computed/framework configuration
for manual review instead of pretending it was parsed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = 2
MAX_FILE_BYTES = 2 * 1024 * 1024
REPORT_NAME = ".csp-scan-report.json"

TEXT_SUFFIXES = {
    ".cjs",
    ".conf",
    ".cs",
    ".ejs",
    ".erb",
    ".go",
    ".h",
    ".hbs",
    ".htm",
    ".html",
    ".htaccess",
    ".java",
    ".jinja",
    ".jinja2",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".mjs",
    ".php",
    ".properties",
    ".py",
    ".rb",
    ".rs",
    ".svelte",
    ".tf",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".vue",
    ".xml",
    ".yaml",
    ".yml",
}

SPECIAL_NAMES = {
    ".htaccess",
    "_headers",
    "apache2.conf",
    "httpd.conf",
    "netlify.toml",
    "nginx.conf",
    "vercel.json",
}

SKIP_DIRS = {
    ".cache",
    ".git",
    ".hg",
    ".idea",
    ".next",
    ".nuxt",
    ".pytest_cache",
    ".svn",
    ".turbo",
    ".venv",
    ".vscode",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "target",
    "vendor",
    "venv",
}

DIRECTIVE_NAME = re.compile(r"^[a-z][a-z0-9-]*$")
POLICY_SHAPE = re.compile(
    r"(?:^|;)\s*(?:default-src|script-src|style-src|img-src|connect-src|font-src|"
    r"object-src|frame-ancestors|base-uri|form-action)\b",
    re.IGNORECASE,
)

META_TAG = re.compile(
    r"<meta\b[^>]*http-equiv\s*=\s*(['\"])Content-Security-Policy(?:-Report-Only)?\1[^>]*>",
    re.IGNORECASE | re.DOTALL,
)
CONTENT_ATTR = re.compile(
    r"\bcontent\s*=\s*(?P<quote>['\"])(?P<policy>.*?)(?P=quote)",
    re.IGNORECASE | re.DOTALL,
)

LITERAL_PATTERNS = (
    (
        "header",
        re.compile(
            r"(?P<keyquote>['\"]?)"
            r"(?P<header>Content-Security-Policy(?P<report_only>-Report-Only)?)"
            r"(?P=keyquote)\s*[:,=]\s*"
            r"(?P<quote>['\"`])(?P<policy>.{1,8192}?)(?P=quote)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "header-object",
        re.compile(
            r"(?P<propquote>['\"]?)key(?P=propquote)\s*:\s*(?P<keyquote>['\"])"
            r"(?P<header>Content-Security-Policy(?P<report_only>-Report-Only)?)"
            r"(?P=keyquote)\s*,\s*(?P<valuequote>['\"]?)value(?P=valuequote)\s*:\s*"
            r"(?P<quote>['\"`])(?P<policy>.{1,8192}?)(?P=quote)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "nginx",
        re.compile(
            r"\badd_header\s+"
            r"(?P<header>Content-Security-Policy(?P<report_only>-Report-Only)?)\s+"
            r"(?P<quote>['\"])(?P<policy>.{1,8192}?)(?P=quote)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "apache",
        re.compile(
            r"\bHeader\s+(?:always\s+)?set\s+"
            r"(?P<header>Content-Security-Policy(?P<report_only>-Report-Only)?)\s+"
            r"(?P<quote>['\"])(?P<policy>.{1,8192}?)(?P=quote)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
)

FRAMEWORK_MARKER = re.compile(
    r"\b(?:contentSecurityPolicy|content_security_policy|securityHeaders)\b|"
    r"\bhelmet\s*\(",
    re.IGNORECASE,
)

BUILD_CONFIG_TOOL = re.compile(
    r"^(?P<tool>webpack|vite|rspack)(?:\.[^.]+)*\.config(?:\.[^.]+)*\.(?:c|m)?(?:j|t)s$",
    re.IGNORECASE,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan a project for CSP risks")
    parser.add_argument("path", nargs="?", default=".", help="project root to scan")
    parser.add_argument(
        "--output",
        default=REPORT_NAME,
        help=f"JSON report path (default: <root>/{REPORT_NAME})",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json", "both"),
        default="markdown",
        help="terminal output format; JSON is still written unless --no-write is used",
    )
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="do not create the JSON report artifact",
    )
    parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=MAX_FILE_BYTES,
        help="skip larger files",
    )
    return parser.parse_args(argv)


def candidate_files(root: Path, max_file_bytes: int) -> Iterable[Path]:
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for filename in sorted(filenames):
            if filename == REPORT_NAME or filename.endswith((".bak", ".pyc")):
                continue
            path = Path(current) / filename
            if path.is_symlink():
                continue
            if filename not in SPECIAL_NAMES and path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            try:
                if path.stat().st_size > max_file_bytes:
                    continue
            except OSError:
                continue
            yield path


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def line_snippet(text: str, offset: int, limit: int = 240) -> str:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end == -1:
        end = len(text)
    snippet = " ".join(text[start:end].strip().split())
    return snippet[:limit] + ("…" if len(snippet) > limit else "")


def config_id(relative_path: str, start: int, policy: str | None) -> str:
    material = f"{relative_path}:{start}:{policy or ''}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:16]


def parse_directives(policy: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    normalized = policy.replace("\\\n", " ").replace("\r", " ").replace("\n", " ")
    for part in normalized.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if not DIRECTIVE_NAME.fullmatch(name):
            continue
        # Browsers use the first occurrence of a duplicate directive.
        directives.setdefault(name, tokens[1:])
    return directives


def looks_like_policy(policy: str) -> bool:
    return bool(POLICY_SHAPE.search(policy))


def inside_named_object(text: str, offset: int, name: str) -> bool:
    """Best-effort check that offset is inside a literal `name: { ... }` object."""
    pattern = re.compile(rf"\b{re.escape(name)}\s*:\s*\{{")
    for match in reversed(list(pattern.finditer(text, 0, offset))):
        segment = text[match.end() : offset]
        if segment.count("{") >= segment.count("}"):
            return True
    return False


def classify_literal_delivery(
    relative_path: str,
    text: str,
    offset: int,
    default_source_kind: str,
) -> tuple[str, str, bool]:
    """Return source kind, delivery environment, and production candidacy."""
    filename = Path(relative_path).name
    match = BUILD_CONFIG_TOOL.match(filename)
    if not match:
        if default_source_kind in {"nginx", "apache"}:
            return default_source_kind, "production", True
        if filename in {"vercel.json", "netlify.toml", "_headers"}:
            return "static-headers", "production", True
        return default_source_kind, "runtime", True

    tool = match.group("tool").lower()
    if tool in {"webpack", "rspack"} and inside_named_object(text, offset, "devServer"):
        return f"{tool}-dev-server", "development", False
    if tool == "vite":
        if inside_named_object(text, offset, "preview"):
            return "vite-preview-server", "preview", False
        if inside_named_object(text, offset, "server"):
            return "vite-dev-server", "development", False
    return f"{tool}-config", "unknown", False


def make_configuration(
    *,
    relative_path: str,
    text: str,
    source_kind: str,
    policy: str | None,
    policy_start: int,
    policy_end: int,
    enforcing: bool,
    delivery: str = "runtime",
    production_candidate: bool = True,
) -> dict[str, Any]:
    return {
        "id": config_id(relative_path, policy_start, policy),
        "file": relative_path,
        "line": line_number(text, policy_start),
        "source_kind": source_kind,
        "delivery": delivery,
        "production_candidate": production_candidate,
        "enforcing": enforcing,
        "editable_literal": policy is not None,
        "snippet": line_snippet(text, policy_start),
        "policy": policy,
        "directives": parse_directives(policy) if policy is not None else {},
        "span": {"start": policy_start, "end": policy_end},
    }


def extract_configurations(relative_path: str, text: str) -> list[dict[str, Any]]:
    configurations: list[dict[str, Any]] = []
    occupied: set[tuple[int, int]] = set()

    for tag_match in META_TAG.finditer(text):
        tag = tag_match.group(0)
        content_match = CONTENT_ATTR.search(tag)
        if not content_match:
            continue
        policy = content_match.group("policy")
        if not looks_like_policy(policy):
            continue
        start = tag_match.start() + content_match.start("policy")
        end = tag_match.start() + content_match.end("policy")
        report_only = "report-only" in tag.lower()
        configurations.append(
            make_configuration(
                relative_path=relative_path,
                text=text,
                source_kind="meta",
                policy=policy,
                policy_start=start,
                policy_end=end,
                enforcing=not report_only,
                delivery="document",
                production_candidate=False,
            )
        )
        occupied.add((start, end))

    if Path(relative_path).name == "_headers":
        for match in re.finditer(
            r"(?im)^\s*Content-Security-Policy(?P<report_only>-Report-Only)?\s*:\s*(?P<policy>[^\r\n]+)",
            text,
        ):
            policy = match.group("policy").strip()
            if not looks_like_policy(policy):
                continue
            raw_start = match.start("policy")
            start = raw_start + len(match.group("policy")) - len(match.group("policy").lstrip())
            end = start + len(policy)
            if (start, end) in occupied:
                continue
            configurations.append(
                make_configuration(
                    relative_path=relative_path,
                    text=text,
                    source_kind="static-headers",
                    policy=policy,
                    policy_start=start,
                    policy_end=end,
                    enforcing=match.group("report_only") is None,
                    delivery="production",
                    production_candidate=True,
                )
            )
            occupied.add((start, end))

    for source_kind, pattern in LITERAL_PATTERNS:
        for match in pattern.finditer(text):
            policy = match.group("policy")
            if not looks_like_policy(policy):
                continue
            start, end = match.span("policy")
            if any(start == known_start and end == known_end for known_start, known_end in occupied):
                continue
            classified_kind, delivery, production_candidate = classify_literal_delivery(
                relative_path, text, start, source_kind
            )
            configurations.append(
                make_configuration(
                    relative_path=relative_path,
                    text=text,
                    source_kind=classified_kind,
                    policy=policy,
                    policy_start=start,
                    policy_end=end,
                    enforcing=match.groupdict().get("report_only") is None,
                    delivery=delivery,
                    production_candidate=production_candidate,
                )
            )
            occupied.add((start, end))

    parsed_spans = [
        (config["span"]["start"], config["span"]["end"])
        for config in configurations
    ]
    for marker in FRAMEWORK_MARKER.finditer(text):
        if any(start - 500 <= marker.start() <= end + 500 for start, end in parsed_spans):
            continue
        start, end = marker.span()
        configurations.append(
            make_configuration(
                relative_path=relative_path,
                text=text,
                source_kind="framework-marker",
                policy=None,
                policy_start=start,
                policy_end=end,
                enforcing=False,
                delivery="unknown",
                production_candidate=False,
            )
        )

    configurations.sort(key=lambda item: (item["line"], item["span"]["start"]))
    return configurations


def finding(
    config: dict[str, Any],
    rule: str,
    severity: str,
    message: str,
    fix_hint: str,
    *,
    auto_fix: str | None = None,
) -> dict[str, Any]:
    detail = hashlib.sha256(message.encode("utf-8")).hexdigest()[:8]
    return {
        "id": f"{config['id']}:{rule}:{detail}",
        "configuration_id": config["id"],
        "file": config["file"],
        "line": config["line"],
        "rule": rule,
        "severity": severity,
        "message": message,
        "fix_hint": fix_hint,
        "requires_review": auto_fix is None,
        "auto_fix": auto_fix,
    }


def evaluate_configuration(config: dict[str, Any]) -> list[dict[str, Any]]:
    if config["policy"] is None:
        return [
            finding(
                config,
                "unparsed-configuration",
                "low",
                "检测到 CSP 相关配置点，但无法静态解析完整策略。",
                "检查此框架配置、变量拼接或生成逻辑中的实际响应头。",
            )
        ]

    findings: list[dict[str, Any]] = []
    directives: dict[str, list[str]] = config["directives"]

    if config["delivery"] in {"development", "preview"}:
        environment = "开发服务器" if config["delivery"] == "development" else "预览服务器"
        findings.append(
            finding(
                config,
                "development-only-csp",
                "medium",
                f"该 CSP 仅配置在{environment}中，不能证明生产部署已启用防护。",
                "找到生产环境的服务器、反向代理、CDN 或托管平台，并以 HTTP 响应头发送经过验证的同等策略。",
            )
        )

    if not config["enforcing"]:
        findings.append(
            finding(
                config,
                "report-only",
                "low",
                "该策略为 Report-Only，不会阻止违规资源。",
                "确认同一路由还返回了有效的强制执行 CSP 响应头。",
            )
        )

    for directive, sources in directives.items():
        lowered = [source.lower() for source in sources]
        if "'unsafe-inline'" in lowered or "unsafe-inline" in lowered:
            severity = "medium" if directive.startswith("style-src") else "high"
            findings.append(
                finding(
                    config,
                    "unsafe-inline",
                    severity,
                    f"{directive} 允许 'unsafe-inline'。",
                    "优先外链化；否则按渲染架构使用逐响应 nonce 或稳定内容 hash。",
                )
            )
        if "'unsafe-eval'" in lowered or "unsafe-eval" in lowered:
            findings.append(
                finding(
                    config,
                    "unsafe-eval",
                    "high",
                    f"{directive} 允许 'unsafe-eval'。",
                    "定位依赖字符串求值的代码或构建模式，确认兼容性后移除。",
                )
            )
        if "*" in sources:
            findings.append(
                finding(
                    config,
                    "wildcard-source",
                    "high",
                    f"{directive} 使用了裸 * 通配符。",
                    "根据实际请求清单改为该指令所需的精确来源。",
                )
            )

    if "object-src" not in directives:
        findings.append(
            finding(
                config,
                "missing-object-src",
                "medium",
                "缺少显式 object-src 'none'。",
                "在当前策略末尾补充 object-src 'none'。",
                auto_fix=(
                    "add-object-src-none"
                    if config["enforcing"] and config["production_candidate"]
                    else None
                ),
            )
        )
    else:
        object_sources = [source.lower() for source in directives["object-src"]]
        if object_sources != ["'none'"] and object_sources != ["none"]:
            findings.append(
                finding(
                    config,
                    "object-src-not-none",
                    "high",
                    "object-src 未严格限制为 'none'。",
                    "确认不再使用插件内容后，将 object-src 收紧为 'none'。",
                )
            )

    if "frame-ancestors" not in directives:
        findings.append(
            finding(
                config,
                "missing-frame-ancestors",
                "medium",
                "缺少显式 frame-ancestors，页面嵌入边界不清晰。",
                "根据产品嵌入需求选择 'none'、'self' 或精确合作方来源，并通过响应头发送。",
            )
        )
    if config["source_kind"] == "meta":
        findings.append(
            finding(
                config,
                "meta-frame-ancestors",
                "high",
                "Meta CSP 无法执行 frame-ancestors 等仅限响应头的能力。",
                "在服务端、反向代理或托管平台响应头中设置 CSP。",
            )
        )

    if "base-uri" not in directives:
        findings.append(
            finding(
                config,
                "missing-base-uri",
                "medium",
                "缺少显式 base-uri 限制。",
                "确认页面的 <base> 用法后设置 base-uri 'self' 或 'none'。",
            )
        )
    else:
        base_sources = [source.lower() for source in directives["base-uri"]]
        acceptable = base_sources in (["'self'"], ["self"], ["'none'"], ["none"])
        if not acceptable:
            findings.append(
                finding(
                    config,
                    "weak-base-uri",
                    "high",
                    "base-uri 未限制为单一的 'self' 或 'none'。",
                    "确认合法 base URL 后收紧来源，不要猜测业务依赖。",
                )
            )

    if any(token in config["policy"] for token in ("${", "{{", "<%")):
        findings.append(
            finding(
                config,
                "unparsed-configuration",
                "low",
                "策略包含模板表达式，静态结果可能不完整。",
                "追踪模板变量在运行时展开后的最终策略。",
            )
        )

    return findings


def markdown_escape(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(report: dict[str, Any]) -> str:
    lines = ["# CSP 扫描报告", ""]
    if not report["detected"]:
        lines.extend(
            [
                "**未检测到 CSP 配置**",
                "",
                "这不是“零问题”：请在实际响应链路中确认是否由仓库外的 CDN 或网关注入 CSP。",
            ]
        )
        if report["build_tools"]:
            tools = "、".join(sorted({item["tool"] for item in report["build_tools"]}))
            lines.extend(
                [
                    "",
                    f"检测到构建工具：{tools}。其开发/预览服务器 headers 只能用于本地验证，生产 CSP 仍应配置在实际响应层。",
                ]
            )
        return "\n".join(lines)

    if not report["enforcing_detected"]:
        lines.extend(["**仅检测到非强制执行或无法确认的 CSP 配置。**", ""])
    elif not report["production_enforcing_detected"]:
        lines.extend(
            [
                "**仅检测到开发/预览、HTML Meta 或无法确认的 CSP；生产环境响应头未确认。**",
                "",
            ]
        )

    lines.extend(
        [
            "| 文件 | 行号 | 风险等级 | 问题描述 | 建议修复方式 |",
            "|---|---:|---|---|---|",
        ]
    )
    severity_label = {"high": "高", "medium": "中", "low": "低"}
    for item in report["findings"]:
        lines.append(
            "| {file} | {line} | {severity} | {message} | {hint} |".format(
                file=markdown_escape(item["file"]),
                line=item["line"],
                severity=severity_label[item["severity"]],
                message=markdown_escape(item["message"]),
                hint=markdown_escape(item["fix_hint"]),
            )
        )

    if not report["findings"]:
        lines.append("| — | — | — | 未发现内置规则覆盖的风险 | 仍需验证实际响应头和路由覆盖 |")

    summary = report["summary"]
    lines.extend(
        [
            "",
            f"配置点：{summary['configurations']}；高风险：{summary['high']}；中风险：{summary['medium']}；低风险：{summary['low']}。",
            "",
            "> 静态扫描未验证浏览器实际收到的响应头、CDN/代理覆盖或运行时违规报告。",
        ]
    )
    return "\n".join(lines)


def scan(root: Path, max_file_bytes: int = MAX_FILE_BYTES) -> dict[str, Any]:
    configurations: list[dict[str, Any]] = []
    build_tools: list[dict[str, str]] = []
    scanned_files = 0
    unreadable_files: list[str] = []

    for path in candidate_files(root, max_file_bytes):
        scanned_files += 1
        relative_path = path.relative_to(root).as_posix()
        build_match = BUILD_CONFIG_TOOL.match(path.name)
        if build_match:
            build_tools.append(
                {"tool": build_match.group("tool").lower(), "file": relative_path}
            )
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            unreadable_files.append(relative_path)
            continue
        configurations.extend(extract_configurations(relative_path, text))

    findings: list[dict[str, Any]] = []
    for config in configurations:
        findings.extend(evaluate_configuration(config))

    severity_order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(
        key=lambda item: (
            severity_order[item["severity"]],
            item["file"],
            item["line"],
            item["rule"],
        )
    )
    summary = {
        "files_scanned": scanned_files,
        "configurations": len(configurations),
        "production_configurations": sum(
            config["production_candidate"] is True for config in configurations
        ),
        "development_configurations": sum(
            config["delivery"] in {"development", "preview"} for config in configurations
        ),
        "high": sum(item["severity"] == "high" for item in findings),
        "medium": sum(item["severity"] == "medium" for item in findings),
        "low": sum(item["severity"] == "low" for item in findings),
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": str(root),
        "detected": bool(configurations),
        "enforcing_detected": any(config["enforcing"] is True for config in configurations),
        "production_enforcing_detected": any(
            config["enforcing"] is True and config["production_candidate"] is True
            for config in configurations
        ),
        "build_tools": build_tools,
        "configurations": configurations,
        "findings": findings,
        "summary": summary,
        "unreadable_files": unreadable_files,
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        print(f"error: scan path is not a directory: {root}", file=sys.stderr)
        return 2
    if args.max_file_bytes <= 0:
        print("error: --max-file-bytes must be positive", file=sys.stderr)
        return 2

    report = scan(root, args.max_file_bytes)
    if not args.no_write:
        output = Path(args.output).expanduser()
        if not output.is_absolute():
            output = root / output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    if args.format in ("markdown", "both"):
        print(render_markdown(report))
    if args.format == "both":
        print("\n---\n")
    if args.format in ("json", "both"):
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
