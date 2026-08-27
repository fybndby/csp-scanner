#!/usr/bin/env python3
"""Preview or apply deterministic fixes from a CSP scanner JSON report."""

from __future__ import annotations

import argparse
import difflib
import json
import shutil
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SUPPORTED_SCHEMA_VERSION = 1


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Preview or apply safe CSP fixes")
    parser.add_argument(
        "--report",
        default=".csp-scan-report.json",
        help="scanner JSON report",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="write deterministic changes after creating backups",
    )
    parser.add_argument(
        "--only",
        choices=("high", "medium", "low"),
        help="include only findings of exactly this severity",
    )
    parser.add_argument(
        "--diff-output",
        help="optional path for the combined unified diff",
    )
    return parser.parse_args(argv)


def load_report(path: Path) -> dict[str, Any]:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"report not found: {path}; run /csp-scan first") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read report {path}: {exc}") from exc
    if report.get("schema_version") != SUPPORTED_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported report schema: {report.get('schema_version')!r}; re-run the bundled scanner"
        )
    if not isinstance(report.get("root"), str):
        raise ValueError("report is missing its project root")
    return report


def append_object_src_none(policy: str) -> str:
    leading = policy[: len(policy) - len(policy.lstrip())]
    trailing = policy[len(policy.rstrip()) :]
    core = policy.strip()
    if not core:
        raise ValueError("cannot edit an empty policy")
    separator = " " if core.endswith(";") else "; "
    return f"{leading}{core}{separator}object-src 'none';{trailing}"


def backup_path(path: Path) -> Path:
    simple = path.with_name(path.name + ".bak")
    if not simple.exists():
        return simple
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    candidate = path.with_name(path.name + f".bak.{stamp}")
    suffix = 1
    while candidate.exists():
        candidate = path.with_name(path.name + f".bak.{stamp}.{suffix}")
        suffix += 1
    return candidate


def selected_findings(report: dict[str, Any], severity: str | None) -> list[dict[str, Any]]:
    findings = report.get("findings", [])
    if severity is None:
        return list(findings)
    return [item for item in findings if item.get("severity") == severity]


def build_plan(
    report: dict[str, Any], severity: str | None
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    configurations = {
        item["id"]: item for item in report.get("configurations", []) if "id" in item
    }
    automatic_by_file: dict[str, list[dict[str, Any]]] = defaultdict(list)
    manual: list[dict[str, Any]] = []

    for item in selected_findings(report, severity):
        auto_fix = item.get("auto_fix")
        config = configurations.get(item.get("configuration_id"))
        if auto_fix != "add-object-src-none" or config is None:
            manual.append(item)
            continue
        if not config.get("enforcing") or not config.get("editable_literal"):
            manual.append(item)
            continue
        if not isinstance(config.get("policy"), str):
            manual.append(item)
            continue
        automatic_by_file[config["file"]].append(
            {
                "finding": item,
                "configuration": config,
                "replacement": append_object_src_none(config["policy"]),
            }
        )
    return dict(automatic_by_file), manual


def make_changes(
    root: Path, automatic_by_file: dict[str, list[dict[str, Any]]]
) -> tuple[dict[Path, tuple[str, str]], list[str]]:
    changes: dict[Path, tuple[str, str]] = {}
    reasons: list[str] = []

    for relative_path, edits in sorted(automatic_by_file.items()):
        path = (root / relative_path).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"report points outside project root: {relative_path}") from exc
        try:
            original = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(f"cannot read source file {path}: {exc}") from exc

        updated = original
        seen_spans: set[tuple[int, int]] = set()
        ordered = sorted(
            edits,
            key=lambda edit: edit["configuration"]["span"]["start"],
            reverse=True,
        )
        for edit in ordered:
            config = edit["configuration"]
            start = config["span"]["start"]
            end = config["span"]["end"]
            span = (start, end)
            if span in seen_spans:
                continue
            seen_spans.add(span)
            if not isinstance(start, int) or not isinstance(end, int) or start < 0 or end < start:
                raise ValueError(f"invalid source span in report for {relative_path}")
            expected = config["policy"]
            if updated[start:end] != expected:
                raise ValueError(
                    f"stale report for {relative_path}:{config['line']}; re-run /csp-scan"
                )
            updated = updated[:start] + edit["replacement"] + updated[end:]
            reasons.append(
                f"{relative_path}:{config['line']} — 补充 object-src 'none'，阻止插件内容继承宽泛来源。"
            )
        if updated != original:
            changes[path] = (original, updated)
    return changes, reasons


def unified_diff(path: Path, root: Path, original: str, updated: str) -> str:
    relative = path.relative_to(root).as_posix()
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            updated.splitlines(keepends=True),
            fromfile=f"a/{relative}",
            tofile=f"b/{relative}",
        )
    )


def render_manual(manual: list[dict[str, Any]]) -> str:
    if not manual:
        return "需人工确认：无"
    lines = ["需人工确认："]
    for item in manual:
        lines.append(
            "- {file}:{line} [{severity}] {message} 建议：{hint}".format(
                file=item.get("file", "?"),
                line=item.get("line", "?"),
                severity=item.get("severity", "?"),
                message=item.get("message", item.get("rule", "unknown finding")),
                hint=item.get("fix_hint", "检查上下文后决定"),
            )
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report_path = Path(args.report).expanduser().resolve()
    try:
        report = load_report(report_path)
        root = Path(report["root"]).expanduser().resolve()
        if not root.is_dir():
            raise ValueError(f"project root from report is not a directory: {root}")
        automatic_by_file, manual = build_plan(report, args.only)
        changes, reasons = make_changes(root, automatic_by_file)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    diffs = [
        unified_diff(path, root, original, updated)
        for path, (original, updated) in sorted(changes.items(), key=lambda pair: str(pair[0]))
    ]
    combined_diff = "".join(diffs)

    print("# CSP 修复预览" if not args.apply else "# CSP 修复应用")
    print()
    if combined_diff:
        print(combined_diff, end="" if combined_diff.endswith("\n") else "\n")
    else:
        print("没有可确定性自动修改的项目。")

    if reasons:
        print("\n改动原因：")
        for reason in reasons:
            print(f"- {reason}")
    print()
    print(render_manual(manual))

    if args.diff_output:
        diff_path = Path(args.diff_output).expanduser()
        if not diff_path.is_absolute():
            diff_path = Path.cwd() / diff_path
        diff_path.parent.mkdir(parents=True, exist_ok=True)
        diff_path.write_text(combined_diff, encoding="utf-8")

    if args.apply and changes:
        backups: list[tuple[Path, Path]] = []
        attempted: list[tuple[Path, Path]] = []
        try:
            # Validate every target before the first source write so a stale
            # later file cannot cause a predictable partial application.
            for path, (original, _updated) in changes.items():
                if path.read_text(encoding="utf-8") != original:
                    raise ValueError(f"source changed during apply: {path}; no files written")
            for path, (original, updated) in changes.items():
                backup = backup_path(path)
                shutil.copy2(path, backup)
                backups.append((path, backup))

            for path, (_original, updated) in changes.items():
                backup = next(saved for target, saved in backups if target == path)
                attempted.append((path, backup))
                path.write_text(updated, encoding="utf-8")
        except (OSError, ValueError) as exc:
            rollback_errors: list[str] = []
            for path, backup in reversed(attempted):
                try:
                    shutil.copy2(backup, path)
                except OSError as rollback_exc:
                    rollback_errors.append(f"{path}: {rollback_exc}")
            print(f"error: apply failed: {exc}", file=sys.stderr)
            if rollback_errors:
                print(
                    "error: rollback also failed for " + "; ".join(rollback_errors),
                    file=sys.stderr,
                )
            return 2
        print("\n已应用：")
        for path, backup in backups:
            print(f"- {path.relative_to(root)}（备份：{backup.name}）")
        print("请重新运行 /csp-scan 验证结果。")
    elif not args.apply:
        print("\n预览模式：未修改任何源文件。使用 --apply 需明确授权。")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
