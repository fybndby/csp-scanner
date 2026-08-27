from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCAN = SKILL_ROOT / "scripts" / "scan_csp.py"
FIX = SKILL_ROOT / "scripts" / "fix_csp.py"


def run_cli(*args: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-B", *(str(arg) for arg in args)],
        check=False,
        capture_output=True,
        text=True,
    )


class CspScannerCliTest(unittest.TestCase):
    def test_scan_finds_five_common_risk_classes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            source = project / "server.js"
            source.write_text(
                "res.setHeader(\"Content-Security-Policy\", "
                "\"default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval'; base-uri *\");\n",
                encoding="utf-8",
            )

            result = run_cli(SCAN, project, "--format", "json")

            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            rules = {item["rule"] for item in report["findings"]}
            self.assertTrue(report["detected"])
            self.assertTrue(report["enforcing_detected"])
            self.assertTrue(
                {
                    "unsafe-inline",
                    "unsafe-eval",
                    "wildcard-source",
                    "missing-object-src",
                    "missing-frame-ancestors",
                    "weak-base-uri",
                }.issubset(rules)
            )

    def test_scan_reports_missing_configuration_explicitly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            (project / "index.html").write_text("<h1>Hello</h1>\n", encoding="utf-8")

            result = run_cli(SCAN, project, "--no-write")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("未检测到 CSP 配置", result.stdout)
            self.assertFalse((project / ".csp-scan-report.json").exists())

    def test_framework_marker_is_detected_but_not_claimed_as_enforcing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            (project / "app.js").write_text(
                "app.use(helmet({ contentSecurityPolicy: buildPolicyFromEnv() }));\n",
                encoding="utf-8",
            )

            result = run_cli(SCAN, project, "--format", "json", "--no-write")

            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertTrue(report["detected"])
            self.assertFalse(report["enforcing_detected"])
            self.assertIn(
                "unparsed-configuration",
                {item["rule"] for item in report["findings"]},
            )

    def test_fix_preview_does_not_modify_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            source = project / "nginx.conf"
            original = "add_header Content-Security-Policy \"default-src 'self'; base-uri 'self';\";\n"
            source.write_text(original, encoding="utf-8")
            scan = run_cli(SCAN, project)
            self.assertEqual(scan.returncode, 0, scan.stderr)

            result = run_cli(FIX, "--report", project / ".csp-scan-report.json")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("+add_header Content-Security-Policy", result.stdout)
            self.assertIn("object-src 'none'", result.stdout)
            self.assertIn("预览模式：未修改任何源文件", result.stdout)
            self.assertEqual(source.read_text(encoding="utf-8"), original)
            self.assertFalse((project / "nginx.conf.bak").exists())

    def test_fix_apply_changes_only_deterministic_finding_and_backs_up(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            source = project / "_headers"
            original = "/*\n  Content-Security-Policy: default-src *; script-src 'unsafe-inline'; base-uri 'self';\n"
            source.write_text(original, encoding="utf-8")
            scan = run_cli(SCAN, project)
            self.assertEqual(scan.returncode, 0, scan.stderr)

            result = run_cli(
                FIX,
                "--report",
                project / ".csp-scan-report.json",
                "--apply",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            updated = source.read_text(encoding="utf-8")
            self.assertIn("object-src 'none'", updated)
            self.assertIn("default-src *", updated)
            self.assertIn("'unsafe-inline'", updated)
            self.assertEqual(
                (project / "_headers.bak").read_text(encoding="utf-8"),
                original,
            )
            self.assertIn("需人工确认", result.stdout)

    def test_fix_refuses_a_stale_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            source = project / "vercel.json"
            source.write_text(
                '{"headers":[{"key":"Content-Security-Policy","value":"default-src \'self\';"}]}\n',
                encoding="utf-8",
            )
            scan = run_cli(SCAN, project)
            self.assertEqual(scan.returncode, 0, scan.stderr)
            source.write_text("{}\n", encoding="utf-8")

            result = run_cli(FIX, "--report", project / ".csp-scan-report.json", "--apply")

            self.assertEqual(result.returncode, 2)
            self.assertIn("stale report", result.stderr)
            self.assertFalse((project / "vercel.json.bak").exists())


if __name__ == "__main__":
    unittest.main()
