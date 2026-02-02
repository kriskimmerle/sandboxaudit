"""Tests for sandboxaudit."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sandboxaudit import (
    Finding,
    ScanResult,
    Severity,
    check_container_detection,
    check_credentials,
    check_docker_socket,
    check_filesystem_boundaries,
    check_git_config,
    check_network_access,
    check_resource_limits,
    check_shell_history,
    check_ssh_keys,
    check_user_privileges,
    check_process_visibility,
    format_json,
    format_text,
    scan_environment,
)


# ── Severity and Finding ───────────────────────────────────────────

class TestSeverity:
    def test_scores(self):
        assert Severity.CRITICAL.score == 25
        assert Severity.HIGH.score == 15
        assert Severity.MEDIUM.score == 8
        assert Severity.LOW.score == 3
        assert Severity.INFO.score == 0


class TestFinding:
    def test_to_dict(self):
        f = Finding(
            rule_id="SA001",
            severity=Severity.CRITICAL,
            category="Identity",
            message="Running as root",
            evidence="uid=0",
            fix="Don't do that",
        )
        d = f.to_dict()
        assert d["rule_id"] == "SA001"
        assert d["severity"] == "CRITICAL"
        assert d["category"] == "Identity"
        assert d["evidence"] == "uid=0"
        assert d["fix"] == "Don't do that"

    def test_to_dict_optional_fields(self):
        f = Finding(
            rule_id="SA001",
            severity=Severity.LOW,
            category="Test",
            message="Test",
        )
        d = f.to_dict()
        assert "evidence" not in d
        assert "fix" not in d


class TestScanResult:
    def test_empty_result(self):
        r = ScanResult()
        assert r.risk_score == 0
        assert r.grade == "A+"
        assert r.risk_label == "SAFE"

    def test_risk_score_caps_at_100(self):
        r = ScanResult(
            findings=[
                Finding("SA001", Severity.CRITICAL, "Test", "x"),
                Finding("SA002", Severity.CRITICAL, "Test", "x"),
                Finding("SA003", Severity.CRITICAL, "Test", "x"),
                Finding("SA004", Severity.CRITICAL, "Test", "x"),
                Finding("SA005", Severity.CRITICAL, "Test", "x"),
            ]
        )
        assert r.risk_score == 100

    def test_grades(self):
        for count, expected in [(0, "A+"), (1, "B"), (2, "D")]:
            findings = [Finding("T", Severity.MEDIUM, "Test", "x")] * count
            r = ScanResult(findings=findings)
            if count == 0:
                assert r.grade == "A+"
            elif count == 1:
                assert r.grade in ("A", "B")  # score=8
            elif count == 2:
                assert r.grade in ("B", "C")  # score=16


# ── Check: User Privileges ─────────────────────────────────────────

class TestCheckUserPrivileges:
    def test_non_root(self):
        result = ScanResult()
        # On CI/test, we shouldn't be root
        if os.getuid() != 0:
            check_user_privileges(result)
            assert result.checks_run == 1
            # May or may not have sudo finding, but shouldn't have root finding
            root_findings = [f for f in result.findings if "Running as root" in f.message]
            assert len(root_findings) == 0


# ── Check: Credentials ─────────────────────────────────────────────

class TestCheckCredentials:
    def test_detects_env_secrets(self):
        result = ScanResult()
        with patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "fakesecret123"}):
            check_credentials(result)
        aws_findings = [f for f in result.findings if "AWS" in f.message]
        assert len(aws_findings) >= 1
        assert aws_findings[0].severity == Severity.CRITICAL

    def test_ignores_empty_values(self):
        result = ScanResult()
        with patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": ""}):
            check_credentials(result)
        aws_findings = [f for f in result.findings if "AWS" in f.message]
        assert len(aws_findings) == 0

    def test_ignores_none_values(self):
        result = ScanResult()
        with patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "none"}):
            check_credentials(result)
        aws_findings = [f for f in result.findings if "AWS" in f.message]
        assert len(aws_findings) == 0


# ── Check: SSH Keys ─────────────────────────────────────────────────

class TestCheckSSHKeys:
    def test_ssh_agent_detection(self):
        result = ScanResult()
        with patch.dict(os.environ, {"SSH_AUTH_SOCK": "/tmp/ssh-agent.sock"}):
            check_ssh_keys(result)
        agent_findings = [f for f in result.findings if "SSH agent" in f.message]
        assert len(agent_findings) >= 1

    def test_no_ssh_agent(self):
        result = ScanResult()
        env = os.environ.copy()
        env.pop("SSH_AUTH_SOCK", None)
        with patch.dict(os.environ, env, clear=True):
            check_ssh_keys(result)
        agent_findings = [f for f in result.findings if "SSH agent" in f.message]
        assert len(agent_findings) == 0


# ── Check: Container Detection ──────────────────────────────────────

class TestCheckContainerDetection:
    def test_runs(self):
        result = ScanResult()
        check_container_detection(result)
        assert result.checks_run == 1
        assert len(result.findings) >= 1  # Should detect container or not-in-container


# ── Check: Network Access ───────────────────────────────────────────

class TestCheckNetworkAccess:
    def test_runs(self):
        result = ScanResult()
        check_network_access(result)
        assert result.checks_run == 1


# ── Check: Git Config ───────────────────────────────────────────────

class TestCheckGitConfig:
    def test_runs(self):
        result = ScanResult()
        check_git_config(result)
        assert result.checks_run == 1


# ── Check: Shell History ────────────────────────────────────────────

class TestCheckShellHistory:
    def test_runs(self):
        result = ScanResult()
        check_shell_history(result)
        assert result.checks_run == 1


# ── Check: Process Visibility ───────────────────────────────────────

class TestCheckProcessVisibility:
    def test_runs(self):
        result = ScanResult()
        check_process_visibility(result)
        assert result.checks_run == 1


# ── Output Formatting ───────────────────────────────────────────────

class TestFormatText:
    def test_clean_output(self):
        result = ScanResult(checks_run=5, platform_info="Test")
        out = format_text(result, color=False)
        assert "sandboxaudit" in out
        assert "A+" in out
        assert "SAFE" in out
        assert "✓" in out

    def test_findings_output(self):
        result = ScanResult(
            findings=[Finding("SA001", Severity.CRITICAL, "Identity", "Root!")],
            checks_run=1,
            platform_info="Test",
        )
        out = format_text(result, color=False)
        assert "SA001" in out
        assert "Root!" in out
        assert "CRITICAL" in out

    def test_verbose_shows_info(self):
        result = ScanResult(
            findings=[Finding("SA008", Severity.INFO, "Isolation", "In Docker")],
            checks_run=1,
        )
        out = format_text(result, verbose=True, color=False)
        assert "In Docker" in out


class TestFormatJSON:
    def test_valid_json(self):
        result = ScanResult(
            findings=[Finding("SA001", Severity.CRITICAL, "Identity", "Root!", "uid=0")],
            checks_run=1,
            platform_info="Test",
        )
        out = format_json(result)
        data = json.loads(out)
        assert data["grade"] == "C"  # score=25 → grade C
        assert len(data["findings"]) == 1
        assert data["findings"][0]["rule_id"] == "SA001"

    def test_empty_json(self):
        result = ScanResult(checks_run=0, platform_info="Test")
        data = json.loads(format_json(result))
        assert data["grade"] == "A+"
        assert data["findings"] == []


# ── Full Scan ───────────────────────────────────────────────────────

class TestFullScan:
    def test_scan_completes(self):
        result = scan_environment()
        assert result.checks_run == 11
        assert result.platform_info != ""

    def test_scan_grade_is_valid(self):
        result = scan_environment()
        assert result.grade in ("A+", "A", "B", "C", "D", "F")


# ── CLI ─────────────────────────────────────────────────────────────

class TestCLI:
    def test_version(self):
        r = subprocess.run(
            [sys.executable, "sandboxaudit.py", "--version"],
            capture_output=True, text=True,
            cwd=str(Path(__file__).resolve().parent.parent),
        )
        assert "0.1.0" in r.stdout

    def test_rules(self):
        r = subprocess.run(
            [sys.executable, "sandboxaudit.py", "--rules"],
            capture_output=True, text=True,
            cwd=str(Path(__file__).resolve().parent.parent),
        )
        assert r.returncode == 0
        assert "SA001" in r.stdout
        assert "SA011" in r.stdout

    def test_json_output(self):
        r = subprocess.run(
            [sys.executable, "sandboxaudit.py", "--json"],
            capture_output=True, text=True,
            cwd=str(Path(__file__).resolve().parent.parent),
        )
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert "grade" in data
        assert "findings" in data

    def test_ci_mode(self):
        r = subprocess.run(
            [sys.executable, "sandboxaudit.py", "--ci"],
            capture_output=True, text=True,
            cwd=str(Path(__file__).resolve().parent.parent),
        )
        # Should return non-zero if there are findings (likely in any real env)
        # Just verify it doesn't crash
        assert r.returncode in (0, 1, 2)
