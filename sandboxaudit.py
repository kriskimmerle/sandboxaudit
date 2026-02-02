#!/usr/bin/env python3
"""sandboxaudit - AI Agent Sandbox Security Auditor.

Runtime probe that audits whether an AI coding agent's execution environment
is properly isolated. Checks for exposed credentials, excessive permissions,
missing sandboxing, network access, filesystem boundaries, and more.

Run this inside your agent's sandbox to verify isolation before giving it
autonomous code execution privileges (e.g., Ralph Wiggum loops, Claude Code
with --dangerously-skip-permissions, Codex, etc.).

Maps to OWASP Top 10 for Agentic Applications 2026:
  ASI03 - Identity and Privilege Abuse
  ASI05 - Unexpected Code Execution

Zero dependencies. Stdlib only. Python 3.8+.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import socket
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

__version__ = "0.1.0"

# ── Severity ────────────────────────────────────────────────────────

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def score(self) -> int:
        return {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}[self.value]


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    category: str
    message: str
    evidence: str = ""
    fix: str = ""

    def to_dict(self) -> dict:
        d: dict = {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "category": self.category,
            "message": self.message,
        }
        if self.evidence:
            d["evidence"] = self.evidence
        if self.fix:
            d["fix"] = self.fix
        return d


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    checks_run: int = 0
    platform_info: str = ""

    @property
    def risk_score(self) -> int:
        return min(sum(f.severity.score for f in self.findings), 100)

    @property
    def grade(self) -> str:
        s = self.risk_score
        if s == 0: return "A+"
        elif s <= 10: return "A"
        elif s <= 20: return "B"
        elif s <= 35: return "C"
        elif s <= 50: return "D"
        else: return "F"

    @property
    def risk_label(self) -> str:
        s = self.risk_score
        if s == 0: return "SAFE"
        elif s <= 20: return "LOW"
        elif s <= 50: return "MODERATE"
        elif s <= 75: return "HIGH"
        else: return "CRITICAL"


def _run_cmd(cmd: List[str], timeout: int = 5) -> Tuple[int, str]:
    """Run a command and return (returncode, stdout)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return -1, ""


def _truncate(text: str, maxlen: int = 120) -> str:
    text = text.strip()
    return text[:maxlen - 3] + "..." if len(text) > maxlen else text


# ── Checks ──────────────────────────────────────────────────────────

def check_user_privileges(result: ScanResult) -> None:
    """SA001: Check if running as root or with elevated privileges."""
    result.checks_run += 1

    uid = os.getuid() if hasattr(os, "getuid") else -1
    euid = os.geteuid() if hasattr(os, "geteuid") else -1
    username = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))

    if uid == 0 or euid == 0:
        result.findings.append(Finding(
            rule_id="SA001",
            severity=Severity.CRITICAL,
            category="Identity",
            message="Running as root — agent has full system access",
            evidence=f"uid={uid} euid={euid} user={username}",
            fix="Run the agent as a non-root user with minimal privileges",
        ))
    else:
        # Check for sudo capability
        rc, _ = _run_cmd(["sudo", "-n", "true"])
        if rc == 0:
            result.findings.append(Finding(
                rule_id="SA001",
                severity=Severity.HIGH,
                category="Identity",
                message="Passwordless sudo available — agent can escalate to root",
                evidence=f"uid={uid} user={username}, sudo -n succeeds",
                fix="Remove agent user from sudoers or require password",
            ))


def check_credentials(result: ScanResult) -> None:
    """SA002: Check for exposed credentials in environment."""
    result.checks_run += 1

    # Patterns for sensitive environment variables
    secret_patterns = [
        (re.compile(r'(AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)', re.I), "AWS credentials"),
        (re.compile(r'(AZURE_CLIENT_SECRET|AZURE_TENANT_ID)', re.I), "Azure credentials"),
        (re.compile(r'(GCP_SERVICE_ACCOUNT|GOOGLE_APPLICATION_CREDENTIALS)', re.I), "GCP credentials"),
        (re.compile(r'(GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT)', re.I), "GitHub token"),
        (re.compile(r'(OPENAI_API_KEY|ANTHROPIC_API_KEY)', re.I), "AI provider API key"),
        (re.compile(r'(DATABASE_URL|DB_PASSWORD|MONGO_URI|REDIS_URL)', re.I), "Database credential"),
        (re.compile(r'(SLACK_TOKEN|SLACK_BOT_TOKEN|SLACK_WEBHOOK)', re.I), "Slack token"),
        (re.compile(r'(STRIPE_SECRET_KEY|STRIPE_API_KEY)', re.I), "Payment credential"),
        (re.compile(r'(NPM_TOKEN|PYPI_TOKEN|RUBYGEMS_API_KEY)', re.I), "Package registry token"),
        (re.compile(r'(SSH_AUTH_SOCK)', re.I), "SSH agent socket"),
        (re.compile(r'(DOCKER_HOST|DOCKER_TLS_VERIFY)', re.I), "Docker daemon access"),
        (re.compile(r'(KUBECONFIG)', re.I), "Kubernetes config"),
        (re.compile(r'(VAULT_TOKEN|VAULT_ADDR)', re.I), "HashiCorp Vault"),
        (re.compile(r'(SENDGRID_API_KEY|MAILGUN_API_KEY)', re.I), "Email service key"),
        (re.compile(r'(TWILIO_AUTH_TOKEN)', re.I), "Twilio credential"),
    ]

    exposed: List[Tuple[str, str]] = []
    for key in os.environ:
        for pattern, desc in secret_patterns:
            if pattern.match(key):
                val = os.environ[key]
                if val and val not in ("", "none", "null", "undefined"):
                    exposed.append((key, desc))
                break

    for key, desc in exposed:
        result.findings.append(Finding(
            rule_id="SA002",
            severity=Severity.CRITICAL,
            category="Credentials",
            message=f"Exposed credential: {desc}",
            evidence=f"{key}=****",
            fix=f"Remove {key} from agent environment or use scoped, short-lived tokens",
        ))

    # Also check for credential files
    cred_paths = [
        ("~/.aws/credentials", "AWS credentials file"),
        ("~/.aws/config", "AWS config"),
        ("~/.azure/accessTokens.json", "Azure tokens"),
        ("~/.config/gcloud/application_default_credentials.json", "GCP credentials"),
        ("~/.kube/config", "Kubernetes config"),
        ("~/.docker/config.json", "Docker config (may contain registry tokens)"),
        ("~/.npmrc", "npm config (may contain auth token)"),
        ("~/.pypirc", "PyPI config (may contain auth token)"),
        ("~/.git-credentials", "Git stored credentials"),
        ("~/.netrc", "netrc (may contain passwords)"),
        ("~/.vault-token", "Vault token file"),
    ]

    for path_str, desc in cred_paths:
        path = Path(os.path.expanduser(path_str))
        if path.exists():
            try:
                readable = os.access(str(path), os.R_OK)
                if readable:
                    result.findings.append(Finding(
                        rule_id="SA002",
                        severity=Severity.HIGH,
                        category="Credentials",
                        message=f"Credential file accessible: {desc}",
                        evidence=f"{path_str} (readable)",
                        fix=f"Mount agent environment without access to {path_str}",
                    ))
            except (OSError, PermissionError):
                pass


def check_ssh_keys(result: ScanResult) -> None:
    """SA003: Check for accessible SSH keys."""
    result.checks_run += 1

    ssh_dir = Path.home() / ".ssh"
    if not ssh_dir.is_dir():
        return

    key_files = []
    try:
        for item in ssh_dir.iterdir():
            if item.is_file() and not item.name.endswith(".pub") and not item.name == "known_hosts":
                try:
                    with open(item, "rb") as f:
                        header = f.read(40)
                    if b"PRIVATE KEY" in header or item.name.startswith("id_"):
                        key_files.append(item.name)
                except (OSError, PermissionError):
                    pass
    except (OSError, PermissionError):
        return

    if key_files:
        result.findings.append(Finding(
            rule_id="SA003",
            severity=Severity.CRITICAL,
            category="Credentials",
            message=f"SSH private keys accessible: {', '.join(key_files)}",
            evidence=f"~/.ssh/ contains {len(key_files)} private key(s)",
            fix="Run agent without access to ~/.ssh or use a dedicated deploy key",
        ))

    # Check SSH agent
    if os.environ.get("SSH_AUTH_SOCK"):
        result.findings.append(Finding(
            rule_id="SA003",
            severity=Severity.HIGH,
            category="Credentials",
            message="SSH agent socket available — agent can use your SSH keys",
            evidence=f"SSH_AUTH_SOCK={os.environ['SSH_AUTH_SOCK']}",
            fix="Unset SSH_AUTH_SOCK in agent environment",
        ))


def check_docker_socket(result: ScanResult) -> None:
    """SA004: Check for Docker socket access."""
    result.checks_run += 1

    docker_sock = Path("/var/run/docker.sock")
    if docker_sock.exists():
        try:
            readable = os.access(str(docker_sock), os.R_OK)
            writable = os.access(str(docker_sock), os.W_OK)
            if readable or writable:
                result.findings.append(Finding(
                    rule_id="SA004",
                    severity=Severity.CRITICAL,
                    category="Isolation",
                    message="Docker socket accessible — agent can control all containers and host",
                    evidence=f"/var/run/docker.sock (r={'Y' if readable else 'N'} w={'Y' if writable else 'N'})",
                    fix="Run agent without Docker socket access",
                ))
        except (OSError, PermissionError):
            pass


def check_filesystem_boundaries(result: ScanResult) -> None:
    """SA005: Check filesystem access boundaries."""
    result.checks_run += 1

    sensitive_paths = [
        ("/etc/shadow", "password hashes"),
        ("/etc/sudoers", "sudo config"),
        ("/root", "root home directory"),
        ("/proc/1/environ", "host process environment"),
    ]

    for path_str, desc in sensitive_paths:
        path = Path(path_str)
        try:
            if path.exists() and os.access(str(path), os.R_OK):
                result.findings.append(Finding(
                    rule_id="SA005",
                    severity=Severity.HIGH,
                    category="Isolation",
                    message=f"Sensitive path readable: {desc}",
                    evidence=path_str,
                    fix=f"Use a chroot, container, or namespace to restrict access",
                ))
        except (OSError, PermissionError):
            pass

    # Check if we can write outside CWD
    for test_dir in ["/tmp", os.path.expanduser("~"), "/var/tmp"]:
        test_file = os.path.join(test_dir, ".sandboxaudit-probe")
        try:
            with open(test_file, "w") as f:
                f.write("probe")
            os.unlink(test_file)
            if test_dir not in (str(Path.cwd()), os.path.expanduser("~")):
                result.findings.append(Finding(
                    rule_id="SA005",
                    severity=Severity.MEDIUM,
                    category="Isolation",
                    message=f"Can write outside project directory: {test_dir}",
                    evidence=f"Write test succeeded in {test_dir}",
                    fix="Use read-only filesystem with tmpfs for required writable paths",
                ))
        except (OSError, PermissionError):
            pass


def check_network_access(result: ScanResult) -> None:
    """SA006: Check network egress capability."""
    result.checks_run += 1

    # Try to resolve external hosts
    test_hosts = [
        ("api.github.com", 443, "GitHub API"),
        ("pypi.org", 443, "PyPI"),
        ("registry.npmjs.org", 443, "npm registry"),
    ]

    can_resolve = False
    can_connect = False

    for host, port, desc in test_hosts:
        try:
            socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
            can_resolve = True

            # Try actual connection (with timeout)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            try:
                sock.connect((host, port))
                can_connect = True
                sock.close()
                break
            except (socket.timeout, ConnectionRefusedError, OSError):
                sock.close()
        except (socket.gaierror, OSError):
            pass

    if can_connect:
        result.findings.append(Finding(
            rule_id="SA006",
            severity=Severity.MEDIUM,
            category="Network",
            message="Unrestricted network egress — agent can reach external services",
            evidence="Connected to external host",
            fix="Use network namespace or firewall rules to restrict egress to required hosts only",
        ))
    elif can_resolve:
        result.findings.append(Finding(
            rule_id="SA006",
            severity=Severity.LOW,
            category="Network",
            message="DNS resolution works but TCP connections blocked",
            evidence="DNS resolves but cannot connect",
        ))

    # Check for unrestricted localhost access
    for port in [5432, 3306, 6379, 27017, 9200, 2379]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            result_code = sock.connect_ex(("127.0.0.1", port))
            if result_code == 0:
                svc_names = {5432: "PostgreSQL", 3306: "MySQL", 6379: "Redis",
                            27017: "MongoDB", 9200: "Elasticsearch", 2379: "etcd"}
                svc = svc_names.get(port, f"port {port}")
                result.findings.append(Finding(
                    rule_id="SA006",
                    severity=Severity.HIGH,
                    category="Network",
                    message=f"Local service accessible: {svc} on port {port}",
                    evidence=f"127.0.0.1:{port} is open",
                    fix=f"Isolate agent network namespace from local services",
                ))
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()


def check_resource_limits(result: ScanResult) -> None:
    """SA007: Check for resource limits (ulimit, cgroup)."""
    result.checks_run += 1

    has_limits = False

    # Check ulimits
    if hasattr(os, "sysconf"):
        try:
            import resource
            # Check max memory
            soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            if soft != resource.RLIM_INFINITY:
                has_limits = True
            # Check max CPU time
            soft_cpu, hard_cpu = resource.getrlimit(resource.RLIMIT_CPU)
            if soft_cpu != resource.RLIM_INFINITY:
                has_limits = True
            # Check max processes
            if hasattr(resource, "RLIMIT_NPROC"):
                soft_proc, _ = resource.getrlimit(resource.RLIMIT_NPROC)
                if soft_proc != resource.RLIM_INFINITY:
                    has_limits = True
        except (ImportError, ValueError):
            pass

    # Check cgroup (Linux)
    cgroup_memory = Path("/sys/fs/cgroup/memory.max")
    cgroup_memory_v1 = Path("/sys/fs/cgroup/memory/memory.limit_in_bytes")
    if cgroup_memory.exists():
        try:
            val = cgroup_memory.read_text().strip()
            if val != "max":
                has_limits = True
        except (OSError, PermissionError):
            pass
    elif cgroup_memory_v1.exists():
        try:
            val = int(cgroup_memory_v1.read_text().strip())
            if val < 2**62:
                has_limits = True
        except (OSError, PermissionError, ValueError):
            pass

    if not has_limits:
        result.findings.append(Finding(
            rule_id="SA007",
            severity=Severity.MEDIUM,
            category="Resources",
            message="No resource limits detected — agent could exhaust host resources",
            fix="Set ulimits, cgroup constraints, or container resource limits",
        ))


def check_container_detection(result: ScanResult) -> None:
    """SA008: Detect if running inside a container/sandbox."""
    result.checks_run += 1

    in_container = False
    container_type = "none detected"

    # Check /.dockerenv
    if Path("/.dockerenv").exists():
        in_container = True
        container_type = "Docker"

    # Check /run/.containerenv (Podman)
    if Path("/run/.containerenv").exists():
        in_container = True
        container_type = "Podman"

    # Check cgroup for container indicators
    try:
        cgroup = Path("/proc/1/cgroup").read_text()
        if "docker" in cgroup or "containerd" in cgroup:
            in_container = True
            container_type = "Docker (cgroup)"
        elif "lxc" in cgroup:
            in_container = True
            container_type = "LXC"
    except (OSError, PermissionError):
        pass

    # Check for Kubernetes
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        in_container = True
        container_type = "Kubernetes pod"

    if not in_container:
        result.findings.append(Finding(
            rule_id="SA008",
            severity=Severity.HIGH,
            category="Isolation",
            message="Not running in a container — agent executes directly on host",
            evidence=f"Container detection: {container_type}",
            fix="Run agent inside a Docker container, VM, or namespace sandbox",
        ))
    else:
        result.findings.append(Finding(
            rule_id="SA008",
            severity=Severity.INFO,
            category="Isolation",
            message=f"Running in container: {container_type}",
            evidence=container_type,
        ))


def check_git_config(result: ScanResult) -> None:
    """SA009: Check git configuration for credential exposure."""
    result.checks_run += 1

    # Check git credential helper
    rc, helper = _run_cmd(["git", "config", "--global", "credential.helper"])
    if rc == 0 and helper:
        if helper in ("store", "cache"):
            result.findings.append(Finding(
                rule_id="SA009",
                severity=Severity.HIGH,
                category="Credentials",
                message=f"Git credential helper '{helper}' — cached credentials accessible",
                evidence=f"credential.helper={helper}",
                fix="Use a scoped token for git operations, not cached credentials",
            ))

    # Check for global git user (indicates shared identity)
    rc, email = _run_cmd(["git", "config", "--global", "user.email"])
    if rc == 0 and email:
        result.findings.append(Finding(
            rule_id="SA009",
            severity=Severity.LOW,
            category="Identity",
            message=f"Agent uses global git identity: {email}",
            evidence=f"user.email={email}",
            fix="Set a dedicated git identity for the agent in the project config",
        ))


def check_shell_history(result: ScanResult) -> None:
    """SA010: Check if shell history is accessible (may contain secrets)."""
    result.checks_run += 1

    history_files = [
        "~/.bash_history",
        "~/.zsh_history",
        "~/.python_history",
        "~/.node_repl_history",
    ]

    for hist_str in history_files:
        hist = Path(os.path.expanduser(hist_str))
        if hist.exists():
            try:
                if os.access(str(hist), os.R_OK):
                    size = hist.stat().st_size
                    if size > 0:
                        result.findings.append(Finding(
                            rule_id="SA010",
                            severity=Severity.LOW,
                            category="Credentials",
                            message=f"Shell history accessible: {hist_str} ({size} bytes)",
                            evidence=hist_str,
                            fix="Clear or mount-mask shell history files in agent environment",
                        ))
            except (OSError, PermissionError):
                pass


def check_process_visibility(result: ScanResult) -> None:
    """SA011: Check if agent can see other users' processes."""
    result.checks_run += 1

    if sys.platform == "darwin":
        rc, output = _run_cmd(["ps", "aux"])
    else:
        rc, output = _run_cmd(["ps", "auxww"])

    if rc == 0 and output:
        lines = output.strip().split("\n")
        my_user = os.environ.get("USER", os.environ.get("USERNAME", ""))
        other_users = set()
        for line in lines[1:]:
            parts = line.split()
            if parts and parts[0] != my_user and parts[0] not in ("root", "USER"):
                other_users.add(parts[0])

        if other_users:
            result.findings.append(Finding(
                rule_id="SA011",
                severity=Severity.MEDIUM,
                category="Isolation",
                message=f"Can see processes from other users: {', '.join(sorted(other_users)[:5])}",
                evidence=f"{len(other_users)} other user(s) visible",
                fix="Use PID namespace isolation (pid: host should be disabled)",
            ))


# ── Main Scanner ────────────────────────────────────────────────────

def scan_environment() -> ScanResult:
    """Run all sandbox security checks."""
    result = ScanResult()
    result.platform_info = f"{platform.system()} {platform.release()} ({platform.machine()})"

    checks = [
        check_user_privileges,
        check_credentials,
        check_ssh_keys,
        check_docker_socket,
        check_filesystem_boundaries,
        check_network_access,
        check_resource_limits,
        check_container_detection,
        check_git_config,
        check_shell_history,
        check_process_visibility,
    ]

    for check in checks:
        try:
            check(result)
        except Exception:
            pass  # Don't let one check failure stop others

    return result


# ── Output ──────────────────────────────────────────────────────────

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
GRAY = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"
MAGENTA = "\033[95m"

SEVERITY_COLORS = {
    Severity.CRITICAL: RED, Severity.HIGH: YELLOW,
    Severity.MEDIUM: MAGENTA, Severity.LOW: CYAN, Severity.INFO: GRAY,
}


def _supports_color() -> bool:
    if os.getenv("NO_COLOR"): return False
    if os.getenv("FORCE_COLOR"): return True
    return hasattr(sys.stderr, "isatty") and sys.stderr.isatty()


def format_text(result: ScanResult, verbose: bool = False, color: bool = True) -> str:
    use_color = color and _supports_color()

    def c(code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if use_color else text

    lines: List[str] = []
    grade_color = GREEN if result.grade.startswith("A") else (YELLOW if result.grade in ("B", "C") else RED)
    risk_color = GREEN if result.risk_label == "SAFE" else (YELLOW if result.risk_label in ("LOW", "MODERATE") else RED)

    lines.append(c(BOLD, "sandboxaudit") + " — AI Agent Sandbox Security Audit")
    lines.append("")
    lines.append(f"  Grade: {c(grade_color, c(BOLD, result.grade))}  Risk: {c(risk_color, result.risk_label)} ({result.risk_score}/100)")
    lines.append(f"  Platform: {result.platform_info}")
    lines.append(f"  Checks run: {result.checks_run}  Findings: {len(result.findings)}")
    lines.append("")

    if not result.findings:
        lines.append(c(GREEN, "  ✓ Sandbox appears properly isolated"))
        return "\n".join(lines)

    # Group by category
    categories: Dict[str, List[Finding]] = {}
    for f in result.findings:
        categories.setdefault(f.category, []).append(f)

    for cat, findings in sorted(categories.items()):
        cat_findings = [f for f in findings if f.severity != Severity.INFO or verbose]
        if not cat_findings:
            continue

        lines.append(c(BOLD, f"  [{cat}]"))
        for f in cat_findings:
            sev_color = SEVERITY_COLORS[f.severity]
            lines.append(f"    {c(sev_color, f'[{f.severity.value}]')} [{f.rule_id}] {f.message}")
            if f.evidence:
                lines.append(f"      {c(GRAY, '→ ' + f.evidence)}")
            if f.fix:
                lines.append(f"      {c(CYAN, '⚡ ' + f.fix)}")
            lines.append("")

    return "\n".join(lines)


def format_json(result: ScanResult) -> str:
    data = {
        "grade": result.grade,
        "risk": result.risk_label,
        "score": result.risk_score,
        "platform": result.platform_info,
        "checks_run": result.checks_run,
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(data, indent=2)


# ── Rule Reference ──────────────────────────────────────────────────

RULES = {
    "SA001": ("CRITICAL/HIGH", "Identity", "Running as root or passwordless sudo available"),
    "SA002": ("CRITICAL/HIGH", "Credentials", "Exposed credentials in env vars or credential files"),
    "SA003": ("CRITICAL/HIGH", "Credentials", "SSH private keys or agent socket accessible"),
    "SA004": ("CRITICAL", "Isolation", "Docker socket accessible (container escape)"),
    "SA005": ("HIGH/MEDIUM", "Isolation", "Sensitive filesystem paths readable/writable"),
    "SA006": ("HIGH/MEDIUM", "Network", "Unrestricted network egress or local service access"),
    "SA007": ("MEDIUM", "Resources", "No CPU/memory resource limits"),
    "SA008": ("HIGH/INFO", "Isolation", "Container/sandbox detection"),
    "SA009": ("HIGH/LOW", "Credentials", "Git credential helper or shared identity"),
    "SA010": ("LOW", "Credentials", "Shell history accessible (may contain secrets)"),
    "SA011": ("MEDIUM", "Isolation", "Can see other users' processes"),
}


def format_rules() -> str:
    lines = ["sandboxaudit rules:", ""]
    for rule_id, (severity, category, desc) in sorted(RULES.items()):
        lines.append(f"  {rule_id}  [{severity:>14s}]  [{category:>11s}]  {desc}")
    return "\n".join(lines)


# ── CLI ─────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="sandboxaudit",
        description="AI Agent Sandbox Security Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  sandboxaudit                    Audit current environment
  sandboxaudit --json             JSON output for CI
  sandboxaudit --ci               Exit 1 if HIGH+, exit 2 if CRITICAL
  sandboxaudit --rules            List all rules

Run this inside your agent's sandbox to verify isolation before
granting autonomous execution privileges.
""",
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show INFO findings")
    parser.add_argument("--rules", action="store_true", help="List all rules and exit")
    parser.add_argument("--ci", action="store_true",
                        help="CI mode: exit 1 if HIGH+, exit 2 if CRITICAL")
    parser.add_argument("--version", action="version",
                        version=f"sandboxaudit {__version__}")

    args = parser.parse_args()

    if args.rules:
        print(format_rules())
        return 0

    result = scan_environment()

    if args.json:
        print(format_json(result))
    else:
        print(format_text(result, verbose=args.verbose))

    if args.ci:
        has_critical = any(f.severity == Severity.CRITICAL for f in result.findings)
        has_high = any(f.severity == Severity.HIGH for f in result.findings)
        if has_critical: return 2
        if has_high: return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
