# sandboxaudit

**AI Agent Sandbox Security Auditor** — Runtime probe that verifies whether an AI coding agent's execution environment is properly isolated before granting autonomous code execution privileges.

Run this inside your agent's sandbox (Ralph Wiggum loops, Claude Code with `--dangerously-skip-permissions`, Codex, Devin, etc.) to find exposed credentials, excessive permissions, missing container boundaries, and unrestricted network access.

Maps to [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/):
- **ASI03** — Identity and Privilege Abuse
- **ASI05** — Unexpected Code Execution

## Why

Autonomous coding agents need execution environments. Most teams give them:
- The developer's full home directory
- All cloud credentials in the environment
- SSH keys, git tokens, Docker socket access
- Unrestricted network egress
- No resource limits

Then wonder why things go wrong. `sandboxaudit` tells you exactly what's exposed.

## Install

```bash
# No dependencies. Just Python 3.8+.
curl -O https://raw.githubusercontent.com/kriskimmerle/sandboxaudit/main/sandboxaudit.py
chmod +x sandboxaudit.py
```

Or clone:
```bash
git clone https://github.com/kriskimmerle/sandboxaudit.git
cd sandboxaudit
python3 sandboxaudit.py
```

## Usage

```bash
# Audit current environment
python3 sandboxaudit.py

# JSON output (for CI/CD pipelines)
python3 sandboxaudit.py --json

# CI mode: exit 1 if HIGH+, exit 2 if CRITICAL
python3 sandboxaudit.py --ci

# Show INFO-level findings
python3 sandboxaudit.py -v

# List all rules
python3 sandboxaudit.py --rules
```

## Example Output

```
sandboxaudit — AI Agent Sandbox Security Audit

  Grade: F  Risk: CRITICAL (100/100)
  Platform: Darwin 25.2.0 (arm64)
  Checks run: 11  Findings: 11

  [Credentials]
    [CRITICAL] [SA002] Exposed credential: SSH agent socket
      → SSH_AUTH_SOCK=****
      ⚡ Remove SSH_AUTH_SOCK from agent environment or use scoped, short-lived tokens

    [HIGH] [SA002] Credential file accessible: Git stored credentials
      → ~/.git-credentials (readable)
      ⚡ Mount agent environment without access to ~/.git-credentials

    [HIGH] [SA003] SSH agent socket available — agent can use your SSH keys
      → SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.xxx/Listeners
      ⚡ Unset SSH_AUTH_SOCK in agent environment

  [Identity]
    [LOW] [SA009] Agent uses global git identity: dev@example.com
      → user.email=dev@example.com
      ⚡ Set a dedicated git identity for the agent in the project config

  [Isolation]
    [HIGH] [SA008] Not running in a container — agent executes directly on host
      → Container detection: none detected
      ⚡ Run agent inside a Docker container, VM, or namespace sandbox

  [Network]
    [MEDIUM] [SA006] Unrestricted network egress — agent can reach external services
      → Connected to external host
      ⚡ Use network namespace or firewall rules to restrict egress to required hosts only
```

## Rules

| Rule | Severity | Category | Description |
|------|----------|----------|-------------|
| SA001 | CRITICAL/HIGH | Identity | Running as root or passwordless sudo |
| SA002 | CRITICAL/HIGH | Credentials | Exposed credentials in env vars or files |
| SA003 | CRITICAL/HIGH | Credentials | SSH private keys or agent socket accessible |
| SA004 | CRITICAL | Isolation | Docker socket accessible (container escape) |
| SA005 | HIGH/MEDIUM | Isolation | Sensitive filesystem paths readable/writable |
| SA006 | HIGH/MEDIUM | Network | Unrestricted network egress or local services |
| SA007 | MEDIUM | Resources | No CPU/memory resource limits |
| SA008 | HIGH/INFO | Isolation | Container/sandbox detection |
| SA009 | HIGH/LOW | Credentials | Git credential helper or shared identity |
| SA010 | LOW | Credentials | Shell history accessible (may contain secrets) |
| SA011 | MEDIUM | Isolation | Can see other users' processes |

## Grading

| Grade | Score | Risk Level |
|-------|-------|------------|
| A+ | 0 | SAFE |
| A | 1-10 | LOW |
| B | 11-20 | LOW |
| C | 21-35 | MODERATE |
| D | 36-50 | MODERATE |
| F | 51+ | HIGH/CRITICAL |

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Audit agent sandbox
  run: |
    python3 sandboxaudit.py --ci
    # Fails the build if HIGH or CRITICAL findings
```

```yaml
# GitLab CI example
audit-sandbox:
  script:
    - python3 sandboxaudit.py --json > sandbox-report.json
  artifacts:
    paths:
      - sandbox-report.json
```

## Use Cases

### Before Enabling Autonomous Agents
```bash
# In your Dockerfile for the agent sandbox:
FROM python:3.12-slim
COPY sandboxaudit.py /usr/local/bin/
RUN python3 /usr/local/bin/sandboxaudit.py --ci
# If this passes, the container is reasonably isolated
```

### Validating Docker Sandbox
```bash
# Test your agent's Docker setup
docker run --rm your-agent-image python3 sandboxaudit.py --json
```

### Periodic Monitoring
```bash
# Cron job to audit agent environment daily
0 6 * * * python3 /opt/sandboxaudit.py --json >> /var/log/sandbox-audit.jsonl
```

## Zero Dependencies

`sandboxaudit` uses only Python standard library. No pip install. No venv. Works on Python 3.8+ across Linux and macOS.

## License

MIT
