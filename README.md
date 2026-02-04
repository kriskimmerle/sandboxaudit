# 🔒 sandboxaudit

**Python Sandbox Escape Pattern Detector** — screen Python code for sandbox escape techniques before executing it in a restricted environment.

Detects the patterns used in real-world sandbox escapes: class hierarchy traversal, format string introspection, builtins access, code object construction, FFI escapes, and more. Informed by actual CVEs including n8n CVE-2026-0863, Langflow CVE-2025-3248, and RestrictedPython CVE-2025-22153.

## What It Detects

| Rule | Category | Severity | Technique |
|------|----------|----------|-----------|
| SB01 | Class Hierarchy Traversal | CRITICAL | `__mro__`, `__bases__`, `__subclasses__()` to find importers |
| SB02 | Builtins Access | CRITICAL | `__builtins__`, `import builtins` |
| SB03 | Format String Introspection | CRITICAL | `f"{obj.__class__.__mro__}"`, `"{0.__class__}".format()` |
| SB04 | Import Tricks | HIGH | `__import__()`, `importlib`, `__loader__`, `__spec__` |
| SB05 | Code Object Construction | CRITICAL | `types.CodeType`, `compile()`, `__code__` |
| SB06 | Frame Introspection | HIGH | `sys._getframe()`, `f_globals`, `__globals__` |
| SB07 | Serialization Escape | CRITICAL | `__reduce__`, `__reduce_ex__` pickle hooks |
| SB08 | FFI Escape | CRITICAL | `ctypes`, `cffi` — C-level sandbox bypass |
| SB09 | GC Object Discovery | HIGH | `gc.get_objects()`, `gc.get_referrers()` |
| SB10 | OS/Process Access | HIGH | `os.system()`, `subprocess`, `os.exec*` |
| SB11 | File System Escape | HIGH | `/proc/self/`, `../` path traversal |
| SB12 | Signal Abuse | MEDIUM | `signal.signal()`, `signal.alarm()` |
| SB13 | Exception Attribute Exploit | CRITICAL | `AttributeError.obj` (Python 3.10+, n8n CVE-2026-0863) |
| SB14 | Obfuscated Access | MEDIUM | `getattr(obj, "__builtins__")`, `__dict__` |
| SB15 | Metaclass/Decorator Abuse | HIGH | Custom metaclasses, `__init_subclass__`, `__set_name__` |

## Use Cases

- **Workflow automation** — Screen user-submitted Python in n8n, Airflow, Prefect
- **AI agent sandboxes** — Pre-check LLM-generated code before execution
- **Code execution services** — Replit, Jupyter Hub, coding challenge platforms
- **CI/CD pipelines** — Audit plugins, extensions, or user-contributed code
- **Security research** — Analyze potential exploits and CTF challenges

## Install

```bash
curl -O https://raw.githubusercontent.com/kriskimmerle/sandboxaudit/main/sandboxaudit.py
chmod +x sandboxaudit.py
```

## Usage

```bash
# Scan submitted code
python3 sandboxaudit.py submitted_code.py

# Scan with fix suggestions and CVE references
python3 sandboxaudit.py -v suspicious.py

# CI mode — reject code with escape patterns
python3 sandboxaudit.py --check --threshold A submitted.py

# JSON output for integration
python3 sandboxaudit.py --json code.py

# Scan from stdin (pipe from code submission)
cat user_code.py | python3 sandboxaudit.py -

# Only show critical patterns
python3 sandboxaudit.py --severity CRITICAL code.py
```

## CVE Coverage

sandboxaudit detects patterns from real sandbox escapes:

| CVE | Product | Technique | Rule |
|-----|---------|-----------|------|
| CVE-2026-0863 | n8n | Format string + AttributeError.obj | SB03, SB13 |
| CVE-2025-68668 | n8n (Pyodide) | eval_code() sandbox bypass | SB05 |
| CVE-2025-22153 | RestrictedPython | try/except* escape | SB13 |
| CVE-2025-3248 | Langflow | Decorator evaluation RCE | SB15 |
| GHSA-3wwr-3g9f-9gc7 | asteval | Format string introspection | SB03 |

## Example Output

```
🔒 sandboxaudit — Sandbox Escape Pattern Detector
────────────────────────────────────────────────────────────
  Files scanned: 1
  Findings: 56
  Score: 0/100  Grade: F
────────────────────────────────────────────────────────────

  CRITICAL: 22
  HIGH: 27
  MEDIUM: 7

────────────────────────────────────────────────────────────
  SB01 Class Hierarchy Traversal: 7
  SB02 Builtins Access: 2
  SB03 Format String Introspection: 3
  SB05 Code Object Construction: 6
  SB07 Serialization Escape: 2
  SB08 FFI Escape: 2
  SB13 Exception Attribute Exploit: 1
  ...
```

## Integration Example

Pre-screen code before sandbox execution:

```python
import subprocess
import sys

def is_safe(code: str) -> bool:
    """Check if code is safe to execute in sandbox."""
    result = subprocess.run(
        [sys.executable, "sandboxaudit.py", "--json", "--check", "--threshold", "A", "-"],
        input=code, capture_output=True, text=True
    )
    return result.returncode == 0
```

## Requirements

- Python 3.9+
- Zero external dependencies

## License

MIT
