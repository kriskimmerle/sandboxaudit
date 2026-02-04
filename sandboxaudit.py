#!/usr/bin/env python3
"""sandboxaudit — Python Sandbox Escape Pattern Detector.

Scans Python code for patterns that attempt to escape restricted execution
environments. Detects class hierarchy traversal, builtins access, format string
introspection, import tricks, code object construction, frame introspection,
and more.

Use this to pre-screen code before executing it in a sandbox.

Usage:
    sandboxaudit submitted_code.py
    sandboxaudit --check --threshold B code/
    sandboxaudit --json code.py
    cat code.py | sandboxaudit -

Informed by:
    - n8n CVE-2026-0863 (format string + AttributeError.obj sandbox escape)
    - n8n CVE-2025-68668 (Pyodide sandbox escape)
    - RestrictedPython CVE-2025-22153 (try/except* escape)
    - Langflow CVE-2025-3248 (decorator evaluation RCE)
    - asteval GHSA-3wwr-3g9f-9gc7 (format string introspection)
    - NVIDIA AI Red Team sandbox security guidance (Jan 2026)
"""

from __future__ import annotations

import ast
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

__version__ = "1.0.0"

# ── Check definitions ──────────────────────────────────────────────

CHECKS: dict[str, dict[str, str]] = {
    "SB01": {"name": "Class Hierarchy Traversal", "severity": "CRITICAL",
             "desc": "Accessing __mro__, __bases__, __subclasses__() to find importers"},
    "SB02": {"name": "Builtins Access", "severity": "CRITICAL",
             "desc": "Direct access to __builtins__ or builtins module"},
    "SB03": {"name": "Format String Introspection", "severity": "CRITICAL",
             "desc": "Using format strings to access object attributes and traverse class hierarchy"},
    "SB04": {"name": "Import Tricks", "severity": "HIGH",
             "desc": "Using __import__, importlib, __loader__, or __spec__ to load modules"},
    "SB05": {"name": "Code Object Construction", "severity": "CRITICAL",
             "desc": "Building code/function objects to bypass restrictions"},
    "SB06": {"name": "Frame Introspection", "severity": "HIGH",
             "desc": "Accessing call frames to reach restricted scopes"},
    "SB07": {"name": "Serialization Escape", "severity": "CRITICAL",
             "desc": "Using pickle/marshal __reduce__ protocol for code execution"},
    "SB08": {"name": "FFI Escape", "severity": "CRITICAL",
             "desc": "Using ctypes/cffi to call C functions and bypass Python restrictions"},
    "SB09": {"name": "GC Object Discovery", "severity": "HIGH",
             "desc": "Using garbage collector to find and access restricted objects"},
    "SB10": {"name": "OS/Process Access", "severity": "HIGH",
             "desc": "Direct OS command execution or process spawning"},
    "SB11": {"name": "File System Escape", "severity": "HIGH",
             "desc": "Accessing files outside sandbox boundaries"},
    "SB12": {"name": "Signal Abuse", "severity": "MEDIUM",
             "desc": "Manipulating signal handlers to alter control flow"},
    "SB13": {"name": "Exception Attribute Exploit", "severity": "CRITICAL",
             "desc": "Exploiting exception attributes (e.g., AttributeError.obj) to access objects"},
    "SB14": {"name": "Obfuscated Attribute Access", "severity": "MEDIUM",
             "desc": "Using getattr/vars/dir for dynamic attribute discovery"},
    "SB15": {"name": "Metaclass/Decorator Abuse", "severity": "HIGH",
             "desc": "Using metaclasses or decorators for code execution during class creation"},
}

SEVERITY_WEIGHT = {"CRITICAL": 15, "HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 1}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ── AST Helpers ─────────────────────────────────────────────────────


def _get_name(node: ast.AST) -> str:
    """Extract a dotted name from an AST node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _get_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _collect_imports(tree: ast.Module) -> dict[str, str]:
    """Collect import aliases → module mappings."""
    imports: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name
                imports[name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                name = alias.asname or alias.name
                imports[name] = f"{mod}.{alias.name}" if mod else alias.name
    return imports


class Finding:
    """A single security finding."""

    __slots__ = ("rule", "file", "line", "message", "severity", "fix", "snippet")

    def __init__(self, rule: str, file: str, line: int, message: str,
                 severity: str, fix: str = "", snippet: str = ""):
        self.rule = rule
        self.file = file
        self.line = line
        self.message = message
        self.severity = severity
        self.fix = fix
        self.snippet = snippet

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "rule": self.rule,
            "name": CHECKS[self.rule]["name"],
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "message": self.message,
        }
        if self.fix:
            d["fix"] = self.fix
        if self.snippet:
            d["snippet"] = self.snippet
        return d


# ── Analyzer ────────────────────────────────────────────────────────


class SandboxAuditor:
    """Detects Python sandbox escape patterns."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def check_file(self, filepath: str, source: str) -> None:
        """Run all checks on source code."""
        # Text-based checks (for patterns in strings, comments, etc.)
        self._check_format_string_text(filepath, source)
        self._check_filesystem_escape_text(filepath, source)

        # AST-based checks
        try:
            tree = ast.parse(source, filename=filepath)
        except SyntaxError:
            return

        imports = _collect_imports(tree)

        self._check_class_hierarchy(filepath, tree)
        self._check_builtins_access(filepath, tree)
        self._check_format_string_ast(filepath, tree)
        self._check_import_tricks(filepath, tree, imports)
        self._check_code_object(filepath, tree, imports)
        self._check_frame_introspection(filepath, tree, imports)
        self._check_serialization_escape(filepath, tree)
        self._check_ffi_escape(filepath, tree, imports)
        self._check_gc_discovery(filepath, tree, imports)
        self._check_os_access(filepath, tree, imports)
        self._check_signal_abuse(filepath, tree, imports)
        self._check_exception_exploit(filepath, tree)
        self._check_obfuscated_access(filepath, tree)
        self._check_metaclass_abuse(filepath, tree)

    # ── SB01: Class Hierarchy Traversal ──────────────────────────

    def _check_class_hierarchy(self, fp: str, tree: ast.Module) -> None:
        """Detect __mro__, __bases__, __subclasses__() access."""
        dangerous_attrs = {
            "__mro__": "Class method resolution order traversal",
            "__bases__": "Base class access for hierarchy walking",
            "__subclasses__": "Subclass enumeration to find importers/loaders",
            "__init_subclass__": "Subclass hook that executes on class creation",
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                if node.attr in dangerous_attrs:
                    self.findings.append(Finding(
                        "SB01", fp, node.lineno,
                        f"{dangerous_attrs[node.attr]}: .{node.attr}",
                        "CRITICAL",
                        "This pattern is used to traverse class hierarchy and find BuiltinImporter",
                    ))

            # __class__ access is suspicious in sandbox context
            if isinstance(node, ast.Attribute) and node.attr == "__class__":
                # Check if it's chained: obj.__class__.__mro__ etc.
                parent = None
                for n in ast.walk(tree):
                    for child in ast.iter_child_nodes(n):
                        if child is node:
                            parent = n
                            break
                if parent and isinstance(parent, ast.Attribute):
                    if parent.attr in ("__mro__", "__bases__", "__subclasses__",
                                        "__dict__", "__init__"):
                        self.findings.append(Finding(
                            "SB01", fp, node.lineno,
                            f"Class hierarchy chain: .__class__.{parent.attr}",
                            "CRITICAL",
                            "Classic sandbox escape: obj.__class__.__mro__[1].__subclasses__()",
                        ))

    # ── SB02: Builtins Access ────────────────────────────────────

    def _check_builtins_access(self, fp: str, tree: ast.Module) -> None:
        """Detect access to __builtins__."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                if node.attr == "__builtins__":
                    self.findings.append(Finding(
                        "SB02", fp, node.lineno,
                        "Direct __builtins__ access — can reach __import__ and other restricted builtins",
                        "CRITICAL",
                        "Block __builtins__ access in sandbox",
                    ))

            if isinstance(node, ast.Name) and node.id == "__builtins__":
                self.findings.append(Finding(
                    "SB02", fp, node.lineno,
                    "__builtins__ name reference — attempting to access builtin functions",
                    "CRITICAL",
                ))

            # import builtins
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "builtins":
                        self.findings.append(Finding(
                            "SB02", fp, node.lineno,
                            "Importing builtins module directly",
                            "CRITICAL",
                            "Block builtins module import in sandbox",
                        ))

            if isinstance(node, ast.ImportFrom) and node.module == "builtins":
                self.findings.append(Finding(
                    "SB02", fp, node.lineno,
                    "Importing from builtins module",
                    "CRITICAL",
                ))

    # ── SB03: Format String Introspection ────────────────────────

    def _check_format_string_ast(self, fp: str, tree: ast.Module) -> None:
        """Detect format strings with dunder attribute access."""
        for node in ast.walk(tree):
            # f-strings with __class__, __dict__, etc.
            if isinstance(node, ast.JoinedStr):
                for val in node.values:
                    if isinstance(val, ast.FormattedValue):
                        name = _get_name(val.value)
                        if any(d in name for d in ("__class__", "__dict__",
                                                     "__mro__", "__bases__",
                                                     "__subclasses__",
                                                     "__builtins__",
                                                     "__globals__",
                                                     "__init__")):
                            self.findings.append(Finding(
                                "SB03", fp, node.lineno,
                                f"F-string accessing dunder attributes: {name}",
                                "CRITICAL",
                                "Format string introspection (n8n CVE-2026-0863, asteval GHSA-3wwr)",
                            ))

            # "...".format() with dunder access in format spec
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                    # Check the format string for {0.__class__} patterns
                    if isinstance(node.func.value, ast.Constant):
                        fmt_str = str(node.func.value.value)
                        if re.search(r'\{[^}]*__\w+__[^}]*\}', fmt_str):
                            self.findings.append(Finding(
                                "SB03", fp, node.lineno,
                                "str.format() with dunder attribute access in format spec",
                                "CRITICAL",
                                "Classic sandbox escape via format string introspection",
                            ))

    def _check_format_string_text(self, fp: str, source: str) -> None:
        """Text-based check for format string escape patterns."""
        # Check for format specs with dunder access that might be in strings
        pattern = re.compile(
            r'''['"].*\{[^}]*(?:__class__|__mro__|__bases__|__subclasses__|'''
            r'''__builtins__|__globals__|__init__|__dict__|__getattribute__)'''
            r'''[^}]*\}.*['"]'''
        )
        for line_num, line in enumerate(source.splitlines(), 1):
            if pattern.search(line):
                # Don't double-count AST findings
                if ".format" not in line and "f'" not in line and 'f"' not in line:
                    self.findings.append(Finding(
                        "SB03", fp, line_num,
                        "String containing format spec with dunder attribute traversal",
                        "CRITICAL",
                        "This string may be used with .format() or eval() for sandbox escape",
                    ))

    # ── SB04: Import Tricks ──────────────────────────────────────

    def _check_import_tricks(self, fp: str, tree: ast.Module,
                              imports: dict) -> None:
        """Detect alternative import mechanisms."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _get_name(node.func)

                # __import__()
                if name == "__import__":
                    self.findings.append(Finding(
                        "SB04", fp, node.lineno,
                        "__import__() call — bypasses standard import restrictions",
                        "HIGH",
                        "Block __import__ in sandbox builtins",
                    ))

                # importlib.import_module()
                if name in ("importlib.import_module", "import_module"):
                    self.findings.append(Finding(
                        "SB04", fp, node.lineno,
                        "importlib.import_module() — dynamic module loading",
                        "HIGH",
                        "Block importlib access in sandbox",
                    ))

            # Access to __loader__, __spec__
            if isinstance(node, ast.Attribute):
                if node.attr in ("__loader__", "__spec__"):
                    self.findings.append(Finding(
                        "SB04", fp, node.lineno,
                        f".{node.attr} access — can reach module loaders",
                        "HIGH",
                        "Module loader access can be used to import restricted modules",
                    ))

                # load_module
                if node.attr == "load_module":
                    self.findings.append(Finding(
                        "SB04", fp, node.lineno,
                        ".load_module() — direct module loading bypassing import hooks",
                        "HIGH",
                    ))

            # import importlib
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "importlib":
                        self.findings.append(Finding(
                            "SB04", fp, node.lineno,
                            "Importing importlib — enables dynamic module loading",
                            "HIGH",
                        ))

    # ── SB05: Code Object Construction ───────────────────────────

    def _check_code_object(self, fp: str, tree: ast.Module,
                            imports: dict) -> None:
        """Detect code/function object construction."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _get_name(node.func)

                # types.CodeType / types.FunctionType
                if name in ("types.CodeType", "CodeType",
                             "types.FunctionType", "FunctionType"):
                    self.findings.append(Finding(
                        "SB05", fp, node.lineno,
                        f"{name}() — constructing executable objects from raw bytecode",
                        "CRITICAL",
                        "Code object construction bypasses all source-level restrictions",
                    ))

                # compile() + exec()
                if name == "compile":
                    self.findings.append(Finding(
                        "SB05", fp, node.lineno,
                        "compile() — creating code objects from strings",
                        "CRITICAL",
                        "compile() + exec() bypasses AST-based restrictions",
                    ))

            # Access to __code__
            if isinstance(node, ast.Attribute):
                if node.attr == "__code__":
                    self.findings.append(Finding(
                        "SB05", fp, node.lineno,
                        ".__code__ access — can modify function bytecode",
                        "CRITICAL",
                        "Code object manipulation can bypass all restrictions",
                    ))

                if node.attr == "co_consts":
                    self.findings.append(Finding(
                        "SB05", fp, node.lineno,
                        ".co_consts access — inspecting code object constants",
                        "HIGH",
                    ))

            # import types
            if isinstance(node, ast.ImportFrom) and node.module == "types":
                for alias in node.names:
                    if alias.name in ("CodeType", "FunctionType"):
                        self.findings.append(Finding(
                            "SB05", fp, node.lineno,
                            f"Importing {alias.name} from types module",
                            "CRITICAL",
                        ))

    # ── SB06: Frame Introspection ────────────────────────────────

    def _check_frame_introspection(self, fp: str, tree: ast.Module,
                                    imports: dict) -> None:
        """Detect stack frame access."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _get_name(node.func)

                if name in ("sys._getframe", "_getframe"):
                    self.findings.append(Finding(
                        "SB06", fp, node.lineno,
                        "sys._getframe() — accessing call stack frames",
                        "HIGH",
                        "Frame access can reach variables in restricted scopes",
                    ))

                if name in ("inspect.currentframe", "currentframe",
                             "inspect.stack", "inspect.getouterframes"):
                    self.findings.append(Finding(
                        "SB06", fp, node.lineno,
                        f"{name}() — inspecting call stack",
                        "HIGH",
                    ))

            if isinstance(node, ast.Attribute):
                if node.attr in ("f_globals", "f_locals", "f_builtins",
                                  "f_back", "f_code"):
                    self.findings.append(Finding(
                        "SB06", fp, node.lineno,
                        f".{node.attr} — accessing frame attributes",
                        "HIGH",
                        "Frame attributes expose the global/local scope of callers",
                    ))

                if node.attr == "__globals__":
                    self.findings.append(Finding(
                        "SB06", fp, node.lineno,
                        ".__globals__ — accessing function's global scope",
                        "HIGH",
                        "func.__globals__ exposes the module namespace",
                    ))

    # ── SB07: Serialization Escape ───────────────────────────────

    def _check_serialization_escape(self, fp: str, tree: ast.Module) -> None:
        """Detect __reduce__ and serialization-based escapes."""
        reduce_methods = {"__reduce__", "__reduce_ex__",
                           "__getstate__", "__setstate__"}

        for node in ast.walk(tree):
            # Class defining __reduce__
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name in reduce_methods:
                    self.findings.append(Finding(
                        "SB07", fp, node.lineno,
                        f"Defining {node.name}() — pickle deserialization hook for code execution",
                        "CRITICAL",
                        f"{node.name} is called during unpickling and can execute arbitrary code",
                    ))

            # copyreg.dispatch_table or copyreg.__newobj__
            if isinstance(node, ast.Attribute):
                if node.attr in ("dispatch_table", "__newobj__",
                                  "__newobj_ex__"):
                    name = _get_name(node.value)
                    if "copyreg" in name or "copy_reg" in name:
                        self.findings.append(Finding(
                            "SB07", fp, node.lineno,
                            f"copyreg.{node.attr} — manipulating pickle dispatch",
                            "CRITICAL",
                        ))

    # ── SB08: FFI Escape ─────────────────────────────────────────

    def _check_ffi_escape(self, fp: str, tree: ast.Module,
                           imports: dict) -> None:
        """Detect ctypes/cffi usage."""
        ffi_modules = {"ctypes", "cffi", "_ctypes"}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in ffi_modules:
                        self.findings.append(Finding(
                            "SB08", fp, node.lineno,
                            f"Importing {alias.name} — foreign function interface",
                            "CRITICAL",
                            "FFI bypasses all Python-level restrictions",
                        ))

            if isinstance(node, ast.ImportFrom):
                if node.module and node.module.split(".")[0] in ffi_modules:
                    self.findings.append(Finding(
                        "SB08", fp, node.lineno,
                        f"Importing from {node.module} — FFI access",
                        "CRITICAL",
                    ))

            # ctypes.CDLL, ctypes.pythonapi etc.
            if isinstance(node, ast.Call):
                name = _get_name(node.func)
                if any(name.startswith(f"{m}.") for m in ffi_modules):
                    self.findings.append(Finding(
                        "SB08", fp, node.lineno,
                        f"{name}() — FFI call",
                        "CRITICAL",
                        "Direct C library access bypasses sandbox",
                    ))

    # ── SB09: GC Object Discovery ────────────────────────────────

    def _check_gc_discovery(self, fp: str, tree: ast.Module,
                             imports: dict) -> None:
        """Detect garbage collector abuse."""
        gc_funcs = {"gc.get_objects", "gc.get_referrers", "gc.get_referents",
                     "get_objects", "get_referrers", "get_referents"}

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _get_name(node.func)
                if name in gc_funcs:
                    self.findings.append(Finding(
                        "SB09", fp, node.lineno,
                        f"{name}() — enumerating Python objects via garbage collector",
                        "HIGH",
                        "GC traversal can find restricted objects in memory",
                    ))

            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "gc":
                        self.findings.append(Finding(
                            "SB09", fp, node.lineno,
                            "Importing gc module — enables object discovery",
                            "HIGH",
                        ))

    # ── SB10: OS/Process Access ──────────────────────────────────

    def _check_os_access(self, fp: str, tree: ast.Module,
                          imports: dict) -> None:
        """Detect OS command execution and process spawning."""
        os_exec_funcs = {
            "os.system", "os.popen", "os.exec", "os.execl", "os.execle",
            "os.execlp", "os.execv", "os.execve", "os.execvp", "os.execvpe",
            "os.spawn", "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnv",
            "os.fork", "os.forkpty",
        }
        subprocess_funcs = {
            "subprocess.run", "subprocess.call", "subprocess.check_output",
            "subprocess.check_call", "subprocess.Popen", "subprocess.getoutput",
            "subprocess.getstatusoutput",
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _get_name(node.func)

                if name in os_exec_funcs or any(name.startswith(f) for f in os_exec_funcs):
                    self.findings.append(Finding(
                        "SB10", fp, node.lineno,
                        f"{name}() — OS command execution",
                        "HIGH",
                        "Block os module exec/spawn/system functions in sandbox",
                    ))

                if name in subprocess_funcs:
                    self.findings.append(Finding(
                        "SB10", fp, node.lineno,
                        f"{name}() — subprocess execution",
                        "HIGH",
                        "Block subprocess module in sandbox",
                    ))

            # import os / import subprocess
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in ("os", "subprocess", "pty", "commands"):
                        self.findings.append(Finding(
                            "SB10", fp, node.lineno,
                            f"Importing {alias.name} module",
                            "HIGH",
                            f"Block {alias.name} module import in sandbox",
                        ))

    # ── SB11: File System Escape ─────────────────────────────────

    def _check_filesystem_escape_text(self, fp: str, source: str) -> None:
        """Detect file system escape attempts."""
        patterns = [
            (r'/proc/self/', "/proc/self/ access — process information disclosure"),
            (r'/proc/\d+/', "/proc/PID access — other process inspection"),
            (r'/dev/shm\b', "/dev/shm access — shared memory"),
            (r'/dev/tcp\b', "/dev/tcp access — network connection via filesystem"),
            (r'\.\./', "Path traversal with ../"),
        ]

        for line_num, line in enumerate(source.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    self.findings.append(Finding(
                        "SB11", fp, line_num,
                        desc,
                        "HIGH",
                        "Block filesystem access outside sandbox directory",
                    ))
                    break

    # ── SB12: Signal Abuse ───────────────────────────────────────

    def _check_signal_abuse(self, fp: str, tree: ast.Module,
                             imports: dict) -> None:
        """Detect signal handler manipulation."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _get_name(node.func)
                if name in ("signal.signal", "signal.alarm",
                             "signal.setitimer"):
                    self.findings.append(Finding(
                        "SB12", fp, node.lineno,
                        f"{name}() — modifying signal handlers",
                        "MEDIUM",
                        "Signal manipulation can alter sandbox control flow",
                    ))

            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "signal":
                        self.findings.append(Finding(
                            "SB12", fp, node.lineno,
                            "Importing signal module",
                            "MEDIUM",
                        ))

    # ── SB13: Exception Attribute Exploit ────────────────────────

    def _check_exception_exploit(self, fp: str, tree: ast.Module) -> None:
        """Detect exploitation of exception attributes (Python 3.10+)."""
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                # Check if handler accesses .obj, .name, or .args on exception
                if node.name:
                    exc_var = node.name
                    for child in ast.walk(node):
                        if isinstance(child, ast.Attribute):
                            parent_name = _get_name(child.value)
                            if parent_name == exc_var:
                                if child.attr == "obj":
                                    self.findings.append(Finding(
                                        "SB13", fp, child.lineno,
                                        f"Accessing .obj on caught exception — "
                                        f"AttributeError.obj exploit (Python 3.10+, n8n CVE-2026-0863)",
                                        "CRITICAL",
                                        "AttributeError.obj returns the object that raised the error, "
                                        "bypassing attribute access restrictions",
                                    ))
                                elif child.attr == "name":
                                    # Less dangerous but still suspicious in sandbox context
                                    pass

            # try/except* (Python 3.11+) — RestrictedPython CVE-2025-22153
            if hasattr(ast, "TryStar") and isinstance(node, ast.TryStar):
                self.findings.append(Finding(
                    "SB13", fp, node.lineno,
                    "try/except* (ExceptionGroup) — potential sandbox escape "
                    "(RestrictedPython CVE-2025-22153)",
                    "HIGH",
                    "except* clauses may bypass sandbox exception handling restrictions",
                ))

    # ── SB14: Obfuscated Attribute Access ────────────────────────

    def _check_obfuscated_access(self, fp: str, tree: ast.Module) -> None:
        """Detect dynamic attribute access for discovery/bypass."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _get_name(node.func)

                # getattr(obj, "__builtins__") / getattr(obj, dunder)
                if name == "getattr" and len(node.args) >= 2:
                    attr_arg = node.args[1]
                    if isinstance(attr_arg, ast.Constant) and isinstance(attr_arg.value, str):
                        if attr_arg.value.startswith("__") and attr_arg.value.endswith("__"):
                            self.findings.append(Finding(
                                "SB14", fp, node.lineno,
                                f'getattr() accessing dunder: "{attr_arg.value}"',
                                "MEDIUM",
                                "getattr with dunder names bypasses static attribute restrictions",
                            ))
                    # getattr with variable name (can't check statically)
                    elif isinstance(attr_arg, ast.Name):
                        self.findings.append(Finding(
                            "SB14", fp, node.lineno,
                            f"getattr() with variable attribute name — dynamic access",
                            "MEDIUM",
                            "Variable attribute names may contain restricted dunder attributes",
                        ))

                # setattr with dunders
                if name == "setattr" and len(node.args) >= 2:
                    attr_arg = node.args[1]
                    if isinstance(attr_arg, ast.Constant) and isinstance(attr_arg.value, str):
                        if attr_arg.value.startswith("__") and attr_arg.value.endswith("__"):
                            self.findings.append(Finding(
                                "SB14", fp, node.lineno,
                                f'setattr() modifying dunder: "{attr_arg.value}"',
                                "HIGH",
                                "Modifying dunder attributes can alter object behavior",
                            ))

            # __dict__ access for attribute discovery
            if isinstance(node, ast.Attribute) and node.attr == "__dict__":
                self.findings.append(Finding(
                    "SB14", fp, node.lineno,
                    ".__dict__ access — direct namespace manipulation",
                    "MEDIUM",
                    "dict access bypasses __getattribute__ and descriptor protocol",
                ))

    # ── SB15: Metaclass/Decorator Abuse ──────────────────────────

    def _check_metaclass_abuse(self, fp: str, tree: ast.Module) -> None:
        """Detect metaclass and decorator-based execution."""
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                # Check for metaclass keyword
                for kw in node.keywords:
                    if kw.arg == "metaclass":
                        self.findings.append(Finding(
                            "SB15", fp, node.lineno,
                            "Custom metaclass — code executes during class creation",
                            "HIGH",
                            "Metaclasses can execute arbitrary code when a class is defined "
                            "(Langflow CVE-2025-3248 pattern)",
                        ))

                # Check for __init_subclass__ in class body
                for item in node.body:
                    if isinstance(item, ast.FunctionDef):
                        if item.name == "__init_subclass__":
                            self.findings.append(Finding(
                                "SB15", fp, item.lineno,
                                "__init_subclass__() — executes when subclassed",
                                "HIGH",
                                "This hook runs automatically when any class inherits from this one",
                            ))
                        if item.name == "__set_name__":
                            self.findings.append(Finding(
                                "SB15", fp, item.lineno,
                                "__set_name__() — descriptor hook executes during class creation",
                                "HIGH",
                            ))

            # Decorators that call functions (execution during definition)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Call):
                        name = _get_name(dec.func)
                        # Flag suspicious decorator calls that could execute code
                        if any(d in name.lower() for d in
                               ("exec", "eval", "system", "import")):
                            self.findings.append(Finding(
                                "SB15", fp, node.lineno,
                                f"Suspicious decorator call: @{name}(...)",
                                "HIGH",
                                "Decorators execute during function/class definition, "
                                "before the function body runs",
                            ))


# ── Scanning and Output ─────────────────────────────────────────────


def scan_path(path: str, auditor: SandboxAuditor) -> int:
    """Scan a file or directory. Returns number of files scanned."""
    p = Path(path)
    count = 0

    if p.is_file():
        if p.suffix == ".py":
            try:
                source = p.read_text(encoding="utf-8", errors="ignore")
                auditor.check_file(str(p), source)
                count = 1
            except OSError:
                pass
    elif p.is_dir():
        skip_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv",
                     ".tox", ".eggs", "build", "dist", ".mypy_cache"}
        for root, dirs, files in os.walk(p):
            dirs[:] = [d for d in dirs if d not in skip_dirs
                       and not d.endswith(".egg-info")]
            for fname in files:
                if fname.endswith(".py"):
                    fpath = os.path.join(root, fname)
                    try:
                        source = Path(fpath).read_text(encoding="utf-8", errors="ignore")
                        auditor.check_file(fpath, source)
                        count += 1
                    except OSError:
                        pass
    return count


def compute_score(findings: list[Finding]) -> int:
    deductions = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    return max(0, 100 - deductions)


def grade(score: int) -> str:
    if score >= 95: return "A+"
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"


def severity_color(severity: str) -> str:
    return {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[33m",
            "LOW": "\033[36m", "INFO": "\033[90m"}.get(severity, "")


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def print_results(auditor: SandboxAuditor, files_scanned: int,
                  verbose: bool = False, severity_filter: str | None = None,
                  ignore_rules: set[str] | None = None) -> tuple[int, str]:
    findings = auditor.findings
    if severity_filter:
        sev_idx = SEVERITY_ORDER.get(severity_filter.upper(), 99)
        findings = [f for f in findings if SEVERITY_ORDER[f.severity] <= sev_idx]
    if ignore_rules:
        findings = [f for f in findings if f.rule not in ignore_rules]

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.line))
    score = compute_score(findings)
    g = grade(score)

    print(f"\n{BOLD}🔒 sandboxaudit{RESET} — Sandbox Escape Pattern Detector")
    print(f"{DIM}{'─' * 60}{RESET}")
    print(f"  Files scanned: {files_scanned}")
    print(f"  Findings: {len(findings)}")
    print(f"  Score: {BOLD}{score}/100{RESET}  Grade: {BOLD}{g}{RESET}")
    print(f"{DIM}{'─' * 60}{RESET}")

    if not findings:
        print(f"\n  {BOLD}✅ No sandbox escape patterns detected.{RESET}\n")
        return score, g

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    print()
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev in by_sev:
            print(f"  {severity_color(sev)}{sev}{RESET}: {by_sev[sev]}")

    by_check: dict[str, int] = {}
    for f in findings:
        by_check[f.rule] = by_check.get(f.rule, 0) + 1
    print(f"\n{DIM}{'─' * 60}{RESET}")
    for rule in sorted(by_check.keys()):
        check = CHECKS[rule]
        color = severity_color(check["severity"])
        print(f"  {color}{rule}{RESET} {check['name']}: {by_check[rule]}")

    print(f"\n{DIM}{'─' * 60}{RESET}")
    current_file = ""
    for f in findings:
        if f.file != current_file:
            current_file = f.file
            print(f"\n  {BOLD}{current_file}{RESET}")

        color = severity_color(f.severity)
        print(f"    {DIM}L{f.line:<4}{RESET} {color}{f.severity:<8}{RESET} "
              f"{color}{f.rule}{RESET} {f.message}")
        if verbose and f.fix:
            print(f"         {DIM}Fix: {f.fix}{RESET}")

    print()
    return score, g


def print_json(auditor: SandboxAuditor, files_scanned: int,
               severity_filter: str | None = None,
               ignore_rules: set[str] | None = None) -> tuple[int, str]:
    findings = auditor.findings
    if severity_filter:
        sev_idx = SEVERITY_ORDER.get(severity_filter.upper(), 99)
        findings = [f for f in findings if SEVERITY_ORDER[f.severity] <= sev_idx]
    if ignore_rules:
        findings = [f for f in findings if f.rule not in ignore_rules]

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.line))
    score = compute_score(findings)
    g = grade(score)

    result = {
        "tool": "sandboxaudit",
        "version": __version__,
        "files_scanned": files_scanned,
        "score": score,
        "grade": g,
        "summary": {sev: sum(1 for f in findings if f.severity == sev)
                     for sev in SEVERITY_ORDER if any(f.severity == sev for f in findings)},
        "findings": [f.to_dict() for f in findings],
    }
    print(json.dumps(result, indent=2))
    return score, g


# ── CLI ──────────────────────────────────────────────────────────────


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="sandboxaudit",
        description="🔒 Python Sandbox Escape Pattern Detector — screen code before sandbox execution",
    )
    parser.add_argument("paths", nargs="*", default=["."],
                        help="Files or directories to scan (default: current directory)")
    parser.add_argument("--check", action="store_true",
                        help="CI mode: exit 1 if grade below threshold")
    parser.add_argument("--threshold", default="C",
                        help="Minimum passing grade for --check (default: C)")
    parser.add_argument("--json", dest="json_output", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--severity",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Minimum severity to report")
    parser.add_argument("--ignore", action="append", default=[],
                        help="Rules to ignore (e.g., --ignore SB12)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show fix suggestions and CVE references")
    parser.add_argument("--version", action="version",
                        version=f"sandboxaudit {__version__}")

    args = parser.parse_args()

    auditor = SandboxAuditor()
    total_files = 0
    ignore_rules = set(args.ignore)

    for path in args.paths:
        if path == "-":
            source = sys.stdin.read()
            auditor.check_file("<stdin>", source)
            total_files += 1
        else:
            total_files += scan_path(path, auditor)

    if total_files == 0:
        print("No Python files found.", file=sys.stderr)
        return 1

    if args.json_output:
        score, g = print_json(auditor, total_files, args.severity, ignore_rules)
    else:
        score, g = print_results(auditor, total_files, args.verbose,
                                  args.severity, ignore_rules)

    if args.check:
        threshold_score = {"A+": 95, "A": 90, "B": 80, "C": 70, "D": 60, "F": 0}
        min_score = threshold_score.get(args.threshold.upper(), 70)
        if score < min_score:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
