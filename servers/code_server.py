"""
servers/code_server.py
Mock MCP server — Python code execution (simulated only).

Tools
-----
run_python(code)    effect=sensitive

IMPORTANT: This server NEVER executes any code. It analyses the submitted
snippet with Python's `ast` module (stdlib only) to:
  1. Confirm it is syntactically valid Python.
  2. Detect dangerous AST node types (Import, ImportFrom, Call to exec/eval,
     os/subprocess usage, open() calls, network-related names).
  3. Return a simulated stdout/stderr based on the detected category.

This design means the gateway's Layer A gets a head start (server-side AST
scan feeds the meta dict), and the layer still has its own independent check.
"""
from __future__ import annotations
from typing import Any
import ast


# ---------------------------------------------------------------------------
# Dangerous AST patterns
# ---------------------------------------------------------------------------
_DANGEROUS_CALLS = frozenset({
    "exec", "eval", "compile", "__import__",
    "subprocess", "popen", "system",
    "open", "read", "write",
    "socket", "connect", "send", "recv",
    "requests", "urllib", "http",
    "os", "sys", "shutil", "pathlib",
})

_DANGEROUS_MODULES = frozenset({
    "os", "sys", "subprocess", "socket", "shutil",
    "pathlib", "requests", "urllib", "http", "ftplib",
    "smtplib", "builtins", "importlib", "ctypes",
})


def _scan_ast(code: str) -> dict:
    """
    Parse code with ast and return a scan report.

    Returns
    -------
    dict:
      valid        (bool)   — syntactically correct Python
      dangerous    (bool)   — contains risky AST nodes
      findings     (list)   — human-readable descriptions
      syntax_error (str)    — set when valid=False
    """
    findings: list[str] = []
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return {"valid": False, "dangerous": False,
                "findings": [], "syntax_error": str(exc)}

    for node in ast.walk(tree):
        # Import statements
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = (
                [alias.name for alias in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
            )
            for name in names:
                root = (name or "").split(".")[0]
                if root in _DANGEROUS_MODULES:
                    findings.append(f"Dangerous import: '{name}'")

        # Function calls
        elif isinstance(node, ast.Call):
            # Direct name call: exec(...), eval(...)
            if isinstance(node.func, ast.Name) and node.func.id in _DANGEROUS_CALLS:
                findings.append(f"Dangerous call: {node.func.id}()")
            # Attribute call: os.system(...), subprocess.run(...)
            elif isinstance(node.func, ast.Attribute):
                full = f"{getattr(node.func.value, 'id', '?')}.{node.func.attr}"
                if node.func.attr in _DANGEROUS_CALLS:
                    findings.append(f"Dangerous attribute call: {full}")

    return {
        "valid":        True,
        "dangerous":    len(findings) > 0,
        "findings":     findings,
        "syntax_error": None,
    }


# ---------------------------------------------------------------------------
# Simulated output library
# ---------------------------------------------------------------------------
_SAFE_OUTPUTS: list[str] = [
    "42\n",
    "Hello, world!\n",
    "[1, 2, 3, 4, 5]\n",
    "{'status': 'ok', 'value': 99}\n",
    "True\n",
    "3.14159\n",
    "Done.\n",
]

def _simulate_output(code: str, scan: dict) -> dict:
    """Produce a fake execution result without running anything."""
    if not scan["valid"]:
        return {
            "stdout": "",
            "stderr": f"SyntaxError: {scan['syntax_error']}",
            "exit_code": 1,
            "simulated": True,
        }
    if scan["dangerous"]:
        return {
            "stdout": "",
            "stderr": (
                "SimulatedSecurityError: execution blocked by sandbox — "
                f"detected: {'; '.join(scan['findings'])}"
            ),
            "exit_code": 126,
            "simulated": True,
        }
    # Pick a deterministic "output" based on code hash so the same snippet
    # always returns the same simulated result.
    idx = hash(code) % len(_SAFE_OUTPUTS)
    return {
        "stdout":   _SAFE_OUTPUTS[idx],
        "stderr":   "",
        "exit_code": 0,
        "simulated": True,
    }


# ---------------------------------------------------------------------------
# Tool metadata catalogue
# ---------------------------------------------------------------------------
_TOOLS: list[dict] = [
    {
        "name":        "run_python",
        "description": (
            "Simulate execution of a Python snippet. "
            "Code is NEVER actually executed; output is simulated."
        ),
        "effect":      "sensitive",
        "args_schema": {
            "code": {"type": "string", "description": "Python source code to run", "required": True},
        },
    },
]


# ---------------------------------------------------------------------------
# Server class
# ---------------------------------------------------------------------------
class CodeServer:
    """Mock Code-execution MCP server (simulated, no real execution)."""

    SERVER_NAME = "code"

    def list_tools(self) -> list[dict]:
        return _TOOLS

    def call(self, tool: str, args: dict[str, Any]) -> dict:
        if tool != "run_python":
            return self._err(tool, f"Unknown tool '{tool}'")
        try:
            code: str = args["code"]
            scan   = _scan_ast(code)
            output = _simulate_output(code, scan)
            return {
                "ok": True,
                "result": output,
                "meta": {
                    "server":    self.SERVER_NAME,
                    "tool":      tool,
                    "effect":    "sensitive",
                    "ast_scan":  scan,   # Layer A can consume this directly
                },
            }
        except (KeyError, TypeError) as exc:
            return self._err(tool, str(exc))

    @staticmethod
    def _err(tool: str, msg: str) -> dict:
        return {"ok": False, "error": msg,
                "meta": {"server": "code", "tool": tool, "effect": "unknown"}}
