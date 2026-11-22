"""
servers/file_server.py
Mock MCP server — File-system operations.

Tools
-----
read_file(path)              effect=read
write_file(path, content)    effect=write

Fake sandbox
------------
The in-memory filesystem is pre-populated with several files, including a
sensitive .env file containing a fake API key.  Path-traversal attempts
(../) are detected and rejected at the server level (a second line of
defence after the gateway's Layer A).
"""
from __future__ import annotations
from typing import Any


# ---------------------------------------------------------------------------
# In-memory fake filesystem
# ---------------------------------------------------------------------------
_FS: dict[str, str] = {
    ".env":               "API_KEY=FAKE123\nDB_PASS=supersecret_fake\n",
    "README.md":          "# Fake Project\nThis is an in-memory fake repository.\n",
    "src/main.py":        "def main():\n    print('hello world')\n",
    "src/auth.py":        "SECRET = 'not-a-real-secret'\ndef authenticate(token): ...\n",
    "docs/design.txt":    "Design notes: lorem ipsum dolor sit amet.\n",
    "data/users.csv":     "id,name,email\n1,Alice,alice@example.fake\n2,Bob,bob@example.fake\n",
}


# ---------------------------------------------------------------------------
# Tool metadata catalogue
# ---------------------------------------------------------------------------
_TOOLS: list[dict] = [
    {
        "name":        "read_file",
        "description": "Read the contents of a file from the fake sandbox.",
        "effect":      "read",
        "args_schema": {
            "path": {"type": "string", "description": "Relative file path", "required": True},
        },
    },
    {
        "name":        "write_file",
        "description": "Write (create or overwrite) a file in the fake sandbox.",
        "effect":      "write",
        "args_schema": {
            "path":    {"type": "string", "description": "Relative file path",  "required": True},
            "content": {"type": "string", "description": "File content to write", "required": True},
        },
    },
]


# ---------------------------------------------------------------------------
# Server class
# ---------------------------------------------------------------------------
class FileServer:
    """In-memory mock File MCP server."""

    SERVER_NAME = "file"

    def list_tools(self) -> list[dict]:
        return _TOOLS

    def call(self, tool: str, args: dict[str, Any]) -> dict:
        dispatch = {
            "read_file":  self._read_file,
            "write_file": self._write_file,
        }
        if tool not in dispatch:
            return self._err(tool, f"Unknown tool '{tool}'")
        try:
            result = dispatch[tool](args)
            effect = next(t["effect"] for t in _TOOLS if t["name"] == tool)
            return {"ok": True, "result": result,
                    "meta": {"server": self.SERVER_NAME, "tool": tool, "effect": effect}}
        except (KeyError, TypeError, ValueError, PermissionError) as exc:
            return self._err(tool, str(exc))

    # -- Tool implementations ------------------------------------------------

    def _sanitise_path(self, path: str) -> str:
        """
        Reject path-traversal attempts while preserving dotfiles (e.g. '.env').

        Rules:
          - '..' anywhere in the path is forbidden (traversal)
          - Absolute paths starting with '/' or '\\' are forbidden
          - Leading './' or '.\\ ' separators are stripped, but a bare
            leading dot (dotfile: '.env') is kept intact.
        """
        if ".." in path or path.startswith("/") or path.startswith("\\"):
            raise PermissionError(
                f"Path traversal detected: '{path}' — access denied by sandbox."
            )
        # Strip only explicit relative-path prefixes like "./" or ".\\"
        # Do NOT strip a lone leading "." that belongs to a dotfile name.
        while path.startswith("./") or path.startswith(".\\"):
            path = path[2:]
        return path

    def _read_file(self, args: dict) -> dict:
        path = self._sanitise_path(args["path"])
        if path not in _FS:
            raise ValueError(f"File not found: '{path}'")
        return {"path": path, "content": _FS[path], "size": len(_FS[path])}

    def _write_file(self, args: dict) -> dict:
        path    = self._sanitise_path(args["path"])
        content: str = args["content"]
        existed = path in _FS
        _FS[path] = content
        return {"path": path, "written": len(content), "created": not existed}

    @staticmethod
    def _err(tool: str, msg: str) -> dict:
        return {"ok": False, "error": msg,
                "meta": {"server": "file", "tool": tool, "effect": "unknown"}}
