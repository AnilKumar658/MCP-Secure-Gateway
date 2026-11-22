"""
servers/git_server.py
Mock MCP server — Git operations.

Tools
-----
list_branches()          effect=read
create_branch(name)      effect=write
commit_file(path,msg)    effect=write
delete_branch(name)      effect=write
force_push(branch)       effect=sensitive
merge_pr(pr_id)          effect=sensitive

Interface
---------
Every server exposes:
  list_tools() -> list[dict]
  call(tool, args) -> dict   keys: ok, result | error, meta
"""
from __future__ import annotations
from typing import Any


# ---------------------------------------------------------------------------
# In-memory fake repository state
# ---------------------------------------------------------------------------
_BRANCHES: list[str] = ["main", "dev", "feature/login"]
_COMMITS: list[dict] = [
    {"sha": "a1b2c3d", "branch": "main",         "msg": "Initial commit",    "file": "README.md"},
    {"sha": "d4e5f6a", "branch": "dev",           "msg": "Add auth module",   "file": "auth.py"},
    {"sha": "7890abc", "branch": "feature/login", "msg": "Login form draft",  "file": "login.html"},
]
_MERGED_PRS: list[int] = []
_FORCE_PUSHES: list[str] = []


# ---------------------------------------------------------------------------
# Tool metadata catalogue
# ---------------------------------------------------------------------------
_TOOLS: list[dict] = [
    {
        "name":        "list_branches",
        "description": "List all branches in the fake repository.",
        "effect":      "read",
        "args_schema": {},
    },
    {
        "name":        "create_branch",
        "description": "Create a new branch from main.",
        "effect":      "write",
        "args_schema": {
            "name": {"type": "string", "description": "Branch name", "required": True},
        },
    },
    {
        "name":        "commit_file",
        "description": "Commit a file change to a branch.",
        "effect":      "write",
        "args_schema": {
            "path":    {"type": "string", "description": "File path",       "required": True},
            "message": {"type": "string", "description": "Commit message",  "required": True},
            "branch":  {"type": "string", "description": "Target branch",   "required": False},
        },
    },
    {
        "name":        "delete_branch",
        "description": "Delete a branch from the repository.",
        "effect":      "write",
        "args_schema": {
            "name": {"type": "string", "description": "Branch name to delete", "required": True},
        },
    },
    {
        "name":        "force_push",
        "description": "Force-push a branch, overwriting remote history.",
        "effect":      "sensitive",
        "args_schema": {
            "branch": {"type": "string", "description": "Branch to force-push", "required": True},
        },
    },
    {
        "name":        "merge_pr",
        "description": "Merge a pull request by ID.",
        "effect":      "sensitive",
        "args_schema": {
            "pr_id": {"type": "integer", "description": "Pull-request ID", "required": True},
        },
    },
]


# ---------------------------------------------------------------------------
# Server class
# ---------------------------------------------------------------------------
class GitServer:
    """In-memory mock Git MCP server."""

    SERVER_NAME = "git"

    # -- Protocol interface --------------------------------------------------

    def list_tools(self) -> list[dict]:
        """Return the tool catalogue for this server."""
        return _TOOLS

    def call(self, tool: str, args: dict[str, Any]) -> dict:
        """
        Dispatch a tool call.

        Returns
        -------
        dict with keys:
          ok     (bool)
          result (Any)   — present when ok=True
          error  (str)   — present when ok=False
          meta   (dict)  — always present; contains effect, server, tool
        """
        dispatch = {
            "list_branches": self._list_branches,
            "create_branch": self._create_branch,
            "commit_file":   self._commit_file,
            "delete_branch": self._delete_branch,
            "force_push":    self._force_push,
            "merge_pr":      self._merge_pr,
        }
        if tool not in dispatch:
            return self._err(tool, f"Unknown tool '{tool}'")
        try:
            result = dispatch[tool](args)
            effect = next(t["effect"] for t in _TOOLS if t["name"] == tool)
            return {"ok": True, "result": result,
                    "meta": {"server": self.SERVER_NAME, "tool": tool, "effect": effect}}
        except (KeyError, TypeError, ValueError) as exc:
            return self._err(tool, str(exc))

    # -- Tool implementations ------------------------------------------------

    def _list_branches(self, _args: dict) -> dict:
        return {"branches": list(_BRANCHES)}

    def _create_branch(self, args: dict) -> dict:
        name: str = args["name"]
        if name in _BRANCHES:
            raise ValueError(f"Branch '{name}' already exists.")
        _BRANCHES.append(name)
        return {"created": name, "from": "main"}

    def _commit_file(self, args: dict) -> dict:
        import hashlib, datetime
        path:    str = args["path"]
        message: str = args["message"]
        branch:  str = args.get("branch", "main")
        if branch not in _BRANCHES:
            raise ValueError(f"Branch '{branch}' does not exist.")
        sha = hashlib.sha1(f"{path}{message}{datetime.datetime.utcnow()}".encode()).hexdigest()[:7]
        entry = {"sha": sha, "branch": branch, "msg": message, "file": path}
        _COMMITS.append(entry)
        return entry

    def _delete_branch(self, args: dict) -> dict:
        name: str = args["name"]
        if name == "main":
            raise ValueError("Cannot delete the default branch 'main'.")
        if name not in _BRANCHES:
            raise ValueError(f"Branch '{name}' not found.")
        _BRANCHES.remove(name)
        return {"deleted": name}

    def _force_push(self, args: dict) -> dict:
        branch: str = args["branch"]
        if branch not in _BRANCHES:
            raise ValueError(f"Branch '{branch}' not found.")
        _FORCE_PUSHES.append(branch)
        return {"force_pushed": branch, "warning": "Remote history rewritten."}

    def _merge_pr(self, args: dict) -> dict:
        pr_id = int(args["pr_id"])
        if pr_id in _MERGED_PRS:
            raise ValueError(f"PR #{pr_id} already merged.")
        _MERGED_PRS.append(pr_id)
        return {"merged_pr": pr_id, "into": "main", "status": "MERGED"}

    # -- Helpers -------------------------------------------------------------

    @staticmethod
    def _err(tool: str, msg: str) -> dict:
        return {"ok": False, "error": msg,
                "meta": {"server": "git", "tool": tool, "effect": "unknown"}}
