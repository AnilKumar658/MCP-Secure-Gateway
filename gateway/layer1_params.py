"""
gateway/layer1_params.py
Layer A — Semantic Parameter & AST Validation  ("Identify")

Position in pipeline: pre-L1 (runs before scope / read-only checks).

Purpose
-------
Inspect the *content* of tool arguments before the call is dispatched to any
MCP server.  Every check returns zero or more Finding objects.  Findings are
either HARD (must trigger an immediate BLOCK regardless of risk score) or SOFT
(contribute additively to the numeric param_risk score, 0..1).

Checks implemented
------------------
1. PATH TRAVERSAL
   - Reject ../, absolute paths (/etc/, \\ prefixes).
   - Reject access to protected filenames (.env, .ssh, .gitconfig, passwd).
   - Simulates os.path.realpath-within-sandbox via os.path.normpath.

2. PROTECTED BRANCH
   - HARD block: delete_branch / force_push targeting main, master, prod,
     production, staging, release.
   - SOFT finding (score 0.40): commit_file / create_branch on a protected name.

3. CREDENTIAL REGEX
   - Scans every string argument for credential patterns:
       PEM private keys, AWS access keys, GitHub PATs, Slack tokens,
       generic KEY=VALUE / TOKEN=VALUE assignments, Bearer tokens,
       and the project's own test sentinel FAKE123.
   - Severity is context-sensitive:
       Outbound args (send_mail.body) → HARD block.
       Content args  (write_file.content, run_python.code) → SOFT (score 0.70).
       Other string args  → SOFT (score 0.40).
   - A generic high-entropy base64-like string always adds SOFT 0.20.

4. RECIPIENT ALLOWLIST
   - Only for mail.send_mail(to).
   - Domain extracted from the address must be in the approved_mail_domains set.
   - Non-allowlisted domain → HARD block.

5. AST VALIDATION (code arguments)
   - Only for code.run_python(code).
   - Parses the snippet with ast.parse (stdlib).
   - HARD block: os.system, subprocess.*, socket.*, smtplib.*, ftplib.*,
                 exec(), eval(), __import__(), ctypes.*, importlib.*,
                 open() on a sensitive path.
   - SOFT (0.30–0.50): open() on non-sensitive path, sys.*, shutil.*,
                       pathlib.*, compile().

Hard-rule hits always appear in hard_blocks AND in findings; soft findings
appear only in findings and contribute to param_risk.

Standard library only — no third-party imports.
"""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from typing import Any


# ===========================================================================
# Configuration
# ===========================================================================

@dataclass
class ValidatorConfig:
    """
    Tunable parameters for ParamValidator.
    All defaults reflect the project's offline fake-data environment.
    """

    # Logical sandbox root used for path normalisation checks.
    # Paths are expected to be relative and resolve inside this root.
    sandbox_root: str = "sandbox"

    # Branch names considered protected for destructive / write operations.
    protected_branches: frozenset[str] = field(
        default_factory=lambda: frozenset({
            "main", "master", "prod", "production", "staging", "release",
        })
    )

    # Email domains that the agent is allowed to send mail to.
    # Anything outside this list triggers a HARD block.
    approved_mail_domains: frozenset[str] = field(
        default_factory=lambda: frozenset({
            "example.fake", "project.fake", "boss.fake",
        })
    )

    # Filesystem paths / name fragments that are always protected.
    protected_path_fragments: tuple[str, ...] = (
        ".env", ".ssh", ".gitconfig", ".git-credentials",
        "passwd", "shadow", "authorized_keys",
        "id_rsa", "id_ecdsa", "id_ed25519", "id_dsa",
        "/etc/", "/proc/", "/sys/",
    )


# Default config singleton (used when callers pass nothing)
DEFAULT_CONFIG = ValidatorConfig()


# ===========================================================================
# Finding & Result types
# ===========================================================================

@dataclass
class Finding:
    """
    A single validation finding produced by one check.

    Attributes
    ----------
    check    : identifier of the check (e.g. "path_traversal")
    severity : "hard" (must block) or "soft" (contributes to score)
    score    : contribution to param_risk (0..1); HARD findings use 1.0
    reason   : human-readable explanation
    """
    check:    str
    severity: str    # "hard" | "soft"
    score:    float
    reason:   str

    def is_hard(self) -> bool:
        return self.severity == "hard"


@dataclass
class ParamCheckResult:
    """
    Aggregated result of all parameter checks for one tool call.

    Attributes
    ----------
    param_risk  : float 0..1 — aggregate risk of the argument content.
                  Any HARD finding pushes this to 1.0.
                  Soft findings accumulate additively (capped at 1.0).
    findings    : all Finding objects (hard + soft) in discovery order
    hard_blocks : human-readable reasons for every HARD finding;
                  non-empty list means the call MUST be blocked
    reasons     : human-readable reasons for ALL findings (for logging)
    is_clean    : True iff no HARD blocks were found
                  (soft findings are tolerated — the risk engine decides)
    server      : server name from the action
    tool        : tool name from the action
    """
    param_risk:   float
    findings:     list[Finding]
    hard_blocks:  list[str]
    reasons:      list[str]
    is_clean:     bool
    server:       str = ""
    tool:         str = ""

    def has_hard_blocks(self) -> bool:
        return bool(self.hard_blocks)

    def __repr__(self) -> str:
        return (
            f"ParamCheckResult("
            f"risk={self.param_risk:.3f}, "
            f"hard={len(self.hard_blocks)}, "
            f"soft={len(self.findings) - len(self.hard_blocks)}, "
            f"clean={self.is_clean})"
        )


# ===========================================================================
# Credential patterns
# ===========================================================================

# Each entry: (compiled_pattern, description, base_score, outbound_is_hard)
#
#   base_score        — score used in content/other-arg context (soft)
#   outbound_is_hard  — if True, finding in an OUTBOUND arg → HARD block
#
_CRED_PATTERNS: list[tuple[re.Pattern, str, float, bool]] = [
    # PEM private key header — always hard regardless of context
    (
        re.compile(
            r'-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE KEY',
            re.IGNORECASE,
        ),
        "PEM private key",
        1.0, True,
    ),
    # AWS IAM access key ID
    (
        re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
        "AWS access key ID",
        1.0, True,
    ),
    # GitHub PAT (new ghp_ format)
    (
        re.compile(r'\bghp_[A-Za-z0-9]{36}\b'),
        "GitHub personal access token",
        1.0, True,
    ),
    # Slack API tokens (bot, app, user, etc.)
    (
        re.compile(r'\bxox[baprs]-[0-9A-Za-z\-]{24,}\b'),
        "Slack API token",
        0.9, True,
    ),
    # Generic: KEY/TOKEN/SECRET assignment  (KEY=value or KEY: value)
    (
        re.compile(
            r'\b(?:API[_\-]?KEY|SECRET[_\-]?KEY|ACCESS[_\-]?TOKEN'
            r'|AUTH[_\-]?TOKEN|PRIVATE[_\-]?KEY|CLIENT[_\-]?SECRET)'
            r'\s*[=:]\s*\S{6,}',
            re.IGNORECASE,
        ),
        "API key / secret assignment",
        0.9, True,
    ),
    # Password assignments
    (
        re.compile(
            r'\b(?:PASSWORD|PASSWD|DB_PASS|DB_PASSWORD|MYSQL_PWD)\s*[=:]\s*\S{4,}',
            re.IGNORECASE,
        ),
        "password assignment",
        0.8, True,
    ),
    # HTTP Bearer token
    (
        re.compile(r'\bBearer\s+[A-Za-z0-9\-._~+/]{20,}', re.IGNORECASE),
        "HTTP Bearer token",
        0.8, True,
    ),
    # Fake test sentinel — FAKE123 is the value inside the sandbox .env
    (
        re.compile(r'\bFAKE123\b'),
        "test-environment API key value (matches .env content)",
        0.9, True,
    ),
    # Generic high-entropy base64-like string (potential encoded secret) — soft only
    (
        re.compile(r'[A-Za-z0-9+/]{32,}={0,2}\b'),
        "high-entropy string (possible encoded credential)",
        0.20, False,
    ),
]

# (server, tool, arg_name) triples that represent OUTBOUND data channels.
# A credential found in these args is a likely exfiltration attempt → HARD block.
_OUTBOUND_ARGS: frozenset[tuple[str, str, str]] = frozenset({
    ("mail", "send_mail", "body"),
    ("web",  "fetch_url", "url"),    # credential embedded in URL
})

# Args that contain user-controlled "content" but are not outbound channels.
# Credentials here are suspicious (soft) but not automatically blocked.
_CONTENT_ARGS: frozenset[tuple[str, str, str]] = frozenset({
    ("file", "write_file", "content"),
    ("code", "run_python", "code"),
    ("git",  "commit_file", "message"),
})


# ===========================================================================
# AST danger tables
# ===========================================================================

# Dangerous function/builtin names called directly: name → (description, score, is_hard)
_AST_DANGER_CALLS: dict[str, tuple[str, float, bool]] = {
    "exec":        ("exec() — arbitrary code execution",          1.0, True),
    "eval":        ("eval() — arbitrary expression evaluation",   1.0, True),
    "__import__":  ("__import__() — dynamic module loading",      0.9, True),
    "compile":     ("compile() — code compilation",               0.5, False),
    "open":        ("open() — file access (path checked)",        0.0, False),  # handled separately
}

# Dangerous module imports: module_root → (description, score, is_hard)
_AST_DANGER_MODULES: dict[str, tuple[str, float, bool]] = {
    "os":          ("os module — system access",                  0.9, True),
    "subprocess":  ("subprocess — shell/process execution",       1.0, True),
    "socket":      ("socket — raw network access",                1.0, True),
    "smtplib":     ("smtplib — SMTP email sending",               1.0, True),
    "ftplib":      ("ftplib — FTP file transfer",                 1.0, True),
    "ctypes":      ("ctypes — native code / FFI",                 1.0, True),
    "importlib":   ("importlib — dynamic import machinery",       0.9, True),
    "sys":         ("sys module — interpreter internals",         0.5, False),
    "shutil":      ("shutil — file/dir operations",               0.6, False),
    "pathlib":     ("pathlib — filesystem path access",           0.4, False),
    "requests":    ("requests — HTTP client",                     0.8, True),
    "urllib":      ("urllib — URL/HTTP client",                   0.7, False),
    "http":        ("http module — HTTP client/server",           0.6, False),
    "builtins":    ("builtins — bypass built-in names",           0.9, True),
}

# Path fragments that make an open() call a hard block
_SENSITIVE_OPEN_PATHS: tuple[str, ...] = (
    ".env", ".ssh", "/etc/", "passwd", "shadow",
    "authorized_keys", "id_rsa", "id_ecdsa", "id_ed25519",
    ".gitconfig", ".git-credentials",
)


# ===========================================================================
# ParamValidator
# ===========================================================================

class ParamValidator:
    """
    Runs all Layer-A checks on a single tool call and returns a
    ParamCheckResult.

    Usage
    -----
    validator = ParamValidator()
    result    = validator.validate("file", "write_file",
                                   {"path": "../etc/passwd", "content": "hi"})
    if result.has_hard_blocks():
        # pipeline → Decision(BLOCK, ...)
    else:
        # forward param_risk to Layer C risk engine
    """

    def __init__(self, config: ValidatorConfig | None = None) -> None:
        self.cfg = config or DEFAULT_CONFIG

    # -- Public entry point --------------------------------------------------

    def validate(
        self,
        server: str,
        tool:   str,
        args:   dict[str, Any],
    ) -> ParamCheckResult:
        """
        Run all parameter checks and return an aggregated result.

        Parameters
        ----------
        server : MCP server name (e.g. "git", "file", "mail")
        tool   : tool name        (e.g. "write_file")
        args   : argument dict as passed by the agent

        Returns
        -------
        ParamCheckResult — see class docstring for fields
        """
        findings: list[Finding] = []

        findings.extend(self._check_paths(server, tool, args))
        findings.extend(self._check_branches(server, tool, args))
        findings.extend(self._check_credentials(server, tool, args))
        findings.extend(self._check_mail_recipient(server, tool, args))
        findings.extend(self._check_ast(server, tool, args))

        return self._aggregate(server, tool, findings)

    # -----------------------------------------------------------------------
    # CHECK 1 — Path traversal & protected filenames
    # -----------------------------------------------------------------------

    def _check_paths(
        self, server: str, tool: str, args: dict[str, Any],
    ) -> list[Finding]:
        """
        Inspect file/git path arguments for traversal and protected names.

        Path arguments are identified by conventional arg names:
          path, file, filename, filepath
        plus the git `branch`/`name` args (not paths, handled by _check_branches).
        """
        PATH_ARGS = ("path", "file", "filename", "filepath")
        findings: list[Finding] = []

        for arg_name in PATH_ARGS:
            raw = args.get(arg_name)
            if not isinstance(raw, str) or not raw:
                continue
            findings.extend(self._validate_one_path(raw, arg_name))

        return findings

    def _validate_one_path(self, raw: str, arg_name: str) -> list[Finding]:
        """Check a single path string for traversal and protected names."""
        findings: list[Finding] = []

        # 1a. Traversal: ".." anywhere
        if ".." in raw:
            findings.append(Finding(
                check="path_traversal",
                severity="hard",
                score=1.0,
                reason=(
                    f"Path traversal detected in arg '{arg_name}': "
                    f"'{raw}' contains '..'"
                ),
            ))

        # 1b. Absolute path (Unix or Windows)
        if os.path.isabs(raw) or raw.startswith("/") or raw.startswith("\\"):
            findings.append(Finding(
                check="path_traversal",
                severity="hard",
                score=1.0,
                reason=(
                    f"Absolute path in arg '{arg_name}': "
                    f"'{raw}' escapes the sandbox"
                ),
            ))

        # 1c. Protected filename fragments (even inside relative paths)
        raw_lower = raw.lower().replace("\\", "/")
        for fragment in self.cfg.protected_path_fragments:
            frag_lower = fragment.lower()
            if frag_lower in raw_lower:
                findings.append(Finding(
                    check="protected_path",
                    severity="hard",
                    score=1.0,
                    reason=(
                        f"Protected path fragment '{fragment}' in arg "
                        f"'{arg_name}': '{raw}'"
                    ),
                ))
                break  # one protected-path finding per arg is enough

        # 1d. Sandbox escape via normpath (simulate realpath)
        #     os.path.normpath collapses redundant separators and . / ..
        #     If the result starts with ".." the path escapes the sandbox.
        try:
            normed = os.path.normpath(raw)
            if normed.startswith(".."):
                # Only add if not already caught by the ".." check above
                if ".." not in raw:  # e.g. unusual separator tricks
                    findings.append(Finding(
                        check="path_traversal",
                        severity="hard",
                        score=1.0,
                        reason=(
                            f"Normalised path escapes sandbox root: "
                            f"normpath('{raw}') = '{normed}'"
                        ),
                    ))
        except (TypeError, ValueError):
            pass

        return findings

    # -----------------------------------------------------------------------
    # CHECK 2 — Protected branch enforcement
    # -----------------------------------------------------------------------

    def _check_branches(
        self, server: str, tool: str, args: dict[str, Any],
    ) -> list[Finding]:
        """
        Block / flag operations on protected branches.

        Hard block:
          git.delete_branch(name)  on a protected name
          git.force_push(branch)   on a protected name

        Soft finding (score 0.40):
          git.commit_file(branch)  on a protected name
          git.create_branch(name)  with a protected name (unusual)
        """
        if server != "git":
            return []

        findings: list[Finding] = []

        if tool == "delete_branch":
            branch = args.get("name", "")
            if isinstance(branch, str) and branch.lower() in self.cfg.protected_branches:
                findings.append(Finding(
                    check="protected_branch",
                    severity="hard",
                    score=1.0,
                    reason=(
                        f"Attempt to delete protected branch '{branch}' — "
                        f"hard block"
                    ),
                ))

        elif tool == "force_push":
            branch = args.get("branch", "")
            if isinstance(branch, str) and branch.lower() in self.cfg.protected_branches:
                findings.append(Finding(
                    check="protected_branch",
                    severity="hard",
                    score=1.0,
                    reason=(
                        f"Force-push to protected branch '{branch}' — "
                        f"hard block"
                    ),
                ))

        elif tool == "commit_file":
            branch = args.get("branch", "")
            if isinstance(branch, str) and branch.lower() in self.cfg.protected_branches:
                findings.append(Finding(
                    check="protected_branch",
                    severity="soft",
                    score=0.40,
                    reason=(
                        f"Direct commit to protected branch '{branch}' — "
                        f"elevated risk (soft)"
                    ),
                ))

        elif tool == "create_branch":
            name = args.get("name", "")
            if isinstance(name, str) and name.lower() in self.cfg.protected_branches:
                findings.append(Finding(
                    check="protected_branch",
                    severity="soft",
                    score=0.30,
                    reason=(
                        f"Creating branch with protected name '{name}' — "
                        f"suspicious (soft)"
                    ),
                ))

        return findings

    # -----------------------------------------------------------------------
    # CHECK 3 — Credential regex
    # -----------------------------------------------------------------------

    def _check_credentials(
        self, server: str, tool: str, args: dict[str, Any],
    ) -> list[Finding]:
        """
        Scan all string arguments for credential patterns.
        Severity depends on whether the arg is an outbound data channel.
        """
        findings: list[Finding] = []

        for arg_name, value in args.items():
            if not isinstance(value, str) or not value:
                continue

            is_outbound = (server, tool, arg_name) in _OUTBOUND_ARGS
            is_content  = (server, tool, arg_name) in _CONTENT_ARGS

            for pattern, cred_name, base_score, outbound_hard in _CRED_PATTERNS:
                match = pattern.search(value)
                if match is None:
                    continue

                matched_text = match.group()[:40]  # truncate for safety

                if is_outbound and outbound_hard:
                    # Credential in an outbound channel → HARD (exfiltration)
                    findings.append(Finding(
                        check="credential_exfiltration",
                        severity="hard",
                        score=1.0,
                        reason=(
                            f"Credential pattern '{cred_name}' found in "
                            f"outbound arg '{arg_name}' of {server}.{tool} "
                            f"— potential exfiltration. Matched: '{matched_text}…'"
                        ),
                    ))
                elif is_content:
                    # Credential in a content arg → SOFT with elevated score
                    soft_score = min(base_score, 0.70)
                    findings.append(Finding(
                        check="credential_in_content",
                        severity="soft",
                        score=soft_score,
                        reason=(
                            f"Credential pattern '{cred_name}' found in "
                            f"content arg '{arg_name}' of {server}.{tool}. "
                            f"Matched: '{matched_text}…'"
                        ),
                    ))
                else:
                    # Other arg → SOFT with lower base score
                    soft_score = min(base_score, 0.40)
                    if soft_score > 0:
                        findings.append(Finding(
                            check="credential_in_arg",
                            severity="soft",
                            score=soft_score,
                            reason=(
                                f"Credential pattern '{cred_name}' found in "
                                f"arg '{arg_name}' of {server}.{tool}. "
                                f"Matched: '{matched_text}…'"
                            ),
                        ))

        return findings

    # -----------------------------------------------------------------------
    # CHECK 4 — Mail recipient allowlist
    # -----------------------------------------------------------------------

    def _check_mail_recipient(
        self, server: str, tool: str, args: dict[str, Any],
    ) -> list[Finding]:
        """
        For mail.send_mail, verify the 'to' address is in an approved domain.
        """
        if server != "mail" or tool != "send_mail":
            return []

        to_addr = args.get("to", "")
        if not isinstance(to_addr, str) or "@" not in to_addr:
            # Malformed address — also flag but as a different check
            if to_addr:
                return [Finding(
                    check="mail_recipient",
                    severity="hard",
                    score=1.0,
                    reason=(
                        f"Malformed recipient address '{to_addr}' — "
                        f"must contain '@'"
                    ),
                )]
            return []

        domain = to_addr.split("@")[-1].lower()

        if domain not in self.cfg.approved_mail_domains:
            return [Finding(
                check="mail_recipient",
                severity="hard",
                score=1.0,
                reason=(
                    f"Recipient domain '{domain}' is not in the approved "
                    f"allowlist {sorted(self.cfg.approved_mail_domains)}. "
                    f"Full address: '{to_addr}'"
                ),
            )]

        return []

    # -----------------------------------------------------------------------
    # CHECK 5 — AST validation for code arguments
    # -----------------------------------------------------------------------

    def _check_ast(
        self, server: str, tool: str, args: dict[str, Any],
    ) -> list[Finding]:
        """
        For code.run_python, parse the snippet with ast and inspect nodes.
        """
        if server != "code" or tool != "run_python":
            return []

        code = args.get("code", "")
        if not isinstance(code, str) or not code.strip():
            return []

        return self._ast_scan(code)

    def _ast_scan(self, code: str) -> list[Finding]:
        """Parse `code` and return AST-based findings."""
        findings: list[Finding] = []

        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            # Invalid Python — treat as soft risk (gateway can't evaluate it;
            # the pipeline may still let it through to the server for simulation)
            findings.append(Finding(
                check="ast_syntax_error",
                severity="soft",
                score=0.20,
                reason=f"Code argument has a syntax error: {exc}",
            ))
            return findings

        # Track which module roots were already flagged via an import statement.
        # Attribute-call findings on the same root are skipped to avoid
        # double-counting the same module risk.
        flagged_import_roots: set[str] = set()

        for node in ast.walk(tree):

            # -- Import statements -------------------------------------------
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                modules = (
                    [alias.name for alias in node.names]
                    if isinstance(node, ast.Import)
                    else [node.module or ""]
                )
                for mod_path in modules:
                    root = (mod_path or "").split(".")[0]
                    info = _AST_DANGER_MODULES.get(root)
                    if info:
                        desc, score, is_hard = info
                        flagged_import_roots.add(root)
                        findings.append(Finding(
                            check="ast_dangerous_import",
                            severity="hard" if is_hard else "soft",
                            score=score,
                            reason=f"Dangerous import detected: '{mod_path}' — {desc}",
                        ))

            # -- Function calls ----------------------------------------------
            elif isinstance(node, ast.Call):
                func = node.func

                # Direct name call: exec(...), eval(...), open(...)
                if isinstance(func, ast.Name):
                    name = func.id
                    if name in _AST_DANGER_CALLS:
                        desc, score, is_hard = _AST_DANGER_CALLS[name]
                        if name == "open":
                            # Inspect the first argument (path)
                            path_findings = self._check_open_path(node)
                            findings.extend(path_findings)
                        else:
                            findings.append(Finding(
                                check="ast_dangerous_call",
                                severity="hard" if is_hard else "soft",
                                score=score,
                                reason=f"Dangerous built-in call: {name}() — {desc}",
                            ))

                # Attribute call: os.system(...), subprocess.run(...)
                # If the module was already flagged at import level, skip the
                # call-level finding to prevent double-counting.
                elif isinstance(func, ast.Attribute):
                    obj_name = getattr(func.value, "id", "?")
                    root = obj_name.split(".")[0]
                    if root in flagged_import_roots:
                        continue   # already counted at import level
                    full_call = f"{obj_name}.{func.attr}"
                    info = _AST_DANGER_MODULES.get(root)
                    if info:
                        desc, score, is_hard = info
                        # Escalate attribute calls from always-hard modules
                        _ALWAYS_HARD_ROOTS = frozenset({
                            "os", "subprocess", "socket", "smtplib",
                            "ftplib", "ctypes", "importlib", "requests",
                        })
                        if root in _ALWAYS_HARD_ROOTS:
                            is_hard = True
                            score   = max(score, 0.9)
                        findings.append(Finding(
                            check="ast_dangerous_call",
                            severity="hard" if is_hard else "soft",
                            score=score,
                            reason=(
                                f"Dangerous attribute call: {full_call}() "
                                f"— {desc}"
                            ),
                        ))

        return findings

    def _check_open_path(self, call_node: ast.Call) -> list[Finding]:
        """
        Inspect the first argument of an open() call.
        Returns a HARD finding if it targets a sensitive path, SOFT otherwise.
        """
        if not call_node.args:
            # open() with no positional args — unusual, flag softly
            return [Finding(
                check="ast_open_call",
                severity="soft",
                score=0.30,
                reason="open() call with no path argument — suspicious",
            )]

        first_arg = call_node.args[0]
        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
            path = first_arg.value.lower().replace("\\", "/")
            for sensitive in _SENSITIVE_OPEN_PATHS:
                if sensitive.lower() in path:
                    return [Finding(
                        check="ast_open_sensitive_path",
                        severity="hard",
                        score=1.0,
                        reason=(
                            f"open() targets a sensitive path: "
                            f"'{first_arg.value}' — matches '{sensitive}'"
                        ),
                    )]
            # Non-sensitive literal path
            return [Finding(
                check="ast_open_call",
                severity="soft",
                score=0.30,
                reason=(
                    f"open() call on path '{first_arg.value}' — "
                    f"file access in sandboxed code"
                ),
            )]
        else:
            # Dynamic path (expression) — cannot statically determine safety
            return [Finding(
                check="ast_open_dynamic",
                severity="soft",
                score=0.50,
                reason=(
                    "open() call with a dynamic (non-literal) path argument — "
                    "cannot statically verify safety"
                ),
            )]

    # -----------------------------------------------------------------------
    # Aggregation helper
    # -----------------------------------------------------------------------

    def _aggregate(
        self,
        server:   str,
        tool:     str,
        findings: list[Finding],
    ) -> ParamCheckResult:
        """Combine all findings into a single ParamCheckResult."""
        hard_blocks = [f.reason for f in findings if f.is_hard()]
        reasons     = [f.reason for f in findings]

        # Soft scores accumulate; any HARD finding pushes to 1.0
        soft_total = sum(f.score for f in findings if not f.is_hard())
        has_hard   = bool(hard_blocks)

        if has_hard:
            param_risk = 1.0
        else:
            param_risk = round(min(1.0, soft_total), 4)

        return ParamCheckResult(
            param_risk=param_risk,
            findings=findings,
            hard_blocks=hard_blocks,
            reasons=reasons,
            is_clean=not has_hard,
            server=server,
            tool=tool,
        )
