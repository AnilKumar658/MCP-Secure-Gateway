"""
gateway/approval.py
L3 approval queue — stores pending requests, processes approve/deny
decisions, and grants time-boxed elevations on the session.

Flow
----
1. pipeline._l3() or _p123() calls approval_queue.enqueue(session, server, tool, args)
   → returns an ApprovalRequest with status="pending"
2. The dashboard, console, or scripted approver calls approval_queue.approve()
   → marks request "approved", calls session.grant_elevation(ttl, tools)
3. pipeline re-evaluates: session.has_active_elevation() returns True → ALLOW
4. After TTL seconds, elevation auto-expires.

Features:
- ConsoleApprover: interactive console prompt (Approve? y/n) with auto-deny on timeout.
- ScriptedApprover: automated deterministic approver for experiments and test suites.

Standard library only.
"""
from __future__ import annotations

import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from gateway.session import SessionState


# ---------------------------------------------------------------------------
# ApprovalRequest
# ---------------------------------------------------------------------------

@dataclass
class ApprovalRequest:
    """
    A single pending (or resolved) L3/P123 approval request.
    """
    request_id:  str                      = field(default_factory=lambda: str(uuid.uuid4()))
    session_id:  str                      = ""
    server:      str                      = ""
    tool:        str                      = ""
    args:        dict[str, Any]           = field(default_factory=dict)
    reason:      str                      = ""
    created_at:  float                    = field(default_factory=time.time)
    status:      str                      = "pending"   # pending|approved|denied|expired
    decided_at:  float | None             = None
    meta:        dict[str, Any]           = field(default_factory=dict)

    def is_pending(self) -> bool:
        return self.status == "pending"

    def age(self) -> float:
        """Seconds since request was created."""
        return time.time() - self.created_at

    def __repr__(self) -> str:
        return (
            f"ApprovalRequest("
            f"id={self.request_id[:8]}…, "
            f"({self.server}.{self.tool}), "
            f"status={self.status})"
        )


# ---------------------------------------------------------------------------
# ApprovalQueue
# ---------------------------------------------------------------------------

class ApprovalQueue:
    """
    Stores and resolves approval requests.
    """

    DEFAULT_TTL: int = 60  # seconds

    def __init__(self, default_ttl: int = DEFAULT_TTL) -> None:
        self.default_ttl: int = default_ttl
        self._queue: dict[str, ApprovalRequest] = {}

    # -- Enqueue -------------------------------------------------------------

    def enqueue(
        self,
        session: SessionState,
        server: str,
        tool:   str,
        args:   dict[str, Any],
        reason: str = "",
        meta:   dict[str, Any] | None = None,
    ) -> ApprovalRequest:
        req = ApprovalRequest(
            session_id=session.session_id,
            server=server,
            tool=tool,
            args=dict(args),
            reason=reason or f"Sensitive tool '{tool}' on server '{server}' requires approval.",
            meta=dict(meta) if meta else {},
        )
        self._queue[req.request_id] = req
        return req

    # -- Decision ------------------------------------------------------------

    def approve(
        self,
        request_id: str,
        session:    SessionState,
        ttl:        int | None = None,
    ) -> bool:
        req = self._queue.get(request_id)
        if req is None or req.status != "pending":
            return False
        effective_ttl = ttl if ttl is not None else self.default_ttl
        req.status     = "approved"
        req.decided_at = time.time()
        # Grant elevation scoped to exactly this tool
        session.grant_elevation(
            ttl=effective_ttl,
            tools=[(req.server, req.tool)],
        )
        return True

    def deny(self, request_id: str, reason: str = "") -> bool:
        req = self._queue.get(request_id)
        if req is None or req.status != "pending":
            return False
        req.status     = "denied"
        req.decided_at = time.time()
        if reason:
            req.meta["deny_reason"] = reason
        return True

    def expire_stale(self, max_age: float | None = None) -> int:
        cutoff = time.time() - (max_age if max_age is not None else self.default_ttl)
        count = 0
        for req in self._queue.values():
            if req.status == "pending" and req.created_at < cutoff:
                req.status     = "expired"
                req.decided_at = time.time()
                count += 1
        return count

    # -- Queries -------------------------------------------------------------

    def get(self, request_id: str) -> ApprovalRequest | None:
        return self._queue.get(request_id)

    def pending(self) -> list[ApprovalRequest]:
        return [r for r in self._queue.values() if r.status == "pending"]

    def all_requests(self) -> list[ApprovalRequest]:
        return list(self._queue.values())

    def clear(self) -> int:
        n = len(self._queue)
        self._queue.clear()
        return n

    def __len__(self) -> int:
        return len(self._queue)

    def __repr__(self) -> str:
        pending = sum(1 for r in self._queue.values() if r.status == "pending")
        return f"ApprovalQueue({pending} pending / {len(self._queue)} total)"


# ===========================================================================
# Interactive Console Approver
# ===========================================================================

class ConsoleApprover:
    """
    Prompts human operator via console with timeout:
      [APPROVAL REQUIRED] Call: git.force_push({'branch': 'dev'})
      Risk score: 0.68 | Reasons: ...
      Approve? (y/n) [timeout in 30s]:
    Auto-denies if no input received within timeout.
    """

    def __init__(self, timeout_seconds: float = 30.0) -> None:
        self.timeout = timeout_seconds

    def prompt(
        self,
        request: ApprovalRequest,
        queue: ApprovalQueue,
        session: SessionState,
        ttl: int | None = None,
    ) -> bool:
        score = request.meta.get("risk_score", "N/A")
        reasons = request.reason

        print("\n" + "=" * 60)
        print(" [HUMAN APPROVAL REQUIRED]")
        print(f" Request ID : {request.request_id}")
        print(f" Target Call: {request.server}.{request.tool}")
        print(f" Arguments  : {request.args}")
        print(f" Risk Score : {score}")
        print(f" Reason     : {reasons}")
        print(f" Timeout    : {self.timeout}s (auto-deny on expiry)")
        print("=" * 60)

        user_input = [None]

        def _get_input():
            try:
                sys.stdout.write(f"Approve? (y/n) [{self.timeout:.0f}s]: ")
                sys.stdout.flush()
                user_input[0] = sys.stdin.readline().strip().lower()
            except Exception:
                user_input[0] = "n"

        thread = threading.Thread(target=_get_input, daemon=True)
        thread.start()
        thread.join(self.timeout)

        if user_input[0] is None:
            print("\n[TIMEOUT] No response within timeout — auto-denying request.")
            queue.deny(request.request_id, reason="Timed out waiting for operator response")
            return False

        if user_input[0] in ("y", "yes"):
            print("[APPROVED] Access elevated for this operation.")
            queue.approve(request.request_id, session, ttl=ttl)
            return True
        else:
            print("[DENIED] Operation rejected by operator.")
            queue.deny(request.request_id, reason="Explicitly denied by operator")
            return False


# ===========================================================================
# Scripted Approver (for Automated Experiments & Tests)
# ===========================================================================

class ScriptedApprover:
    """
    Automated approver for experiments and reproducible evaluation.

    Policies:
      - "approve_all"     : approves all pending requests immediately.
      - "deny_all"        : denies all pending requests immediately.
      - "timeout"         : simulates operator timeout (auto-denies).
      - custom callable   : fn(request) -> bool
    """

    def __init__(
        self,
        policy: str | Callable[[ApprovalRequest], bool] = "approve_all",
        elevation_ttl: int = 60,
    ) -> None:
        self.policy = policy
        self.elevation_ttl = elevation_ttl
        self.decision_log: list[dict[str, Any]] = []

    def resolve(
        self,
        request: ApprovalRequest,
        queue: ApprovalQueue,
        session: SessionState,
    ) -> bool:
        decision = False
        reason = ""

        if callable(self.policy):
            decision = bool(self.policy(request))
            reason = "Custom scripted policy"
        elif self.policy == "approve_all":
            decision = True
            reason = "Scripted approve_all"
        elif self.policy == "deny_all":
            decision = False
            reason = "Scripted deny_all"
        elif self.policy == "timeout":
            decision = False
            reason = "Scripted timeout auto-deny"
        else:
            decision = False
            reason = f"Unknown policy '{self.policy}' — defaulted to deny"

        if decision:
            queue.approve(request.request_id, session, ttl=self.elevation_ttl)
        else:
            queue.deny(request.request_id, reason=reason)

        self.decision_log.append({
            "request_id": request.request_id,
            "server": request.server,
            "tool": request.tool,
            "approved": decision,
            "reason": reason,
            "timestamp": time.time(),
        })
        return decision
