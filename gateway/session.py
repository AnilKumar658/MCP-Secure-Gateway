"""
gateway/session.py
SessionState, Elevation, and SessionRegistry — the stateful core of
the Dynamic Security Gateway.

Design
------
SessionState is a plain dataclass that holds all mutable per-session
data.  It is intentionally NOT thread-safe; concurrency is the caller's
responsibility (the pipeline processes one action at a time per session).

Elevation
---------
An Elevation represents a time-boxed relaxation of L3 restrictions
granted after a human approves a sensitive tool call.  Elevation is
optionally scoped to specific (server, tool) pairs; None means all tools
in scope are elevated.

Level semantics (enforced by pipeline.py):
  0  — L0: allow everything, no checks
  1  — L1: scope check only
  2  — L2: scope check + read-only enforcement (write/sensitive blocked)
  3  — L3: scope check + write allowed + sensitive requires approval/elevation

Standard library only (no third-party imports).
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Elevation
# ---------------------------------------------------------------------------

@dataclass
class Elevation:
    """
    Time-boxed permission elevation granted after L3 approval.

    Attributes
    ----------
    granted_at    : unix timestamp when the elevation was created
    expires_at    : unix timestamp when the elevation expires
    ttl           : original TTL in seconds (for display / logging)
    granted_tools : frozenset of (server, tool) pairs this elevation covers;
                    None means all in-scope tools are covered
    """
    granted_at:    float
    expires_at:    float
    ttl:           int
    granted_tools: frozenset[tuple[str, str]] | None  # None = all tools

    # -- Time checks ---------------------------------------------------------

    def is_active(self) -> bool:
        """Return True if the elevation has not yet expired."""
        return time.time() < self.expires_at

    def seconds_remaining(self) -> float:
        """Seconds until expiry (negative if already expired)."""
        return self.expires_at - time.time()

    def covers(self, server: str, tool: str) -> bool:
        """
        Return True if this elevation is still active AND covers the given
        (server, tool) pair.
        """
        if not self.is_active():
            return False
        if self.granted_tools is None:
            return True
        return (server, tool) in self.granted_tools

    def __repr__(self) -> str:
        remaining = self.seconds_remaining()
        scope = "all" if self.granted_tools is None else str(len(self.granted_tools))
        status = f"{remaining:.1f}s left" if remaining > 0 else "EXPIRED"
        return f"Elevation(tools={scope}, {status})"


# ---------------------------------------------------------------------------
# SessionState
# ---------------------------------------------------------------------------

@dataclass
class SessionState:
    """
    All mutable state for a single agent session.

    Fields
    ------
    session_id   : unique identifier (UUID string)
    level        : enforcement level — 0 (L0) through 3 (L3)
    scope        : frozenset of (server, tool) pairs allowed at L1+;
                   None means no scope restriction (used at L0 / before
                   set_scope is called)
    elevation    : active Elevation, or None
    taint_store  : dict keyed by call_id; populated by Layer B (layer2_taint)
    call_history : chronological list of call records written by pipeline.py
    created_at   : unix timestamp of session creation
    """
    session_id:   str                          = field(default_factory=lambda: str(uuid.uuid4()))
    level:        int                          = 0
    mode:         str | None                   = None
    scope:        frozenset | None             = None
    elevation:    Elevation | None             = None
    taint_store:  dict[str, Any]               = field(default_factory=dict)
    session_taint_level: float                 = 0.0
    taint_flows:  list[dict[str, Any]]         = field(default_factory=list)
    call_history: list[dict[str, Any]]         = field(default_factory=list)
    created_at:   float                        = field(default_factory=time.time)

    # -- Scope management ----------------------------------------------------

    def set_scope(self, tools: list[tuple[str, str]]) -> None:
        """
        Declare the allowed (server, tool) pairs for L1+ enforcement.

        Parameters
        ----------
        tools : list of (server_name, tool_name) tuples
        """
        self.scope = frozenset(tools)

    def add_to_scope(self, server: str, tool: str) -> None:
        """Add a single (server, tool) pair to the current scope."""
        existing = set(self.scope) if self.scope is not None else set()
        existing.add((server, tool))
        self.scope = frozenset(existing)

    def remove_from_scope(self, server: str, tool: str) -> None:
        """Remove a (server, tool) pair from scope (no-op if absent)."""
        if self.scope is None:
            return
        self.scope = frozenset(p for p in self.scope if p != (server, tool))

    def in_scope(self, server: str, tool: str) -> bool:
        """
        Return True if (server, tool) is within the declared scope.
        When scope is None (unset) every pair is considered in-scope.
        """
        if self.scope is None:
            return True
        return (server, tool) in self.scope

    # -- Elevation management ------------------------------------------------

    def grant_elevation(
        self,
        ttl: int = 60,
        tools: list[tuple[str, str]] | None = None,
    ) -> Elevation:
        """
        Grant a time-boxed elevation.

        Parameters
        ----------
        ttl   : seconds until the elevation expires (default 60)
        tools : specific (server, tool) pairs to elevate;
                None means all in-scope tools are elevated
        """
        now = time.time()
        self.elevation = Elevation(
            granted_at=now,
            expires_at=now + ttl,
            ttl=ttl,
            granted_tools=frozenset(tools) if tools is not None else None,
        )
        return self.elevation

    def revoke_elevation(self) -> None:
        """Immediately revoke any active elevation."""
        self.elevation = None

    def has_active_elevation(self, server: str = "", tool: str = "") -> bool:
        """
        Return True if an elevation is currently active.

        If server and tool are provided, also check that the elevation
        covers that specific (server, tool) pair.

        Side-effect: auto-expires and clears a stale elevation.
        """
        if self.elevation is None:
            return False
        # Auto-expire check
        if not self.elevation.is_active():
            self.elevation = None
            return False
        if server and tool:
            return self.elevation.covers(server, tool)
        return True

    # -- Call history --------------------------------------------------------

    def record_call(self, record: dict[str, Any]) -> None:
        """Append a call record to the session's history."""
        self.call_history.append(record)

    def last_call(self) -> dict[str, Any] | None:
        """Return the most recent call record, or None."""
        return self.call_history[-1] if self.call_history else None

    def calls_by_decision(self, decision: str) -> list[dict[str, Any]]:
        """Filter call history by decision string."""
        return [c for c in self.call_history if c.get("decision") == decision]

    # -- Taint store (used by Layer B) ---------------------------------------

    def store_taint(self, call_id: str, taint_info: Any) -> None:
        self.taint_store[call_id] = taint_info

    def get_taint(self, call_id: str) -> Any | None:
        return self.taint_store.get(call_id)

    # -- Representation ------------------------------------------------------

    def __repr__(self) -> str:
        elev = repr(self.elevation) if self.elevation else "none"
        scope_repr = len(self.scope) if self.scope is not None else "unrestricted"
        return (
            f"SessionState("
            f"id={self.session_id[:8]}…, "
            f"level=L{self.level}, "
            f"scope={scope_repr}, "
            f"elevation={elev}, "
            f"calls={len(self.call_history)})"
        )


# ---------------------------------------------------------------------------
# SessionRegistry
# ---------------------------------------------------------------------------

class SessionRegistry:
    """
    In-memory registry of active sessions.

    Usage
    -----
    registry = SessionRegistry()

    # Create a new session
    session = registry.create(
        level=1,
        scope=[("git", "list_branches"), ("git", "commit_file")],
    )

    # Look up later
    session = registry.get(session.session_id)

    # Destroy when done
    registry.close(session.session_id)
    """

    def __init__(self) -> None:
        self._sessions: dict[str, SessionState] = {}

    def create(
        self,
        level: int = 0,
        scope: list[tuple[str, str]] | None = None,
        session_id: str | None = None,
        mode: str | None = None,
    ) -> SessionState:
        """
        Create, register, and return a new SessionState.

        Parameters
        ----------
        level      : initial enforcement level (0-3)
        scope      : initial (server, tool) scope; None = unrestricted
        session_id : explicit ID (useful for tests); auto-generated if omitted
        mode       : ablation mode ("L0", "L1", "L2", "L3", "P1", "P12", "P123")
        """
        s = SessionState(
            session_id=session_id or str(uuid.uuid4()),
            level=level,
            mode=mode,
            scope=frozenset(scope) if scope is not None else None,
        )
        self._sessions[s.session_id] = s
        return s

    def get(self, session_id: str) -> SessionState | None:
        """Return the SessionState for the given ID, or None."""
        return self._sessions.get(session_id)

    def close(self, session_id: str) -> bool:
        """Remove a session from the registry.  Returns True if it existed."""
        return bool(self._sessions.pop(session_id, None))

    def all_sessions(self) -> list[SessionState]:
        """Return a snapshot list of all active sessions."""
        return list(self._sessions.values())

    def purge_all(self) -> int:
        """Clear every session.  Returns number removed (useful for tests)."""
        n = len(self._sessions)
        self._sessions.clear()
        return n

    def __len__(self) -> int:
        return len(self._sessions)

    def __repr__(self) -> str:
        return f"SessionRegistry({len(self._sessions)} active sessions)"
