"""
tests/test_session.py
Unit tests for gateway/session.py, gateway/approval.py and the
baseline L0-L3 pipeline in gateway/pipeline.py.

Run with:
    python -m unittest tests.test_session -v

Coverage targets
----------------
SessionState
  - creation defaults, repr
  - set_scope / add_to_scope / remove_from_scope / in_scope
  - grant_elevation / revoke_elevation / has_active_elevation
  - elevation auto-expiry (fake expired timestamp, no monkey-patching needed)
  - record_call / last_call / calls_by_decision / taint_store

SessionRegistry
  - create / get / close / purge_all / len

ApprovalQueue
  - enqueue / get / pending
  - approve → elevation granted on session
  - deny → no elevation
  - double-approve is a no-op
  - expire_stale

GatewayPipeline — L0
  - all effects: ALLOW

GatewayPipeline — L1
  - in-scope tool: ALLOW
  - out-of-scope tool: BLOCK
  - unknown server: BLOCK
  - null scope (unrestricted): ALLOW

GatewayPipeline — L2
  - read tool in scope: ALLOW
  - write tool in scope: BLOCK (layer="L2-readonly")
  - sensitive tool in scope: BLOCK (layer="L2-readonly")
  - out-of-scope: BLOCK (layer="L2-scope")

GatewayPipeline — L3
  - read tool: ALLOW
  - write tool: ALLOW
  - sensitive without elevation: APPROVAL
  - sensitive after approval (elevation active): ALLOW (layer="L3-elevation")
  - sensitive after elevation expires: APPROVAL again
  - out-of-scope sensitive: BLOCK (layer="L3-scope")
  - approve then deny same request: second deny returns False

Call-history recording
  - every pipeline.process() appends a record
  - calls_by_decision filters correctly
"""
from __future__ import annotations

import sys
import os
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gateway.session  import SessionState, SessionRegistry, Elevation
from gateway.approval import ApprovalQueue, ApprovalRequest
from gateway.pipeline import (
    GatewayPipeline, Decision,
    DECISION_ALLOW, DECISION_BLOCK, DECISION_APPROVAL, DECISION_DOWNGRADE,
)
from servers import REGISTRY as SERVER_REGISTRY


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_pipeline(ttl: int = 60) -> GatewayPipeline:
    q = ApprovalQueue(default_ttl=ttl)
    return GatewayPipeline(SERVER_REGISTRY, approval_queue=q)


def _action(server: str, tool: str, args: dict | None = None) -> dict:
    return {"server": server, "tool": tool, "args": args or {}}


def _expired_elevation(ttl: int = 60, tools=None) -> Elevation:
    """Return an Elevation whose expires_at is in the past."""
    now = time.time()
    return Elevation(
        granted_at=now - ttl - 10,
        expires_at=now - 1,       # 1 second ago
        ttl=ttl,
        granted_tools=frozenset(tools) if tools else None,
    )


# ---------------------------------------------------------------------------
# TestSessionState
# ---------------------------------------------------------------------------

class TestSessionState(unittest.TestCase):

    # -- Creation ------------------------------------------------------------

    def test_default_level_is_zero(self):
        s = SessionState()
        self.assertEqual(s.level, 0)

    def test_default_scope_is_none(self):
        s = SessionState()
        self.assertIsNone(s.scope)

    def test_default_elevation_is_none(self):
        s = SessionState()
        self.assertIsNone(s.elevation)

    def test_session_id_is_string(self):
        s = SessionState()
        self.assertIsInstance(s.session_id, str)
        self.assertGreater(len(s.session_id), 0)

    def test_repr_does_not_raise(self):
        s = SessionState(level=2)
        repr(s)  # must not raise

    # -- Scope management ----------------------------------------------------

    def test_set_scope_stores_frozenset(self):
        s = SessionState()
        s.set_scope([("git", "list_branches"), ("file", "read_file")])
        self.assertIsInstance(s.scope, frozenset)
        self.assertEqual(len(s.scope), 2)

    def test_in_scope_true(self):
        s = SessionState()
        s.set_scope([("git", "list_branches")])
        self.assertTrue(s.in_scope("git", "list_branches"))

    def test_in_scope_false(self):
        s = SessionState()
        s.set_scope([("git", "list_branches")])
        self.assertFalse(s.in_scope("git", "force_push"))

    def test_in_scope_none_scope_returns_true(self):
        s = SessionState()  # scope=None
        self.assertTrue(s.in_scope("any", "tool"))

    def test_add_to_scope(self):
        s = SessionState()
        s.set_scope([("git", "list_branches")])
        s.add_to_scope("file", "read_file")
        self.assertTrue(s.in_scope("file", "read_file"))
        self.assertTrue(s.in_scope("git", "list_branches"))

    def test_add_to_scope_when_scope_is_none(self):
        s = SessionState()  # scope=None
        s.add_to_scope("mail", "read_inbox")
        self.assertTrue(s.in_scope("mail", "read_inbox"))
        self.assertFalse(s.in_scope("mail", "send_mail"))

    def test_remove_from_scope(self):
        s = SessionState()
        s.set_scope([("git", "list_branches"), ("git", "commit_file")])
        s.remove_from_scope("git", "commit_file")
        self.assertFalse(s.in_scope("git", "commit_file"))
        self.assertTrue(s.in_scope("git", "list_branches"))

    def test_remove_from_scope_noop_when_absent(self):
        s = SessionState()
        s.set_scope([("git", "list_branches")])
        s.remove_from_scope("git", "nonexistent")  # must not raise
        self.assertEqual(len(s.scope), 1)

    def test_remove_from_scope_noop_when_none(self):
        s = SessionState()  # scope=None
        s.remove_from_scope("git", "list_branches")  # must not raise
        self.assertIsNone(s.scope)

    # -- Elevation management ------------------------------------------------

    def test_grant_elevation_creates_elevation(self):
        s = SessionState()
        elev = s.grant_elevation(ttl=30)
        self.assertIsNotNone(s.elevation)
        self.assertEqual(elev.ttl, 30)

    def test_grant_elevation_is_active(self):
        s = SessionState()
        s.grant_elevation(ttl=60)
        self.assertTrue(s.has_active_elevation())

    def test_grant_elevation_covers_specific_tool(self):
        s = SessionState()
        s.grant_elevation(ttl=60, tools=[("git", "force_push")])
        self.assertTrue(s.has_active_elevation("git", "force_push"))
        self.assertFalse(s.has_active_elevation("git", "merge_pr"))

    def test_grant_elevation_none_tools_covers_all(self):
        s = SessionState()
        s.grant_elevation(ttl=60, tools=None)
        self.assertTrue(s.has_active_elevation("any", "tool"))

    def test_revoke_elevation(self):
        s = SessionState()
        s.grant_elevation(ttl=60)
        s.revoke_elevation()
        self.assertIsNone(s.elevation)
        self.assertFalse(s.has_active_elevation())

    def test_expired_elevation_is_not_active(self):
        s = SessionState()
        s.elevation = _expired_elevation()
        self.assertFalse(s.has_active_elevation())

    def test_expired_elevation_auto_cleared(self):
        """has_active_elevation() must set elevation=None when expired."""
        s = SessionState()
        s.elevation = _expired_elevation()
        s.has_active_elevation()  # triggers auto-expire
        self.assertIsNone(s.elevation)

    def test_expired_elevation_does_not_cover_tool(self):
        s = SessionState()
        s.elevation = _expired_elevation(tools=[("git", "force_push")])
        self.assertFalse(s.has_active_elevation("git", "force_push"))

    def test_no_elevation_has_active_returns_false(self):
        s = SessionState()
        self.assertFalse(s.has_active_elevation())
        self.assertFalse(s.has_active_elevation("git", "force_push"))

    # -- Call history --------------------------------------------------------

    def test_record_call_appends(self):
        s = SessionState()
        s.record_call({"call_id": "abc", "decision": "ALLOW"})
        self.assertEqual(len(s.call_history), 1)

    def test_last_call_none_when_empty(self):
        s = SessionState()
        self.assertIsNone(s.last_call())

    def test_last_call_returns_latest(self):
        s = SessionState()
        s.record_call({"call_id": "1", "decision": "ALLOW"})
        s.record_call({"call_id": "2", "decision": "BLOCK"})
        self.assertEqual(s.last_call()["call_id"], "2")

    def test_calls_by_decision(self):
        s = SessionState()
        s.record_call({"decision": "ALLOW"})
        s.record_call({"decision": "BLOCK"})
        s.record_call({"decision": "ALLOW"})
        allowed = s.calls_by_decision("ALLOW")
        self.assertEqual(len(allowed), 2)
        blocked = s.calls_by_decision("BLOCK")
        self.assertEqual(len(blocked), 1)

    # -- Taint store ---------------------------------------------------------

    def test_store_and_get_taint(self):
        s = SessionState()
        s.store_taint("call-1", {"source": "web", "level": 0.9})
        result = s.get_taint("call-1")
        self.assertEqual(result["source"], "web")

    def test_get_taint_missing_returns_none(self):
        s = SessionState()
        self.assertIsNone(s.get_taint("nonexistent"))


# ---------------------------------------------------------------------------
# TestElevation (unit)
# ---------------------------------------------------------------------------

class TestElevation(unittest.TestCase):

    def test_active_elevation_is_active(self):
        now = time.time()
        elev = Elevation(granted_at=now, expires_at=now + 60, ttl=60, granted_tools=None)
        self.assertTrue(elev.is_active())

    def test_expired_elevation_is_not_active(self):
        now = time.time()
        elev = Elevation(granted_at=now - 70, expires_at=now - 1, ttl=60, granted_tools=None)
        self.assertFalse(elev.is_active())

    def test_seconds_remaining_positive_when_active(self):
        now = time.time()
        elev = Elevation(granted_at=now, expires_at=now + 60, ttl=60, granted_tools=None)
        self.assertGreater(elev.seconds_remaining(), 0)

    def test_seconds_remaining_negative_when_expired(self):
        now = time.time()
        elev = Elevation(granted_at=now - 70, expires_at=now - 1, ttl=60, granted_tools=None)
        self.assertLess(elev.seconds_remaining(), 0)

    def test_covers_specific_tool_when_in_set(self):
        now = time.time()
        elev = Elevation(
            granted_at=now, expires_at=now + 60, ttl=60,
            granted_tools=frozenset({("git", "force_push")}),
        )
        self.assertTrue(elev.covers("git", "force_push"))
        self.assertFalse(elev.covers("git", "merge_pr"))

    def test_covers_all_when_tools_is_none(self):
        now = time.time()
        elev = Elevation(granted_at=now, expires_at=now + 60, ttl=60, granted_tools=None)
        self.assertTrue(elev.covers("any", "thing"))

    def test_covers_returns_false_when_expired(self):
        now = time.time()
        elev = Elevation(
            granted_at=now - 70, expires_at=now - 1, ttl=60,
            granted_tools=frozenset({("git", "force_push")}),
        )
        self.assertFalse(elev.covers("git", "force_push"))

    def test_repr_shows_active_status(self):
        now = time.time()
        elev = Elevation(granted_at=now, expires_at=now + 60, ttl=60, granted_tools=None)
        self.assertIn("left", repr(elev))

    def test_repr_shows_expired_status(self):
        now = time.time()
        elev = Elevation(granted_at=now - 70, expires_at=now - 1, ttl=60, granted_tools=None)
        self.assertIn("EXPIRED", repr(elev))


# ---------------------------------------------------------------------------
# TestSessionRegistry
# ---------------------------------------------------------------------------

class TestSessionRegistry(unittest.TestCase):

    def setUp(self):
        self.reg = SessionRegistry()

    def test_create_returns_session(self):
        s = self.reg.create(level=1)
        self.assertIsInstance(s, SessionState)
        self.assertEqual(s.level, 1)

    def test_get_returns_session(self):
        s = self.reg.create()
        found = self.reg.get(s.session_id)
        self.assertIs(found, s)

    def test_get_missing_returns_none(self):
        self.assertIsNone(self.reg.get("nonexistent-id"))

    def test_create_with_scope(self):
        s = self.reg.create(scope=[("git", "list_branches")])
        self.assertTrue(s.in_scope("git", "list_branches"))
        self.assertFalse(s.in_scope("git", "force_push"))

    def test_create_with_explicit_id(self):
        s = self.reg.create(session_id="fixed-id")
        self.assertEqual(s.session_id, "fixed-id")

    def test_len_tracks_sessions(self):
        self.assertEqual(len(self.reg), 0)
        self.reg.create()
        self.reg.create()
        self.assertEqual(len(self.reg), 2)

    def test_close_removes_session(self):
        s = self.reg.create()
        result = self.reg.close(s.session_id)
        self.assertTrue(result)
        self.assertIsNone(self.reg.get(s.session_id))

    def test_close_missing_returns_false(self):
        self.assertFalse(self.reg.close("ghost"))

    def test_all_sessions_snapshot(self):
        s1 = self.reg.create()
        s2 = self.reg.create()
        all_ = self.reg.all_sessions()
        self.assertEqual(len(all_), 2)
        ids = {s.session_id for s in all_}
        self.assertIn(s1.session_id, ids)
        self.assertIn(s2.session_id, ids)

    def test_purge_all(self):
        self.reg.create(); self.reg.create(); self.reg.create()
        n = self.reg.purge_all()
        self.assertEqual(n, 3)
        self.assertEqual(len(self.reg), 0)


# ---------------------------------------------------------------------------
# TestApprovalQueue
# ---------------------------------------------------------------------------

class TestApprovalQueue(unittest.TestCase):

    def setUp(self):
        self.q       = ApprovalQueue(default_ttl=60)
        self.session = SessionState(level=3)
        self.session.set_scope([("git", "force_push"), ("git", "merge_pr")])

    def test_enqueue_returns_pending_request(self):
        req = self.q.enqueue(self.session, "git", "force_push", {})
        self.assertEqual(req.status, "pending")
        self.assertEqual(req.server, "git")
        self.assertEqual(req.tool, "force_push")

    def test_get_returns_request(self):
        req = self.q.enqueue(self.session, "git", "force_push", {})
        found = self.q.get(req.request_id)
        self.assertIs(found, req)

    def test_pending_lists_pending_only(self):
        r1 = self.q.enqueue(self.session, "git", "force_push", {})
        r2 = self.q.enqueue(self.session, "git", "merge_pr",  {})
        self.q.approve(r1.request_id, self.session)
        pending = self.q.pending()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].request_id, r2.request_id)

    def test_approve_marks_approved(self):
        req = self.q.enqueue(self.session, "git", "force_push", {})
        result = self.q.approve(req.request_id, self.session)
        self.assertTrue(result)
        self.assertEqual(req.status, "approved")
        self.assertIsNotNone(req.decided_at)

    def test_approve_grants_elevation_on_session(self):
        req = self.q.enqueue(self.session, "git", "force_push", {})
        self.q.approve(req.request_id, self.session, ttl=60)
        self.assertTrue(self.session.has_active_elevation("git", "force_push"))

    def test_approve_elevation_scoped_to_approved_tool(self):
        req = self.q.enqueue(self.session, "git", "force_push", {})
        self.q.approve(req.request_id, self.session, ttl=60)
        # merge_pr was NOT approved — should not be covered
        self.assertFalse(self.session.has_active_elevation("git", "merge_pr"))

    def test_approve_nonexistent_returns_false(self):
        self.assertFalse(self.q.approve("ghost-id", self.session))

    def test_approve_already_approved_returns_false(self):
        req = self.q.enqueue(self.session, "git", "force_push", {})
        self.q.approve(req.request_id, self.session)
        self.assertFalse(self.q.approve(req.request_id, self.session))

    def test_deny_marks_denied(self):
        req = self.q.enqueue(self.session, "git", "force_push", {})
        result = self.q.deny(req.request_id)
        self.assertTrue(result)
        self.assertEqual(req.status, "denied")

    def test_deny_does_not_grant_elevation(self):
        req = self.q.enqueue(self.session, "git", "force_push", {})
        self.q.deny(req.request_id)
        self.assertFalse(self.session.has_active_elevation())

    def test_deny_already_approved_returns_false(self):
        req = self.q.enqueue(self.session, "git", "force_push", {})
        self.q.approve(req.request_id, self.session)
        self.assertFalse(self.q.deny(req.request_id))

    def test_expire_stale_marks_old_requests(self):
        req = self.q.enqueue(self.session, "git", "force_push", {})
        # Backdate the creation time so it appears old
        req.created_at -= 200
        expired = self.q.expire_stale(max_age=100)
        self.assertEqual(expired, 1)
        self.assertEqual(req.status, "expired")

    def test_expire_stale_ignores_recent(self):
        self.q.enqueue(self.session, "git", "force_push", {})
        expired = self.q.expire_stale(max_age=100)
        self.assertEqual(expired, 0)

    def test_expire_stale_ignores_resolved(self):
        req = self.q.enqueue(self.session, "git", "force_push", {})
        self.q.approve(req.request_id, self.session)
        req.created_at -= 200
        expired = self.q.expire_stale(max_age=100)
        self.assertEqual(expired, 0)

    def test_clear_removes_all(self):
        self.q.enqueue(self.session, "git", "force_push", {})
        self.q.enqueue(self.session, "git", "merge_pr",  {})
        n = self.q.clear()
        self.assertEqual(n, 2)
        self.assertEqual(len(self.q), 0)

    def test_len_counts_all_requests(self):
        self.q.enqueue(self.session, "git", "force_push", {})
        self.q.enqueue(self.session, "git", "merge_pr",  {})
        self.assertEqual(len(self.q), 2)


# ---------------------------------------------------------------------------
# TestL0Pipeline
# ---------------------------------------------------------------------------

class TestL0Pipeline(unittest.TestCase):
    """L0: everything passes, no checks."""

    def setUp(self):
        self.pipeline = _make_pipeline()
        self.session  = SessionState(level=0)

    def test_read_allowed(self):
        d = self.pipeline.process(_action("git", "list_branches"), self.session)
        self.assertEqual(d.decision, DECISION_ALLOW)
        self.assertEqual(d.layer, "L0")

    def test_write_allowed(self):
        d = self.pipeline.process(_action("git", "create_branch", {"name": "x"}), self.session)
        self.assertEqual(d.decision, DECISION_ALLOW)

    def test_sensitive_allowed(self):
        d = self.pipeline.process(_action("git", "force_push", {"branch": "main"}), self.session)
        self.assertEqual(d.decision, DECISION_ALLOW)

    def test_unknown_server_allowed_at_l0(self):
        """L0 bypasses the unknown-server pre-check."""
        d = self.pipeline.process(_action("nonexistent_server", "some_tool"), self.session)
        self.assertEqual(d.decision, DECISION_ALLOW)
        self.assertEqual(d.effect, "unknown")

    def test_every_effect_class_allowed(self):
        for server, tool in [
            ("git",  "list_branches"),   # read
            ("git",  "commit_file"),      # write
            ("git",  "force_push"),       # sensitive
            ("mail", "read_inbox"),       # read
            ("mail", "send_mail"),        # sensitive
            ("code", "run_python"),       # sensitive
        ]:
            args = {}
            if tool == "commit_file":
                args = {"path": "f.txt", "message": "m"}
            if tool == "force_push":
                args = {"branch": "main"}
            if tool == "send_mail":
                args = {"to": "a@b.fake", "body": "hi"}
            if tool == "run_python":
                args = {"code": "print(1)"}
            d = self.pipeline.process(_action(server, tool, args), self.session)
            self.assertEqual(d.decision, DECISION_ALLOW, msg=f"{server}.{tool} should ALLOW at L0")


# ---------------------------------------------------------------------------
# TestL1Pipeline
# ---------------------------------------------------------------------------

class TestL1Pipeline(unittest.TestCase):
    """L1: scope check only."""

    def setUp(self):
        self.pipeline = _make_pipeline()
        self.session  = SessionState(level=1)
        self.session.set_scope([
            ("git",  "list_branches"),
            ("git",  "commit_file"),
            ("file", "read_file"),
        ])

    def test_in_scope_read_allowed(self):
        d = self.pipeline.process(_action("git", "list_branches"), self.session)
        self.assertEqual(d.decision, DECISION_ALLOW)
        self.assertEqual(d.layer,    "L1")

    def test_in_scope_write_allowed(self):
        """L1 does not enforce read-only — that is L2's job."""
        d = self.pipeline.process(
            _action("git", "commit_file", {"path": "f.py", "message": "m"}),
            self.session,
        )
        self.assertEqual(d.decision, DECISION_ALLOW)

    def test_out_of_scope_blocked(self):
        d = self.pipeline.process(_action("git", "force_push", {"branch": "main"}), self.session)
        self.assertEqual(d.decision, DECISION_BLOCK)
        self.assertEqual(d.layer,    "L1")
        self.assertIn("scope", d.reason.lower())

    def test_different_server_out_of_scope(self):
        d = self.pipeline.process(_action("mail", "send_mail", {"to": "a@b", "body": "x"}), self.session)
        self.assertEqual(d.decision, DECISION_BLOCK)

    def test_unknown_server_blocked_at_l1(self):
        d = self.pipeline.process(_action("ghost_server", "some_tool"), self.session)
        self.assertEqual(d.decision, DECISION_BLOCK)
        self.assertEqual(d.layer,    "pre-check")

    def test_null_scope_allows_all(self):
        """A session at L1 with scope=None behaves like L0."""
        s = SessionState(level=1)  # scope=None
        d = self.pipeline.process(_action("git", "force_push", {"branch": "main"}), s)
        self.assertEqual(d.decision, DECISION_ALLOW)

    def test_history_recorded(self):
        self.pipeline.process(_action("git", "list_branches"), self.session)
        self.assertEqual(len(self.session.call_history), 1)
        self.assertEqual(self.session.call_history[0]["decision"], DECISION_ALLOW)


# ---------------------------------------------------------------------------
# TestL2Pipeline
# ---------------------------------------------------------------------------

class TestL2Pipeline(unittest.TestCase):
    """L2: scope check + read-only enforcement."""

    def setUp(self):
        self.pipeline = _make_pipeline()
        self.session  = SessionState(level=2)
        self.session.set_scope([
            ("git",  "list_branches"),   # read
            ("git",  "create_branch"),   # write
            ("git",  "force_push"),      # sensitive
            ("file", "read_file"),       # read
            ("mail", "read_inbox"),      # read
            ("code", "run_python"),      # sensitive
        ])

    def test_read_in_scope_allowed(self):
        d = self.pipeline.process(_action("git", "list_branches"), self.session)
        self.assertEqual(d.decision, DECISION_ALLOW)
        self.assertEqual(d.layer,    "L2")

    def test_write_in_scope_blocked(self):
        d = self.pipeline.process(
            _action("git", "create_branch", {"name": "new"}), self.session
        )
        self.assertEqual(d.decision, DECISION_BLOCK)
        self.assertEqual(d.layer,    "L2-readonly")
        self.assertIn("write", d.reason)

    def test_sensitive_in_scope_blocked(self):
        d = self.pipeline.process(
            _action("git", "force_push", {"branch": "main"}), self.session
        )
        self.assertEqual(d.decision, DECISION_BLOCK)
        self.assertEqual(d.layer,    "L2-readonly")
        self.assertIn("sensitive", d.reason)

    def test_code_run_python_blocked(self):
        d = self.pipeline.process(
            _action("code", "run_python", {"code": "print(1)"}), self.session
        )
        self.assertEqual(d.decision, DECISION_BLOCK)
        self.assertEqual(d.effect,   "sensitive")

    def test_out_of_scope_blocked_at_scope_layer(self):
        d = self.pipeline.process(_action("web", "fetch_url", {"url": "http://x.fake"}), self.session)
        self.assertEqual(d.decision, DECISION_BLOCK)
        self.assertEqual(d.layer,    "L2-scope")

    def test_multiple_read_tools_all_allowed(self):
        for server, tool in [("git", "list_branches"), ("file", "read_file"), ("mail", "read_inbox")]:
            d = self.pipeline.process(_action(server, tool), self.session)
            self.assertEqual(d.decision, DECISION_ALLOW, msg=f"{server}.{tool}")

    def test_history_contains_all_decisions(self):
        self.pipeline.process(_action("git", "list_branches"), self.session)       # ALLOW
        self.pipeline.process(_action("git", "create_branch", {"name": "b"}), self.session)  # BLOCK
        self.assertEqual(len(self.session.call_history), 2)
        decisions = {c["decision"] for c in self.session.call_history}
        self.assertIn(DECISION_ALLOW, decisions)
        self.assertIn(DECISION_BLOCK, decisions)


# ---------------------------------------------------------------------------
# TestL3Pipeline
# ---------------------------------------------------------------------------

class TestL3Pipeline(unittest.TestCase):
    """L3: scope + write allowed + sensitive → approval / elevation."""

    def setUp(self):
        self.pipeline = _make_pipeline(ttl=60)
        self.session  = SessionState(level=3)
        self.session.set_scope([
            ("git",  "list_branches"),   # read
            ("git",  "create_branch"),   # write
            ("git",  "force_push"),      # sensitive
            ("git",  "merge_pr"),        # sensitive
            ("mail", "send_mail"),       # sensitive
            ("file", "read_file"),       # read
        ])

    def test_read_tool_allowed(self):
        d = self.pipeline.process(_action("git", "list_branches"), self.session)
        self.assertEqual(d.decision, DECISION_ALLOW)
        self.assertEqual(d.layer,    "L3")

    def test_write_tool_allowed(self):
        d = self.pipeline.process(
            _action("git", "create_branch", {"name": "feature-x"}), self.session
        )
        self.assertEqual(d.decision, DECISION_ALLOW)
        self.assertEqual(d.layer,    "L3")

    def test_sensitive_without_elevation_needs_approval(self):
        d = self.pipeline.process(
            _action("git", "force_push", {"branch": "main"}), self.session
        )
        self.assertEqual(d.decision,         DECISION_APPROVAL)
        self.assertEqual(d.layer,            "L3-approval")
        self.assertIsNotNone(d.approval_request)
        self.assertEqual(d.approval_request.status, "pending")

    def test_approval_request_stored_in_queue(self):
        d = self.pipeline.process(
            _action("git", "force_push", {"branch": "main"}), self.session
        )
        req_id = d.approval_request.request_id
        found  = self.pipeline.approval.get(req_id)
        self.assertIsNotNone(found)
        self.assertEqual(found.status, "pending")

    def test_sensitive_after_approval_allowed(self):
        """Full happy path: request → approve → allowed under elevation."""
        # Step 1: request approval
        d1 = self.pipeline.process(
            _action("git", "force_push", {"branch": "main"}), self.session
        )
        self.assertEqual(d1.decision, DECISION_APPROVAL)
        req_id = d1.approval_request.request_id

        # Step 2: approve the request (simulates dashboard action)
        ok = self.pipeline.approval.approve(req_id, self.session, ttl=60)
        self.assertTrue(ok)

        # Step 3: retry — should now be ALLOW under elevation
        d2 = self.pipeline.process(
            _action("git", "force_push", {"branch": "main"}), self.session
        )
        self.assertEqual(d2.decision, DECISION_ALLOW)
        self.assertEqual(d2.layer,    "L3-elevation")
        self.assertIn("remaining", d2.reason)

    def test_elevation_covers_only_approved_tool(self):
        """Approving force_push must NOT elevate merge_pr."""
        d1 = self.pipeline.process(
            _action("git", "force_push", {"branch": "main"}), self.session
        )
        self.pipeline.approval.approve(d1.approval_request.request_id, self.session, ttl=60)

        # merge_pr still needs approval
        d2 = self.pipeline.process(
            _action("git", "merge_pr", {"pr_id": 42}), self.session
        )
        self.assertEqual(d2.decision, DECISION_APPROVAL)

    def test_sensitive_after_elevation_expires_needs_approval_again(self):
        """Once elevation expires, sensitive calls must be re-approved."""
        d1 = self.pipeline.process(
            _action("git", "force_push", {"branch": "main"}), self.session
        )
        self.pipeline.approval.approve(d1.approval_request.request_id, self.session, ttl=60)

        # Manually expire the elevation
        self.session.elevation = _expired_elevation(
            ttl=60, tools=[("git", "force_push")]
        )

        # Next call: elevation gone → back to APPROVAL
        d2 = self.pipeline.process(
            _action("git", "force_push", {"branch": "main"}), self.session
        )
        self.assertEqual(d2.decision, DECISION_APPROVAL)
        self.assertEqual(d2.layer,    "L3-approval")

    def test_out_of_scope_sensitive_blocked_not_queued(self):
        """Scope check runs BEFORE the approval queue — no request created."""
        d = self.pipeline.process(
            _action("code", "run_python", {"code": "print(1)"}), self.session
        )
        self.assertEqual(d.decision, DECISION_BLOCK)
        self.assertEqual(d.layer,    "L3-scope")
        self.assertIsNone(d.approval_request)

    def test_out_of_scope_read_blocked(self):
        d = self.pipeline.process(
            _action("web", "fetch_url", {"url": "http://x.fake"}), self.session
        )
        self.assertEqual(d.decision, DECISION_BLOCK)
        self.assertEqual(d.layer,    "L3-scope")

    def test_multiple_sensitive_each_needs_own_approval(self):
        d1 = self.pipeline.process(
            _action("git", "force_push", {"branch": "main"}), self.session
        )
        d2 = self.pipeline.process(
            _action("git", "merge_pr", {"pr_id": 1}), self.session
        )
        self.assertEqual(d1.decision, DECISION_APPROVAL)
        self.assertEqual(d2.decision, DECISION_APPROVAL)
        self.assertNotEqual(
            d1.approval_request.request_id,
            d2.approval_request.request_id,
        )

    def test_deny_keeps_tool_blocked(self):
        d1 = self.pipeline.process(
            _action("git", "force_push", {"branch": "main"}), self.session
        )
        self.pipeline.approval.deny(d1.approval_request.request_id)
        # Next attempt still needs approval (no elevation granted)
        d2 = self.pipeline.process(
            _action("git", "force_push", {"branch": "main"}), self.session
        )
        self.assertEqual(d2.decision, DECISION_APPROVAL)


# ---------------------------------------------------------------------------
# TestCallHistoryRecording
# ---------------------------------------------------------------------------

class TestCallHistoryRecording(unittest.TestCase):
    """Every pipeline.process() call must append a correct history record."""

    def setUp(self):
        self.pipeline = _make_pipeline()

    def test_history_has_required_keys(self):
        s = SessionState(level=0)
        self.pipeline.process(_action("git", "list_branches"), s)
        record = s.call_history[0]
        for key in ("call_id", "server", "tool", "args", "effect",
                    "decision", "reason", "layer", "timestamp"):
            self.assertIn(key, record, msg=f"Missing key: {key}")

    def test_history_records_decision_correctly(self):
        s = SessionState(level=2)
        s.set_scope([("git", "list_branches"), ("git", "create_branch")])
        self.pipeline.process(_action("git", "list_branches"), s)   # ALLOW
        self.pipeline.process(_action("git", "create_branch", {"name": "b"}), s)  # BLOCK
        decisions = [c["decision"] for c in s.call_history]
        self.assertEqual(decisions, [DECISION_ALLOW, DECISION_BLOCK])

    def test_calls_by_decision_matches_history(self):
        s = SessionState(level=1)
        s.set_scope([("git", "list_branches")])
        self.pipeline.process(_action("git", "list_branches"), s)
        self.pipeline.process(_action("git", "force_push", {"branch": "main"}), s)
        self.pipeline.process(_action("git", "list_branches"), s)
        allowed = s.calls_by_decision(DECISION_ALLOW)
        blocked = s.calls_by_decision(DECISION_BLOCK)
        self.assertEqual(len(allowed), 2)
        self.assertEqual(len(blocked), 1)

    def test_effect_is_recorded(self):
        s = SessionState(level=0)
        self.pipeline.process(_action("git", "list_branches"), s)
        self.assertEqual(s.call_history[0]["effect"], "read")

    def test_history_grows_with_each_call(self):
        s = SessionState(level=0)
        for i in range(5):
            self.pipeline.process(_action("git", "list_branches"), s)
        self.assertEqual(len(s.call_history), 5)


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
