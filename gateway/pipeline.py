"""
gateway/pipeline.py
Dynamic Security Gateway Pipeline.

Architecture:
  Wires session/scope -> L1 -> L2 -> L3 -> Layer A -> Layer B -> Layer C -> decision

Supported Ablation Modes:
  - "L0"   : Baseline L0 — Allow everything unconditionally.
  - "L1"   : Baseline L1 — Scope check only.
  - "L2"   : Baseline L2 — Scope check + read-only enforcement.
  - "L3"   : Baseline L3 — Scope check + write allowed + sensitive requires approval / elevation.
  - "P1"   : Layer A (Param & AST Validation) + baseline scope/elevation.
  - "P12"  : Layer A + Layer B (Dynamic Taint Engine) + baseline.
  - "P123" : Full Dynamic Gateway — Layer A + Layer B + Layer C (Risk Scoring Engine) + baseline.

Latency:
  Measures processing latency with time.perf_counter() and records latency_ms in decision.meta.

Standard library only.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from gateway.session import SessionState
from gateway.approval import ApprovalQueue, ApprovalRequest
from gateway.layer1_params import ParamValidator, ParamCheckResult
from gateway.layer2_taint import TaintEngine, TaintCheckResult
from gateway.layer3_risk import RiskEngine, RiskAssessment


# ---------------------------------------------------------------------------
# Decision constants
# ---------------------------------------------------------------------------

DECISION_ALLOW     = "ALLOW"
DECISION_BLOCK     = "BLOCK"
DECISION_APPROVAL  = "APPROVAL"
DECISION_DOWNGRADE = "DOWNGRADE"


# ---------------------------------------------------------------------------
# Decision dataclass
# ---------------------------------------------------------------------------

@dataclass
class Decision:
    """
    The gateway's verdict for a single tool call.
    """
    decision:         str
    reason:           str
    call_id:          str                       = field(default_factory=lambda: str(uuid.uuid4()))
    server:           str                       = ""
    tool:             str                       = ""
    args:             dict[str, Any]            = field(default_factory=dict)
    effect:           str                       = ""
    layer:            str                       = ""
    approval_request: ApprovalRequest | None    = None
    timestamp:        float                     = field(default_factory=time.time)
    meta:             dict[str, Any]            = field(default_factory=dict)

    def is_allowed(self) -> bool:
        return self.decision == DECISION_ALLOW

    def is_blocked(self) -> bool:
        return self.decision == DECISION_BLOCK

    def needs_approval(self) -> bool:
        return self.decision == DECISION_APPROVAL

    def is_downgraded(self) -> bool:
        return self.decision == DECISION_DOWNGRADE

    def __repr__(self) -> str:
        return (
            f"Decision({self.decision}, layer={self.layer}, "
            f"{self.server}.{self.tool}, effect={self.effect})"
        )


# ---------------------------------------------------------------------------
# GatewayPipeline
# ---------------------------------------------------------------------------

class GatewayPipeline:
    """
    Integrated security gateway with ablation support across L0, L1, L2, L3,
    P1, P12, and P123.
    """

    def __init__(
        self,
        server_registry: dict[str, Any],
        approval_queue: ApprovalQueue | None = None,
        param_validator: ParamValidator | None = None,
        taint_engine: TaintEngine | None = None,
        risk_engine: RiskEngine | None = None,
        default_mode: str | None = None,
    ) -> None:
        self.servers = server_registry
        self.approval = approval_queue or ApprovalQueue()
        self.param_validator = param_validator or ParamValidator()
        self.taint_engine = taint_engine or TaintEngine()
        self.risk_engine = risk_engine or RiskEngine()
        self.default_mode = default_mode

    # -- Public Entry Point --------------------------------------------------

    def process(
        self,
        action: dict[str, Any],
        session: SessionState,
        mode: str | None = None,
    ) -> Decision:
        """
        Process a proposed tool call action through the configured pipeline mode.
        """
        t_start = time.perf_counter()

        server_name: str = action.get("server", "")
        tool_name:   str = action.get("tool",   "")
        args:        dict = dict(action.get("args", {}))
        call_id:     str = str(uuid.uuid4())

        # Determine effective mode: explicit arg -> session.mode -> default_mode -> fallback to L{level}
        effective_mode = mode or session.mode or self.default_mode or f"L{session.level}"

        # Resolve effect from registry
        effect = self._resolve_effect(server_name, tool_name)

        # Pre-flight check: reject unknown server/tool at L1+ / P1+
        if effective_mode != "L0" and effect == "unknown":
            decision = Decision(
                decision=DECISION_BLOCK,
                reason=(
                    f"Unknown server '{server_name}' or tool '{tool_name}' — "
                    f"not found in server registry"
                ),
                call_id=call_id, server=server_name, tool=tool_name,
                args=args, effect=effect, layer="pre-check",
                meta={"mode": effective_mode},
            )
            return self._finalize(decision, session, t_start)

        # Dispatch according to ablation mode
        match effective_mode:
            case "L0":
                decision = self._l0(server_name, tool_name, args, effect, call_id)
            case "L1":
                decision = self._l1(server_name, tool_name, args, effect, call_id, session)
            case "L2":
                decision = self._l2(server_name, tool_name, args, effect, call_id, session)
            case "L3":
                decision = self._l3(server_name, tool_name, args, effect, call_id, session)
            case "P1":
                decision = self._p1(server_name, tool_name, args, effect, call_id, session)
            case "P12":
                decision = self._p12(server_name, tool_name, args, effect, call_id, session)
            case "P123":
                decision = self._p123(server_name, tool_name, args, effect, call_id, session)
            case _:
                decision = Decision(
                    decision=DECISION_BLOCK,
                    reason=f"Invalid pipeline ablation mode: '{effective_mode}'",
                    call_id=call_id, server=server_name, tool=tool_name,
                    args=args, effect=effect, layer="pipeline",
                )

        decision.meta["mode"] = effective_mode
        return self._finalize(decision, session, t_start)

    # -- Observation Ingestion Helper ----------------------------------------

    def ingest_observation(
        self,
        session: SessionState,
        server: str,
        tool: str,
        observation: Any,
        call_id: str | None = None,
    ) -> Any:
        """
        Convenience hook to record tool outputs into Layer B Taint Engine.
        """
        return self.taint_engine.ingest_observation(session, server, tool, observation, call_id=call_id)

    # -----------------------------------------------------------------------
    # Baseline Levels (L0 - L3)
    # -----------------------------------------------------------------------

    def _l0(self, server: str, tool: str, args: dict, effect: str, call_id: str) -> Decision:
        return Decision(
            decision=DECISION_ALLOW,
            reason="L0: all calls permitted — no restrictions active",
            call_id=call_id, server=server, tool=tool,
            args=args, effect=effect, layer="L0",
        )

    def _l1(self, server: str, tool: str, args: dict, effect: str, call_id: str, session: SessionState) -> Decision:
        if not session.in_scope(server, tool):
            return Decision(
                decision=DECISION_BLOCK,
                reason=f"L1 scope violation: ({server}, {tool}) is not in declared session scope",
                call_id=call_id, server=server, tool=tool,
                args=args, effect=effect, layer="L1",
            )
        return Decision(
            decision=DECISION_ALLOW,
            reason=f"L1: ({server}, {tool}) is within declared scope",
            call_id=call_id, server=server, tool=tool,
            args=args, effect=effect, layer="L1",
        )

    def _l2(self, server: str, tool: str, args: dict, effect: str, call_id: str, session: SessionState) -> Decision:
        if not session.in_scope(server, tool):
            return Decision(
                decision=DECISION_BLOCK,
                reason=f"L2 scope violation: ({server}, {tool}) is not in declared session scope",
                call_id=call_id, server=server, tool=tool,
                args=args, effect=effect, layer="L2-scope",
            )
        if effect in ("write", "sensitive"):
            return Decision(
                decision=DECISION_BLOCK,
                reason=f"L2 read-only violation: tool '{tool}' has effect='{effect}' — only read tools permitted",
                call_id=call_id, server=server, tool=tool,
                args=args, effect=effect, layer="L2-readonly",
            )
        return Decision(
            decision=DECISION_ALLOW,
            reason=f"L2: read-class tool allowed (effect='{effect}')",
            call_id=call_id, server=server, tool=tool,
            args=args, effect=effect, layer="L2",
        )

    def _l3(self, server: str, tool: str, args: dict, effect: str, call_id: str, session: SessionState) -> Decision:
        if not session.in_scope(server, tool):
            return Decision(
                decision=DECISION_BLOCK,
                reason=f"L3 scope violation: ({server}, {tool}) is not in declared session scope",
                call_id=call_id, server=server, tool=tool,
                args=args, effect=effect, layer="L3-scope",
            )
        if effect == "sensitive":
            if session.has_active_elevation(server, tool):
                remaining = session.elevation.seconds_remaining() if session.elevation else 0.0
                return Decision(
                    decision=DECISION_ALLOW,
                    reason=f"L3: '{tool}' allowed under active elevation ({remaining:.1f}s remaining)",
                    call_id=call_id, server=server, tool=tool,
                    args=args, effect=effect, layer="L3-elevation",
                    meta={"elevation_remaining_s": remaining},
                )
            req = self.approval.enqueue(
                session=session, server=server, tool=tool, args=args,
                reason=f"Sensitive tool '{tool}' on server '{server}' requires human approval (L3).",
            )
            return Decision(
                decision=DECISION_APPROVAL,
                reason=f"L3: '{tool}' has effect=sensitive — queued for approval (request_id={req.request_id})",
                call_id=call_id, server=server, tool=tool,
                args=args, effect=effect, layer="L3-approval",
                approval_request=req,
            )
        return Decision(
            decision=DECISION_ALLOW,
            reason=f"L3: effect='{effect}' allowed without approval",
            call_id=call_id, server=server, tool=tool,
            args=args, effect=effect, layer="L3",
        )

    # -----------------------------------------------------------------------
    # Ablation Modes (P1, P12, P123)
    # -----------------------------------------------------------------------

    def _p1(
        self, server: str, tool: str, args: dict, effect: str, call_id: str, session: SessionState
    ) -> Decision:
        """Mode P1: Layer A (Param/AST Validation) + Baseline Scope & Elevation."""
        # 1. Layer A Param Check
        param_res = self.param_validator.validate(server, tool, args)
        if param_res.has_hard_blocks():
            return Decision(
                decision=DECISION_BLOCK,
                reason=f"P1 Layer A Hard Block: {'; '.join(param_res.hard_blocks)}",
                call_id=call_id, server=server, tool=tool,
                args=args, effect=effect, layer="LayerA-params",
                meta={"param_risk": param_res.param_risk, "hard_blocks": param_res.hard_blocks},
            )

        # 2. Baseline checks (Scope & Elevation)
        base_dec = self._l3(server, tool, args, effect, call_id, session)
        base_dec.meta["param_risk"] = param_res.param_risk
        return base_dec

    def _p12(
        self, server: str, tool: str, args: dict, effect: str, call_id: str, session: SessionState
    ) -> Decision:
        """Mode P12: Layer A + Layer B (Dynamic Taint Engine) + Baseline."""
        # 1. Layer A
        param_res = self.param_validator.validate(server, tool, args)
        if param_res.has_hard_blocks():
            return Decision(
                decision=DECISION_BLOCK,
                reason=f"P12 Layer A Hard Block: {'; '.join(param_res.hard_blocks)}",
                call_id=call_id, server=server, tool=tool,
                args=args, effect=effect, layer="LayerA-params",
                meta={"param_risk": param_res.param_risk, "hard_blocks": param_res.hard_blocks},
            )

        # 2. Layer B Taint Check
        taint_res = self.taint_engine.check_call(session, server, tool, args, call_id=call_id)
        if taint_res.action_recommendation == "BLOCK":
            return Decision(
                decision=DECISION_BLOCK,
                reason=f"P12 Layer B Block: {'; '.join(taint_res.reasons)}",
                call_id=call_id, server=server, tool=tool,
                args=args, effect=effect, layer="LayerB-taint",
                meta={"taint_score": taint_res.taint_score, "flows": [f.to_dict() for f in taint_res.flows]},
            )

        # 3. Baseline Scope & Elevation Check
        base_dec = self._l3(server, tool, args, effect, call_id, session)
        base_dec.meta["param_risk"] = param_res.param_risk
        base_dec.meta["taint_score"] = taint_res.taint_score
        return base_dec

    def _p123(
        self, server: str, tool: str, args: dict, effect: str, call_id: str, session: SessionState
    ) -> Decision:
        """Mode P123: Full Gateway — Layer A + Layer B + Baseline + Layer C (Risk Engine)."""
        # 1. Scope Pre-Check
        if not session.in_scope(server, tool):
            return Decision(
                decision=DECISION_BLOCK,
                reason=f"Scope violation: ({server}, {tool}) is not in declared session scope",
                call_id=call_id, server=server, tool=tool,
                args=args, effect=effect, layer="L1-scope",
            )

        # 2. Layer A Parameter & AST Validation
        param_res = self.param_validator.validate(server, tool, args)

        # 3. Layer B Dynamic Taint Propagation
        taint_res = self.taint_engine.check_call(session, server, tool, args, call_id=call_id)

        # 4. Check Hard Rules
        hard_rule_hit = param_res.has_hard_blocks() or (taint_res.action_recommendation == "BLOCK")
        hard_reasons = []
        if param_res.has_hard_blocks():
            hard_reasons.extend(param_res.hard_blocks)
        if taint_res.action_recommendation == "BLOCK":
            hard_reasons.extend(taint_res.reasons)

        # 5. Layer C Risk Scoring Engine
        risk: RiskAssessment = self.risk_engine.compute_risk(
            session=session,
            server=server,
            tool=tool,
            effect=effect,
            param_risk=param_res.param_risk,
            taint_score=taint_res.taint_score,
            hard_rule_hit=hard_rule_hit,
            hard_reasons=hard_reasons,
        )

        meta = {
            "risk_score": risk.score,
            "risk_vector": risk.vector,
            "param_risk": param_res.param_risk,
            "taint_score": taint_res.taint_score,
            "hard_rule_hit": risk.hard_rule_hit,
            "flows": [f.to_dict() for f in taint_res.flows],
        }

        # 6. Map Risk Assessment to Final Gateway Decision
        if risk.is_blocked():
            return Decision(
                decision=DECISION_BLOCK,
                reason=f"P123 Block: {'; '.join(risk.reasons)}",
                call_id=call_id, server=server, tool=tool,
                args=args, effect=effect, layer="LayerC-risk",
                meta=meta,
            )

        # If session holds active elevation covering this sensitive tool and no hard block, allow under elevation!
        if session.has_active_elevation(server, tool):
            remaining = session.elevation.seconds_remaining() if session.elevation else 0.0
            meta["elevation_remaining_s"] = remaining
            return Decision(
                decision=DECISION_ALLOW,
                reason=f"P123 Allowed under active elevation ({remaining:.1f}s remaining)",
                call_id=call_id, server=server, tool=tool,
                args=args, effect=effect, layer="L3-elevation",
                meta=meta,
            )

        if risk.is_downgraded():
            meta["downgrade_action"] = risk.downgrade_action
            return Decision(
                decision=DECISION_DOWNGRADE,
                reason=f"P123 Downgrade: {'; '.join(risk.reasons)}",
                call_id=call_id, server=server, tool=tool,
                args=args, effect=effect, layer="LayerC-risk",
                meta=meta,
            )

        if risk.needs_approval():
            # Enqueue approval request
            req = self.approval.enqueue(
                session=session, server=server, tool=tool, args=args,
                reason=f"Operation requires human approval (Risk score: {risk.score:.3f}).",
                meta=meta,
            )
            return Decision(
                decision=DECISION_APPROVAL,
                reason=f"P123 Approval Required: {'; '.join(risk.reasons)} (request_id={req.request_id})",
                call_id=call_id, server=server, tool=tool,
                args=args, effect=effect, layer="LayerC-risk",
                approval_request=req,
                meta=meta,
            )

        # score < allow_threshold -> ALLOW
        return Decision(
            decision=DECISION_ALLOW,
            reason=f"P123 Allow: {'; '.join(risk.reasons)}",
            call_id=call_id, server=server, tool=tool,
            args=args, effect=effect, layer="LayerC-risk",
            meta=meta,
        )

    # -----------------------------------------------------------------------
    # Finalization & Helpers
    # -----------------------------------------------------------------------

    def _finalize(self, decision: Decision, session: SessionState, t_start: float) -> Decision:
        """Measure latency, store in meta, and record to session call history."""
        latency_ms = (time.perf_counter() - t_start) * 1000.0
        decision.meta["latency_ms"] = round(latency_ms, 3)

        session.record_call({
            "call_id":    decision.call_id,
            "server":     decision.server,
            "tool":       decision.tool,
            "args":       decision.args,
            "effect":     decision.effect,
            "decision":   decision.decision,
            "reason":     decision.reason,
            "layer":      decision.layer,
            "timestamp":  decision.timestamp,
            "latency_ms": decision.meta["latency_ms"],
            "meta":       decision.meta,
        })
        return decision

    def _resolve_effect(self, server: str, tool: str) -> str:
        srv = self.servers.get(server)
        if srv is None:
            return "unknown"
        for t in srv.list_tools():
            if t["name"] == tool:
                return t.get("effect", "unknown")
        return "unknown"
