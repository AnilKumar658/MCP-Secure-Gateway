"""
gateway/layer3_risk.py
Layer C — Risk Scoring Engine ("Conclusion")

Position in pipeline: post-L3 (evaluated in full dynamic gateway mode P123).

Purpose
-------
Calculates a multi-dimensional risk score for a tool call using the vector:
  1. tool_sensitivity: read (0.1), write (0.5), sensitive/destructive (0.9)
  2. param_risk: parameter/AST risk from Layer A (0..1)
  3. taint: dynamic taint score from Layer B (0..1)
  4. privilege_level: elevation status & privilege gap (0..1)
  5. chain_risk: multi-step sequence risk (e.g. read secret then send_mail)

Formula:
  score = sum(w_i * v_i)
Weights are loaded from gateway/config.json and can be overridden for ablation studies.

Thresholds:
  - score < 0.30       -> ALLOW
  - 0.30 <= score < 0.60 -> DOWNGRADE (dry-run/draft)
  - 0.60 <= score < 0.85 -> APPROVAL
  - score >= 0.85      -> BLOCK

Hard Rule Override:
  Any hard-rule violation from Layer A or Layer B immediately overrides the score
  to 1.0 and forces a BLOCK decision.

Standard library only.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from gateway.session import SessionState


# Path to default config file
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")


@dataclass
class RiskAssessment:
    """
    Detailed output of the Risk Scoring Engine.
    """
    score: float
    decision: str                  # "ALLOW" | "DOWNGRADE" | "APPROVAL" | "BLOCK"
    vector: dict[str, float]       # Individual component values (0..1)
    weights: dict[str, float]      # Active component weights
    reasons: list[str]             # Explainable breakdown
    hard_rule_hit: bool = False
    downgrade_action: str | None = None

    def is_allowed(self) -> bool:
        return self.decision == "ALLOW"

    def is_downgraded(self) -> bool:
        return self.decision == "DOWNGRADE"

    def needs_approval(self) -> bool:
        return self.decision == "APPROVAL"

    def is_blocked(self) -> bool:
        return self.decision == "BLOCK"

    def __repr__(self) -> str:
        return (
            f"RiskAssessment(score={self.score:.3f}, decision={self.decision}, "
            f"hard={self.hard_rule_hit}, vector={self.vector})"
        )


class RiskEngine:
    """
    Computes holistic risk scores based on config.json weights and thresholds.
    """

    def __init__(
        self,
        config_path: str | None = None,
        config_dict: dict[str, Any] | None = None,
    ) -> None:
        if config_dict:
            self.config = config_dict
        else:
            path = config_path or CONFIG_PATH
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    self.config = json.load(f)
            else:
                # Built-in fallback
                self.config = {
                    "weights": {
                        "tool_sensitivity": 0.25,
                        "param_risk": 0.30,
                        "taint": 0.25,
                        "privilege_level": 0.10,
                        "chain_risk": 0.10,
                    },
                    "thresholds": {
                        "allow": 0.30,
                        "downgrade": 0.60,
                        "approval": 0.85,
                    },
                    "tool_sensitivity": {
                        "read": 0.1,
                        "write": 0.5,
                        "sensitive": 0.9,
                        "destructive": 0.9,
                        "unknown": 0.5,
                    },
                }

        self.weights: dict[str, float] = self.config.get("weights", {})
        self.thresholds: dict[str, float] = self.config.get("thresholds", {
            "allow": 0.30,
            "downgrade": 0.60,
            "approval": 0.85,
        })
        self.sensitivity_map: dict[str, float] = self.config.get("tool_sensitivity", {
            "read": 0.1,
            "write": 0.5,
            "sensitive": 0.9,
            "destructive": 0.9,
            "unknown": 0.5,
        })

    def compute_risk(
        self,
        session: SessionState,
        server: str,
        tool: str,
        effect: str,
        param_risk: float = 0.0,
        taint_score: float = 0.0,
        hard_rule_hit: bool = False,
        hard_reasons: list[str] | None = None,
    ) -> RiskAssessment:
        """
        Compute holistic risk assessment for a proposed tool call.
        """
        reasons: list[str] = []

        # 1. Check Hard Rule Overrides
        if hard_rule_hit:
            msg = "Hard security rule triggered: " + ("; ".join(hard_reasons or ["Security policy violation"]))
            reasons.append(msg)
            return RiskAssessment(
                score=1.0,
                decision="BLOCK",
                vector={
                    "tool_sensitivity": self._calc_tool_sensitivity(effect),
                    "param_risk": 1.0,
                    "taint": taint_score,
                    "privilege_level": 1.0,
                    "chain_risk": 1.0,
                },
                weights=dict(self.weights),
                reasons=reasons,
                hard_rule_hit=True,
            )

        # 2. Vector Component 1: Tool Sensitivity
        v_tool = self._calc_tool_sensitivity(effect)

        # 3. Vector Component 2: Param Risk (Layer A)
        v_param = max(0.0, min(1.0, float(param_risk)))

        # 4. Vector Component 3: Dynamic Taint (Layer B)
        v_taint = max(0.0, min(1.0, float(taint_score)))

        # 5. Vector Component 4: Privilege Level
        v_priv = self._calc_privilege_level(session, server, tool, effect)

        # 6. Vector Component 5: Chain Risk (multi-call sequence analysis)
        v_chain = self._calc_chain_risk(session, server, tool, effect)

        # 7. Weighted Sum
        vector = {
            "tool_sensitivity": v_tool,
            "param_risk": v_param,
            "taint": v_taint,
            "privilege_level": v_priv,
            "chain_risk": v_chain,
        }

        score = sum(self.weights.get(k, 0.0) * vector[k] for k in vector)
        score = round(max(0.0, min(1.0, score)), 4)

        # 8. Decision Band Mapping
        allow_th = self.thresholds.get("allow", 0.30)
        downgrade_th = self.thresholds.get("downgrade", 0.60)
        approval_th = self.thresholds.get("approval", 0.85)

        downgrade_action = None
        if score < allow_th:
            decision = "ALLOW"
            reasons.append(f"Risk score {score:.3f} < {allow_th}: operation allowed unconditionally.")
        elif score < downgrade_th:
            decision = "DOWNGRADE"
            downgrade_action = "read_only_draft" if effect in ("write", "sensitive") else "sandboxed_execution"
            reasons.append(
                f"Risk score {score:.3f} in [{allow_th}, {downgrade_th}): downgraded to "
                f"dry-run/draft mode ({downgrade_action})."
            )
        elif score < approval_th:
            decision = "APPROVAL"
            reasons.append(
                f"Risk score {score:.3f} in [{downgrade_th}, {approval_th}): queued for human approval."
            )
        else:
            decision = "BLOCK"
            reasons.append(f"Risk score {score:.3f} >= {approval_th}: operation blocked due to high aggregate risk.")

        # Add vector rationale
        reasons.append(
            f"Components: tool_sensitivity={v_tool:.2f}, param_risk={v_param:.2f}, "
            f"taint={v_taint:.2f}, privilege_gap={v_priv:.2f}, chain_risk={v_chain:.2f}"
        )

        return RiskAssessment(
            score=score,
            decision=decision,
            vector=vector,
            weights=dict(self.weights),
            reasons=reasons,
            hard_rule_hit=False,
            downgrade_action=downgrade_action,
        )

    def _calc_tool_sensitivity(self, effect: str) -> float:
        eff_lower = (effect or "unknown").lower()
        return self.sensitivity_map.get(eff_lower, self.sensitivity_map.get("unknown", 0.5))

    def _calc_privilege_level(
        self, session: SessionState, server: str, tool: str, effect: str
    ) -> float:
        """
        Evaluate privilege gap:
        - 0.0 if session has active elevation for this tool, or session level 0
        - 0.8 if sensitive tool and no active elevation
        - 0.3 for write tool
        - 0.1 for read tool
        """
        if session.level == 0:
            return 0.0
        if session.has_active_elevation(server, tool):
            return 0.0
        if effect == "sensitive":
            return 0.9
        if effect == "write":
            return 0.4
        return 0.1

    def _calc_chain_risk(
        self, session: SessionState, server: str, tool: str, effect: str
    ) -> float:
        """
        Evaluate multi-step sequence risk from session context & call_history.
        Example: Reading secret / sensitive content followed immediately by an outbound
        or destructive call (read .env -> send_mail or write_file).
        """
        # Pattern 1: Tainted session context attempting mutating or sensitive operation
        if session.session_taint_level > 0.60 and effect in ("write", "sensitive"):
            return 0.70

        if not session.call_history:
            return 0.0

        last_call = session.last_call()
        if not last_call:
            return 0.0

        last_tool = last_call.get("tool", "")
        last_args = str(last_call.get("args", {}))

        # Pattern 2: Secret Read -> Outbound / Mutation Sink
        is_secret_read = (
            last_tool in ("read_file", "read_inbox", "fetch_url") and
            (".env" in last_args or "secret" in last_args.lower() or "key" in last_args.lower())
        )
        is_sink_action = (server, tool) in {
            ("mail", "send_mail"),
            ("file", "write_file"),
            ("git", "force_push"),
            ("git", "delete_branch"),
            ("code", "run_python"),
        }

        if is_secret_read and is_sink_action:
            return 0.95

        # Pattern 3: Rapid successive mutating calls
        if last_call.get("effect") in ("write", "sensitive") and effect in ("write", "sensitive"):
            return 0.60

        return 0.0
