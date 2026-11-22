"""
gateway/logger.py
JSONL logging of every tool call passing through the Dynamic Security Gateway.

Schema per record:
  - timestamp  : ISO-8601 string
  - model      : name of the calling agent/model (e.g. "llama3.1:8b", "simulated")
  - task       : natural language task prompt
  - mode       : pipeline ablation mode (L0, L1, L2, L3, P1, P12, P123)
  - action     : {"server": str, "tool": str, "args": dict}
  - layer_outputs:
      - layer_a : {"param_risk": float, "hard_blocks": list[str]}
      - layer_b : {"taint_score": float, "flows": list[dict]}
      - layer_c : {"risk_score": float, "risk_vector": dict, "hard_rule_hit": bool}
  - decision   : ALLOW | DOWNGRADE | APPROVAL | BLOCK
  - reason     : human-readable explanation
  - latency_ms : pipeline execution duration in milliseconds

Standard library only.
"""
from __future__ import annotations

import datetime
import json
import os
from typing import Any

from gateway.pipeline import Decision


DEFAULT_LOG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "logs", "calls.jsonl"
)


class JSONLLogger:
    """
    Appends structured gateway call events to a JSONL log file.
    """

    def __init__(self, log_path: str = DEFAULT_LOG_PATH) -> None:
        self.log_path = log_path
        os.makedirs(os.path.dirname(os.path.abspath(self.log_path)), exist_ok=True)

    def log(
        self,
        decision: Decision,
        task: str = "",
        model: str = "simulated",
        mode: str | None = None,
        extra_meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Format and append a call event.
        """
        meta = decision.meta or {}
        effective_mode = mode or meta.get("mode", "P123")

        record: dict[str, Any] = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "call_id": decision.call_id,
            "model": model,
            "task": task,
            "mode": effective_mode,
            "action": {
                "server": decision.server,
                "tool": decision.tool,
                "args": decision.args,
            },
            "effect": decision.effect,
            "layer_outputs": {
                "layer_a": {
                    "param_risk": meta.get("param_risk", 0.0),
                    "hard_blocks": meta.get("hard_blocks", []),
                },
                "layer_b": {
                    "taint_score": meta.get("taint_score", 0.0),
                    "flows": meta.get("flows", []),
                },
                "layer_c": {
                    "risk_score": meta.get("risk_score", 0.0),
                    "risk_vector": meta.get("risk_vector", {}),
                    "hard_rule_hit": meta.get("hard_rule_hit", False),
                },
            },
            "decision": decision.decision,
            "reason": decision.reason,
            "layer": decision.layer,
            "latency_ms": meta.get("latency_ms", 0.0),
        }

        if extra_meta:
            record["extra"] = extra_meta

        line = json.dumps(record) + "\n"
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line)

        return record

    def read_logs(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Read all logged events (or up to limit)."""
        if not os.path.exists(self.log_path):
            return []
        records = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        pass
        if limit:
            return records[-limit:]
        return records

    def clear(self) -> None:
        """Clear the log file."""
        if os.path.exists(self.log_path):
            with open(self.log_path, "w", encoding="utf-8"):
                pass
