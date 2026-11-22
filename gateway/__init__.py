"""
gateway/__init__.py
Public surface of the gateway package.
"""
from gateway.session  import SessionState, SessionRegistry, Elevation
from gateway.approval import ApprovalQueue, ApprovalRequest, ConsoleApprover, ScriptedApprover
from gateway.pipeline import GatewayPipeline, Decision, DECISION_ALLOW, DECISION_BLOCK, DECISION_APPROVAL, DECISION_DOWNGRADE
from gateway.layer1_params import ParamValidator, ParamCheckResult, Finding, ValidatorConfig
from gateway.layer2_taint import TaintEngine, TaintRecord, TaintFlow, TaintCheckResult
from gateway.layer3_risk import RiskEngine, RiskAssessment
from gateway.logger import JSONLLogger

__all__ = [
    "SessionState", "SessionRegistry", "Elevation",
    "ApprovalQueue", "ApprovalRequest", "ConsoleApprover", "ScriptedApprover",
    "GatewayPipeline", "Decision",
    "DECISION_ALLOW", "DECISION_BLOCK", "DECISION_APPROVAL", "DECISION_DOWNGRADE",
    "ParamValidator", "ParamCheckResult", "Finding", "ValidatorConfig",
    "TaintEngine", "TaintRecord", "TaintFlow", "TaintCheckResult",
    "RiskEngine", "RiskAssessment",
    "JSONLLogger",
]
