"""
tests/test_layer_c.py
Unit tests for gateway/layer3_risk.py (Layer C — Risk Scoring Engine).

Coverage:
1. Weights & Config loading:
   - Default weights and thresholds loaded from config.json.
   - Customizable weights for ablation experiments.
2. Vector components:
   - tool_sensitivity: read (0.1), write (0.5), sensitive/destructive (0.9).
   - param_risk: from Layer A.
   - taint: from Layer B.
   - privilege_level: elevation status & privilege gap.
   - chain_risk: sequence analysis (read secret -> sink).
3. Every decision band:
   - < 0.30       -> ALLOW
   - 0.30 .. 0.60 -> DOWNGRADE (dry-run/draft)
   - 0.60 .. 0.85 -> APPROVAL
   - >= 0.85      -> BLOCK
4. Hard rule overrides:
   - Any hard-rule hit overrides numeric score to 1.0 and decision to BLOCK.

Run with:
    python -m unittest tests.test_layer_c -v
"""
import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gateway.session import SessionState
from gateway.layer3_risk import RiskEngine, RiskAssessment


class TestRiskEngineBasics(unittest.TestCase):

    def setUp(self):
        self.engine = RiskEngine()
        self.session = SessionState()

    def test_default_weights_loaded(self):
        weights = self.engine.weights
        for k in ("tool_sensitivity", "param_risk", "taint", "privilege_level", "chain_risk"):
            self.assertIn(k, weights)
        total = sum(weights.values())
        self.assertAlmostEqual(total, 1.0, places=2)

    def test_default_thresholds_loaded(self):
        th = self.engine.thresholds
        self.assertEqual(th["allow"], 0.30)
        self.assertEqual(th["downgrade"], 0.60)
        self.assertEqual(th["approval"], 0.85)

    def test_custom_weights_ablation(self):
        # Ablation: zero out taint and param_risk weights
        custom_config = {
            "weights": {
                "tool_sensitivity": 0.50,
                "param_risk": 0.00,
                "taint": 0.00,
                "privilege_level": 0.50,
                "chain_risk": 0.00,
            },
            "thresholds": {"allow": 0.30, "downgrade": 0.60, "approval": 0.85},
            "tool_sensitivity": {"read": 0.1, "write": 0.5, "sensitive": 0.9},
        }
        ablated_engine = RiskEngine(config_dict=custom_config)
        risk = ablated_engine.compute_risk(
            self.session, "file", "read_file", effect="read", param_risk=0.9, taint_score=0.9
        )
        # Even with high param_risk and taint, their zero weights mean score = 0.5*0.1 + 0.5*0.1 = 0.10
        self.assertLess(risk.score, 0.30)
        self.assertEqual(risk.decision, "ALLOW")


class TestDecisionBands(unittest.TestCase):

    def setUp(self):
        self.engine = RiskEngine()
        self.session = SessionState(level=3)

    def test_band_allow_under_point_three(self):
        # Benign read: sensitivity=0.1, param=0.0, taint=0.0, priv=0.1, chain=0.0
        risk = self.engine.compute_risk(
            self.session, "git", "list_branches", effect="read",
            param_risk=0.0, taint_score=0.0
        )
        self.assertLess(risk.score, 0.30)
        self.assertEqual(risk.decision, "ALLOW")
        self.assertTrue(risk.is_allowed())

    def test_band_downgrade_between_point_three_and_point_six(self):
        # Benign write with no taint: sensitivity=0.5, param=0.0, taint=0.0, priv=0.4, chain=0.0
        # Score = 0.25*0.5 + 0.30*0.0 + 0.25*0.0 + 0.10*0.4 + 0.10*0.0 = 0.125 + 0.04 = 0.165
        # Add moderate param_risk 0.60 -> adds 0.30*0.60 = 0.18 -> Total = 0.345
        risk = self.engine.compute_risk(
            self.session, "file", "write_file", effect="write",
            param_risk=0.60, taint_score=0.0
        )
        self.assertGreaterEqual(risk.score, 0.30)
        self.assertLess(risk.score, 0.60)
        self.assertEqual(risk.decision, "DOWNGRADE")
        self.assertTrue(risk.is_downgraded())
        self.assertIsNotNone(risk.downgrade_action)

    def test_band_approval_between_point_six_and_point_eight_five(self):
        # Sensitive tool without elevation: sensitivity=0.9, priv=0.9
        # Score = 0.25*0.9 + 0.10*0.9 = 0.225 + 0.09 = 0.315
        # With moderate taint 0.80 -> adds 0.25*0.80 = 0.20 -> 0.515
        # With mild param_risk 0.40 -> adds 0.30*0.40 = 0.12 -> Total = 0.635
        risk = self.engine.compute_risk(
            self.session, "git", "force_push", effect="sensitive",
            param_risk=0.40, taint_score=0.80
        )
        self.assertGreaterEqual(risk.score, 0.60)
        self.assertLess(risk.score, 0.85)
        self.assertEqual(risk.decision, "APPROVAL")
        self.assertTrue(risk.needs_approval())

    def test_band_block_above_point_eight_five(self):
        # High sensitivity + high param_risk + high taint + chain risk
        self.session.session_taint_level = 0.80
        risk = self.engine.compute_risk(
            self.session, "mail", "send_mail", effect="sensitive",
            param_risk=0.90, taint_score=0.90
        )
        self.assertGreaterEqual(risk.score, 0.85)
        self.assertEqual(risk.decision, "BLOCK")
        self.assertTrue(risk.is_blocked())


class TestHardRuleOverrides(unittest.TestCase):

    def setUp(self):
        self.engine = RiskEngine()
        self.session = SessionState()

    def test_hard_rule_forces_score_one_and_block(self):
        # Even on a read tool where normal score would be ~0.10, hard_rule_hit forces score=1.0 & BLOCK
        risk = self.engine.compute_risk(
            self.session, "file", "read_file", effect="read",
            hard_rule_hit=True, hard_reasons=["Path traversal detected"]
        )
        self.assertEqual(risk.score, 1.0)
        self.assertEqual(risk.decision, "BLOCK")
        self.assertTrue(risk.hard_rule_hit)
        self.assertTrue(any("Path traversal" in r for r in risk.reasons))

    def test_multiple_hard_reasons_logged(self):
        reasons = ["Protected branch deletion", "Credential exfiltration"]
        risk = self.engine.compute_risk(
            self.session, "git", "delete_branch", effect="write",
            hard_rule_hit=True, hard_reasons=reasons
        )
        self.assertEqual(risk.decision, "BLOCK")
        for r in reasons:
            self.assertTrue(any(r in reason_str for reason_str in risk.reasons))


class TestChainRisk(unittest.TestCase):

    def setUp(self):
        self.engine = RiskEngine()
        self.session = SessionState()

    def test_read_secret_then_send_mail_triggers_chain_risk(self):
        # Record a prior call that read a secret .env file
        self.session.record_call({
            "tool": "read_file",
            "args": {"path": ".env"},
            "effect": "read",
        })

        # Next call is an outbound send_mail
        risk = self.engine.compute_risk(
            self.session, "mail", "send_mail", effect="sensitive",
            param_risk=0.1, taint_score=0.1
        )
        self.assertEqual(risk.vector["chain_risk"], 0.95)
        # Should escalate to APPROVAL or BLOCK due to sequence risk
        self.assertGreaterEqual(risk.score, 0.40)


if __name__ == "__main__":
    unittest.main(verbosity=2)
