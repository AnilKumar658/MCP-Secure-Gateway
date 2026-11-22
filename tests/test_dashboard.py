import os
import unittest
import tempfile
import json
from dashboard.app import load_call_logs, load_ablation_csv, get_decision_badge

class TestDashboardHelpers(unittest.TestCase):
    """Unit tests for dashboard data loading and rendering helpers without launching Streamlit UI."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_decision_badge(self):
        badge_allow = get_decision_badge("ALLOW")
        self.assertIn("ALLOW", badge_allow)
        self.assertIn("#28a745", badge_allow)

        badge_block = get_decision_badge("BLOCK")
        self.assertIn("BLOCK", badge_block)
        self.assertIn("#dc3545", badge_block)

        badge_downgrade = get_decision_badge("DOWNGRADE")
        self.assertIn("DOWNGRADE", badge_downgrade)
        self.assertIn("#ffc107", badge_downgrade)

        badge_approval = get_decision_badge("APPROVAL")
        self.assertIn("APPROVAL", badge_approval)
        self.assertIn("#fd7e14", badge_approval)

    def test_load_call_logs(self):
        fake_log = os.path.join(self.temp_dir.name, "test_calls.jsonl")
        record = {
            "timestamp": "2026-11-21T19:00:00Z",
            "model": "simulated",
            "task": "Test task",
            "mode": "P123",
            "session_id": "test_session_1",
            "action": {"server": "file", "tool": "read_file", "args": {"path": "README.md"}},
            "decision": "ALLOW",
            "reason": "Test allow",
            "latency_ms": 0.12,
            "layer_outputs": {
                "layer_c": {
                    "risk_vector": {
                        "tool_sensitivity": 0.1,
                        "param_risk": 0.0,
                        "taint": 0.0,
                        "privilege_level": 0.1,
                        "chain_risk": 0.0
                    }
                }
            }
        }
        with open(fake_log, "w", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        df = load_call_logs(fake_log)
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]["decision"], "ALLOW")
        self.assertEqual(df.iloc[0]["server"], "file")
        self.assertEqual(df.iloc[0]["tool"], "read_file")

    def test_load_ablation_csv(self):
        fake_csv = os.path.join(self.temp_dir.name, "test_ablation.csv")
        csv_content = (
            "config,attack_block_rate_%,benign_completion_%,false_positive_rate_%,attack_attempted_%,block_given_attempt_%,latency_mean_ms,total_runs\n"
            "L0,0.0,100.0,0.0,100.0,0.0,0.04,40\n"
            "P123,100.0,100.0,0.0,100.0,100.0,0.16,40\n"
        )
        with open(fake_csv, "w", encoding="utf-8") as f:
            f.write(csv_content)

        df = load_ablation_csv(fake_csv)
        self.assertEqual(len(df), 2)
        self.assertIn("P123", df["config"].values)
        self.assertEqual(df[df["config"] == "P123"]["attack_block_rate_%"].iloc[0], 100.0)

if __name__ == "__main__":
    unittest.main()

