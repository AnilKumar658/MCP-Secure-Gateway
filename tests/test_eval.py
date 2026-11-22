"""
tests/test_eval.py
Unit tests for eval/tasks.py and eval/run_experiments.py.

Coverage:
1. Task dataset verification:
   - At least 15 benign tasks.
   - At least 25 attack tasks covering all required vulnerability categories.
   - Task filtering and retrieval.
2. ExperimentRunner execution & metrics:
   - Evaluates subset of tasks across configs (L0, P123).
   - Verifies generation of results.csv, ablation_summary.csv, and summary.txt.
   - Verifies metric formulas (attack_block_rate, benign_completion, latency).

Run with:
    python -m unittest tests.test_eval -v
"""
import sys
import os
import unittest
import tempfile
import csv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from eval.tasks import (
    ALL_TASKS, BENIGN_TASKS, ATTACK_TASKS,
    get_task_by_id, get_tasks_by_filter,
)
from eval.run_experiments import ExperimentRunner, ConfigMetrics


class TestTaskDataset(unittest.TestCase):

    def test_benign_tasks_count_at_least_fifteen(self):
        self.assertGreaterEqual(len(BENIGN_TASKS), 15)
        for t in BENIGN_TASKS:
            self.assertFalse(t.is_attack)
            self.assertEqual(t.category, "benign")
            self.assertGreater(len(t.prompt), 0)
            self.assertGreater(len(t.allowed_scope), 0)
            self.assertIsNotNone(t.scripted_actions)

    def test_attack_tasks_count_at_least_twenty_five(self):
        self.assertGreaterEqual(len(ATTACK_TASKS), 25)
        for t in ATTACK_TASKS:
            self.assertTrue(t.is_attack)
            self.assertNotEqual(t.category, "benign")
            self.assertGreater(len(t.prompt), 0)
            self.assertGreater(len(t.allowed_scope), 0)

    def test_attack_categories_covered(self):
        categories = {t.category for t in ATTACK_TASKS}
        expected_cats = {
            "path_traversal",
            "protected_branch",
            "credential_exfiltration",
            "indirect_injection_web",
            "indirect_injection_mail",
            "chained_read_send",
            "ast_injection",
        }
        for cat in expected_cats:
            self.assertIn(cat, categories, msg=f"Missing attack category: {cat}")

    def test_get_tasks_by_filter(self):
        all_t = get_tasks_by_filter("all")
        self.assertEqual(len(all_t), len(ALL_TASKS))

        benign_t = get_tasks_by_filter("benign")
        self.assertEqual(len(benign_t), len(BENIGN_TASKS))

        attack_t = get_tasks_by_filter("attack")
        self.assertEqual(len(attack_t), len(ATTACK_TASKS))

    def test_get_task_by_id(self):
        t1 = get_task_by_id("benign_01")
        self.assertIsNotNone(t1)
        self.assertEqual(t1.name, "List Repository Branches")

        t_bad = get_task_by_id("nonexistent_task")
        self.assertIsNone(t_bad)


class TestExperimentRunnerExecution(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_runner_executes_and_generates_outputs(self):
        # Run small fast evaluation on 2 tasks across L0 and P123
        runner = ExperimentRunner(
            agent_type="simulated",
            configs=["L0", "P123"],
            repeats=1,
            output_dir=self.temp_dir,
            task_filter="all",
        )
        # Filter down tasks to 2 for rapid unit test execution
        runner.tasks = [
            get_task_by_id("benign_01"),
            get_task_by_id("attack_01"),  # path traversal
        ]

        summary = runner.run()

        # Check metrics generated for both configs
        self.assertIn("L0", summary)
        self.assertIn("P123", summary)

        l0_metrics = summary["L0"]
        p123_metrics = summary["P123"]

        # L0 should allow attack (0% block rate)
        self.assertEqual(l0_metrics.attack_block_rate, 0.0)
        self.assertEqual(l0_metrics.benign_completion_rate, 100.0)

        # P123 should block attack_01 (/etc/passwd)
        self.assertEqual(p123_metrics.attack_block_rate, 100.0)
        self.assertEqual(p123_metrics.benign_completion_rate, 100.0)
        self.assertEqual(p123_metrics.false_positive_rate, 0.0)

        # Check export files exist
        results_csv = os.path.join(self.temp_dir, "results.csv")
        summary_csv = os.path.join(self.temp_dir, "ablation_summary.csv")
        summary_txt = os.path.join(self.temp_dir, "summary.txt")

        self.assertTrue(os.path.exists(results_csv))
        self.assertTrue(os.path.exists(summary_csv))
        self.assertTrue(os.path.exists(summary_txt))

        # Check CSV content
        with open(summary_csv, "r", encoding="utf-8") as f:
            reader = list(csv.DictReader(f))
            self.assertEqual(len(reader), 2)
            cfg_names = {row["config"] for row in reader}
            self.assertEqual(cfg_names, {"L0", "P123"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
