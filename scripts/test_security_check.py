"""Regression checks for the audit's trust and completeness boundaries."""
import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("security_check", Path(__file__).with_name("security-check.py"))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.root_patch = patch.object(audit, "ROOT", self.root)
        self.root_patch.start()
        self.config_patch = patch.object(audit, "CONFIG", self.root / "security-check/modules.json")
        self.config_patch.start()
        (self.root / "electron-app").mkdir()
        (self.root / "electron-app/example.ts").write_text("// Synthetic audit fixture only\nexport const limit = 1;\n", encoding="utf-8")
        self.config = {"scope": "electron-app", "context": [], "excluded_directories": ["node_modules"],
                       "excluded_extensions": [], "modules": [{"id": "example", "paths": ["electron-app/*.ts"], "focus": "Synthetic"}]}
        audit.write(audit.CONFIG, self.config)
        with patch.object(audit.subprocess, "check_output", return_value="synthetic-revision\n"):
            audit.prepare("synthetic-run")
        self.target, self.manifest = audit.load_run("synthetic-run")
        self.evidence = {"path": "electron-app/example.ts", "start_line": 1, "end_line": 2, "fact": "Synthetic evidence"}
        self.result = {"module_id": "example", "run_id": "synthetic-run", "source_digest": self.manifest["source_digest"],
                       "status": "complete", "summary": "Synthetic review", "fully_reviewed_files": ["electron-app/example.ts"],
                       "findings": [], "resolved_questions": [], "limitations": []}
        self.integration = {"run_id": "synthetic-run", "source_digest": self.manifest["source_digest"], "decisions": [], "limitations": []}

    def tearDown(self):
        self.config_patch.stop()
        self.root_patch.stop()
        self.temp.cleanup()

    def save(self):
        audit.write(self.target / "results/example.json", self.result)
        audit.write(self.target / "integration.json", self.integration)

    def finding(self, number=1):
        return {"id": f"example-{number:03}", "title": "Synthetic finding", "severity": "medium", "confidence": "high", "cwe": "CWE-20",
                **{k: "Synthetic test fact" for k in ("summary", "attacker", "prerequisites", "dataflow", "root_cause", "impact", "counterevidence", "validation", "remediation")},
                "evidence": [copy.deepcopy(self.evidence)]}

    def decision(self, number=1, disposition="confirmed", duplicate=None):
        return {"finding_id": f"example-{number:03}", "disposition": disposition, "duplicate_of": duplicate,
                "severity": "medium" if disposition == "confirmed" else None,
                "confidence": "high" if disposition == "confirmed" else None,
                "reason": "Synthetic validation", "evidence": [copy.deepcopy(self.evidence)]}

    def test_success_and_missing_module_are_distinct(self):
        self.save()
        self.assertEqual(audit.merge("synthetic-run"), 0)
        (self.target / "results/example.json").unlink()
        self.assertEqual(audit.merge("synthetic-run"), 3)
        self.assertIn("INCOMPLETE", (self.root / "security_check_result.md").read_text(encoding="utf-8"))

    def test_stale_source_and_new_unassigned_file_rejected(self):
        (self.root / "electron-app/example.ts").write_text("// changed\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Source/context changed"):
            audit.load_run("synthetic-run")
        (self.root / "electron-app/new.ts").write_text("// Synthetic\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "inventory changed"):
            audit.load_run("synthetic-run")

    def test_incomplete_coverage_cannot_claim_complete(self):
        self.result["fully_reviewed_files"] = []
        self.save()
        with self.assertRaisesRegex(ValueError, "missing source coverage"):
            audit.merge("synthetic-run")

    def test_finding_requires_valid_source_and_lines(self):
        for path, start, end in [("../outside", 1, 2), ("electron-app/example.ts", 1, 3), ("electron-app/example.ts", 2, 1)]:
            with self.subTest(path=path, end=end):
                self.result["findings"] = [self.finding()]
                self.result["findings"][0]["evidence"][0].update(path=path, start_line=start, end_line=end)
                self.save()
                with self.assertRaises(ValueError):
                    audit.merge("synthetic-run")

    def test_missing_decision_rejected_and_unresolved_not_clean(self):
        self.result["findings"] = [self.finding()]
        self.save()
        with self.assertRaisesRegex(ValueError, "every candidate"):
            audit.merge("synthetic-run")
        self.integration["decisions"] = [self.decision(disposition="unresolved")]
        self.save()
        self.assertEqual(audit.merge("synthetic-run"), 3)

    def test_duplicates_keep_evidence_and_high_blocks(self):
        self.result["findings"] = [self.finding(), self.finding(2)]
        self.result["findings"][0]["severity"] = "high"
        self.result["findings"][1]["evidence"][0]["fact"] = "Synthetic duplicate evidence retained"
        self.integration["decisions"] = [self.decision(), self.decision(2, "duplicate", "example-001")]
        self.integration["decisions"][0]["severity"] = "high"
        self.save()
        self.assertEqual(audit.merge("synthetic-run"), 2)
        text = (self.root / "security_check_result.md").read_text(encoding="utf-8")
        self.assertIn("Synthetic duplicate evidence retained", text)
        self.assertIn("| high | 1 |", text)

    def test_duplicate_cycle_and_stale_result_rejected(self):
        self.result["findings"] = [self.finding()]
        self.integration["decisions"] = [self.decision(1, "duplicate", "example-001")]
        self.save()
        with self.assertRaisesRegex(ValueError, "confirmed finding"):
            audit.merge("synthetic-run")
        self.result["run_id"] = "other-run"
        self.save()
        with self.assertRaisesRegex(ValueError, "Stale result"):
            audit.merge("synthetic-run")

    def test_markdown_content_is_data(self):
        self.result["summary"] = '<script>alert(1)</script> [run](javascript:example)\n# fake section'
        self.save()
        audit.merge("synthetic-run")
        text = (self.root / "security_check_result.md").read_text(encoding="utf-8")
        self.assertNotIn("<script>", text)
        self.assertNotIn("\n# fake section", text)
        self.assertIn("\\[run\\]", text)

    def test_run_path_and_absolute_source_escape_rejected(self):
        for run_id in ["../escape", "x/y", "C:/absolute", ".."]:
            with self.assertRaises(ValueError):
                audit.run_path(run_id)
        for source in ["../escape", "C:/absolute", "/absolute", "x/../../escape"]:
            with self.assertRaises(ValueError):
                audit.safe_path(source)

    def test_duplicate_owners_fail_preparation(self):
        self.config["modules"].append({"id": "second", "paths": ["electron-app/*.ts"], "focus": "Synthetic"})
        audit.write(audit.CONFIG, self.config)
        with self.assertRaisesRegex(ValueError, "exactly one owner"):
            audit.prepare("another-run")

    def test_output_cannot_leave_repository(self):
        with self.assertRaisesRegex(ValueError, "Output leaves"):
            audit.write(self.root.parent / "outside-synthetic.json", {})

    def test_module_id_cannot_inject_an_output_path(self):
        self.config["modules"][0]["id"] = "../../outside"
        audit.write(audit.CONFIG, self.config)
        with self.assertRaisesRegex(ValueError, "Invalid or duplicate module ID"):
            audit.prepare("another-run")

    def test_severity_calibration_preserves_agent_result(self):
        self.result["findings"] = [self.finding()]
        self.integration["decisions"] = [self.decision()]
        self.integration["decisions"][0]["severity"] = "low"
        self.save()
        self.assertEqual(audit.merge("synthetic-run"), 0)
        combined = audit.read(self.target / "combined.json")
        self.assertEqual(combined["modules"][0]["findings"][0]["severity"], "medium")
        self.assertIn("| low | 1 |", (self.root / "security_check_result.md").read_text(encoding="utf-8"))

    def test_supporting_source_is_hashed_and_drift_is_rejected(self):
        dependency = self.root / "electron-app/node_modules/synthetic/source.ts"
        dependency.parent.mkdir(parents=True)
        dependency.write_text("// Synthetic dependency source\n", encoding="utf-8")
        support_evidence = {"path": dependency.relative_to(self.root).as_posix(), "start_line": 1, "end_line": 1, "fact": "Synthetic trace"}
        self.result["resolved_questions"] = [{"question": "Synthetic", "disposition": "Traced", "evidence": [support_evidence]}]
        self.save()
        with self.assertRaisesRegex(ValueError, "outside captured"):
            audit.merge("synthetic-run")
        audit.capture_support("synthetic-run")
        self.assertEqual(audit.merge("synthetic-run"), 0)
        dependency.write_text("// Changed synthetic dependency\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Supporting dependency source changed"):
            audit.merge("synthetic-run")

    def test_support_capture_rejects_non_dependency(self):
        self.result["resolved_questions"] = [{"question": "Synthetic", "disposition": "Untrusted", "evidence": [{"path": "secret.pfx", "start_line": 1, "end_line": 1, "fact": "Untrusted path"}]}]
        self.save()
        with self.assertRaisesRegex(ValueError, "dependency source"):
            audit.capture_support("synthetic-run")


if __name__ == "__main__":
    unittest.main()
