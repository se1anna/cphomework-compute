"""Focused checks for Python missing-dependency attribution."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from sandbox.runner import _classify_missing_import
from core.models import DynamicRunResult, StaticAnalysisResult, TaskPayload
from graph.nodes import _generate_deterministic_rfc_memo


class TestMissingImportClassification(unittest.TestCase):
    def test_missing_manifest_is_reported_as_missing_requirements_txt(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            project = root / "hw1"
            project.mkdir()

            result = _classify_missing_import(
                root, project, None, "ModuleNotFoundError: No module named 'numpy'"
            )

            self.assertTrue(result.startswith("STUDENT_MISSING_REQUIREMENTS_TXT:"))
            self.assertIn("numpy", result)

    def test_manifest_without_missing_import_is_dependency_omission(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            project = root / "hw1"
            project.mkdir()
            (project / "requirements.txt").write_text("scipy\n", encoding="utf-8")

            result = _classify_missing_import(
                root, project, None, "ModuleNotFoundError: No module named 'numpy'"
            )

            self.assertTrue(result.startswith("STUDENT_DEPENDENCY_DECLARATION_MISSING:"))
            self.assertIn("requirements.txt", result)
            self.assertIn("numpy", result)

    def test_declared_missing_import_is_environment_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            project = root / "hw1"
            project.mkdir()
            (project / "requirements.txt").write_text("numpy>=1.20\n", encoding="utf-8")

            result = _classify_missing_import(
                root, project, None, "ModuleNotFoundError: No module named 'numpy'"
            )

            self.assertTrue(result.startswith("DECLARED_DEPENDENCY_ENVIRONMENT_FAILURE:"))

    def test_non_import_runtime_error_is_not_mislabeled(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            project = root / "hw1"
            project.mkdir()

            result = _classify_missing_import(root, project, None, "NameError: name 'x' is not defined")

            self.assertIsNone(result)

    def test_missing_manifest_report_uses_submission_wording_and_low_score(self):
        task = TaskPayload(
            taskId="virtual-task-001",
            studentId="virtual-student",
            assignmentId="virtual-hw",
            assignmentTitle="虚拟测试",
            repoUrl="https://example.invalid/virtual",
        )
        static = StaticAnalysisResult(
            passed=True,
            security_clean=True,
            topic_matched=True,
            topic_decision="MATCHED",
        )
        dynamic = DynamicRunResult(
            executed=True,
            exit_code=1,
            stderr="ModuleNotFoundError: No module named 'numpy'",
            error_summary="STUDENT_MISSING_REQUIREMENTS_TXT: numpy is imported but no applicable manifest exists",
        )

        score, report = _generate_deterministic_rfc_memo(
            task, static, dynamic, metrics=None, target_score=88.0
        )

        self.assertEqual(score, 78.0)
        self.assertIn("提交缺少 `requirements.txt`", report)
        self.assertIn("提交缺少 requirements.txt", report)
        self.assertNotIn("沙箱少依赖", report)
        self.assertNotIn("环境导致未验证", report)


if __name__ == "__main__":
    unittest.main()
