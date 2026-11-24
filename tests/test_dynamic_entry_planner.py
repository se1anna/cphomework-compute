import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import graph.nodes as nodes
from core.models import DynamicRunResult, TaskPayload


class TestDynamicEntryPlanner(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        (self.repo / "main.py").write_text("print('synthetic')\n", encoding="utf-8")
        self.task = SimpleNamespace(
            get_effective_title=lambda: "synthetic assignment",
            get_effective_details=lambda: "synthetic details",
        )

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def response(content, finish_reason):
        response = Mock()
        response.content = b"{}"
        response.status_code = 200
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "choices": [{"message": {"content": content}, "finish_reason": finish_reason}]
        }
        return response

    def test_retries_truncated_planner_response_with_larger_budget(self):
        valid_plan = json.dumps({
            "run": True,
            "done": True,
            "path": "main.py",
            "command": "python main.py",
            "project_dir": ".",
            "reason": "synthetic test",
        })
        responses = [
            self.response('{"run":true,"path":', "length"),
            self.response(valid_plan, "stop"),
        ]
        with patch.object(nodes, "OPENAI_API_KEY", "test-key"), \
             patch.object(nodes, "OPENAI_API_BASE", "http://model.invalid/v1"), \
             patch.object(nodes, "cache_llm_response") as cache, \
             patch.object(nodes.requests, "post", side_effect=responses) as post:
            result = nodes._agent_entry_plan(
                self.task, self.repo, {"main.py": "print('synthetic')"}, "python",
                ["main.py"],
            )

        self.assertEqual(post.call_count, 2)
        self.assertEqual([call.kwargs["json"]["max_tokens"] for call in post.call_args_list], [8192, 16384])
        self.assertEqual(cache.call_count, 2)
        self.assertEqual(result["path"], "main.py")
        self.assertEqual(result["run"], "true")

    def test_stops_after_second_truncated_response(self):
        responses = [self.response("{", "length"), self.response("{", "length")]
        with patch.object(nodes, "OPENAI_API_KEY", "test-key"), \
             patch.object(nodes, "OPENAI_API_BASE", "http://model.invalid/v1"), \
             patch.object(nodes, "cache_llm_response"), \
             patch.object(nodes.requests, "post", side_effect=responses) as post:
            with self.assertRaisesRegex(ValueError, "token 上限截断"):
                nodes._agent_entry_plan(
                    self.task, self.repo, {"main.py": "print('synthetic')"}, "python",
                    ["main.py"],
                )
        self.assertEqual(post.call_count, 2)

    def test_retries_empty_or_invalid_plan_and_validates_replacement(self):
        good_plan = json.dumps({"run": True, "path": "main.py", "command": "python main.py"})
        for content in ("", '{"run":', '{"run":"false"}', '{"path":"main.py","command":"python main.py --plot"}'):
            with self.subTest(content=content), \
                 patch.object(nodes, "OPENAI_API_KEY", "test-key"), \
                 patch.object(nodes, "OPENAI_API_BASE", "http://model.invalid/v1"), \
                 patch.object(nodes, "cache_llm_response"), \
                 patch.object(nodes.requests, "post", side_effect=[
                     self.response(content, "stop"), self.response(good_plan, "stop"),
                 ]) as post:
                result = nodes._agent_entry_plan(self.task, self.repo, {"main.py": ""}, "python")
                self.assertEqual(result["path"], "main.py")
                self.assertEqual(post.call_count, 2)
                self.assertIn("不加参数", post.call_args.kwargs["json"]["messages"][-1]["content"])

    def test_invalid_command_is_still_rejected_after_retry(self):
        response = self.response('{"path":"main.py","command":"python main.py --plot"}', "stop")
        with patch.object(nodes, "OPENAI_API_KEY", "test-key"), \
             patch.object(nodes, "OPENAI_API_BASE", "http://model.invalid/v1"), \
             patch.object(nodes, "cache_llm_response"), \
             patch.object(nodes.requests, "post", return_value=response) as post:
            with self.assertRaisesRegex(ValueError, "直接 Python 文件执行校验"):
                nodes._agent_entry_plan(self.task, self.repo, {"main.py": ""}, "python")
        self.assertEqual(post.call_count, 2)

    def test_only_selects_an_audited_entry_and_nearest_manifest(self):
        project = self.repo / "week" / "nested"
        project.mkdir(parents=True)
        (project / "solution.py").write_text("print('synthetic')\n", encoding="utf-8")
        (project / "requirements.txt").touch()
        entry = "week/nested/solution.py"
        manifest = "week/nested/requirements.txt"
        plan = json.dumps({"path": entry, "command": f"python {entry}", "project_dir": "week"})

        with self.assertRaisesRegex(ValueError, "文件不在已审计"):
            nodes._validate_entry_plan(plan, self.repo, [manifest])
        with self.assertRaisesRegex(ValueError, "依赖清单不在已审计"):
            nodes._validate_entry_plan(plan, self.repo, [entry])
        self.assertEqual(nodes._validate_entry_plan(plan, self.repo, [entry, manifest])["requirements_file"], manifest)

        (self.repo / "sibling").mkdir()
        (self.repo / "sibling/requirements.txt").touch()
        sibling = "sibling/requirements.txt"
        plan = json.dumps({"path": entry, "command": f"python {entry}", "project_dir": ".", "requirements_file": sibling})
        with self.assertRaisesRegex(ValueError, "不属于所选作业目录"):
            nodes._validate_entry_plan(plan, self.repo, [entry, manifest, sibling])

    def test_later_planner_failure_keeps_first_run_evidence_for_scoring(self):
        state = {"task": self.task, "repo_dir": str(self.repo), "raw_code_files": {"main.py": ""}, "nonce": "test"}
        plan = {
            "run": "true", "done": False, "path": "main.py", "command": "python main.py",
            "reason": "choose the assignment entry", "goal": "show the sample result",
            "expected_observation": "value=2",
        }
        run = DynamicRunResult(executed=True, exit_code=0, stdout="value=3")
        with patch.object(nodes, "_agent_entry_plan", side_effect=[plan, ValueError("invalid second plan")]) as planner, \
             patch.object(nodes, "sandbox_runner_tool", return_value=run) as sandbox:
            result = nodes.dynamic_exec_node(state)["dynamic_run"]

        sandbox.assert_called_once()
        self.assertIn("value=3", planner.call_args.args[-1])
        self.assertTrue(result.executed)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.termination, "planning_failed")
        self.assertEqual(result.termination_step, 2)
        self.assertIsNone(result.error_summary)
        evidence = "\n".join(nodes._dynamic_evidence_sections(result, "test"))
        self.assertIn("第 2 轮终止原因", evidence)
        self.assertIn("未提供受信断言", evidence)
        self.assertIn('"expected_observation": "value=2"', evidence)
        self.assertIn('"stdout_excerpt": "value=3"', evidence)
        self.assertIn('source="dynamic-step-1"', evidence)

    def test_dependency_security_violation_stops_before_next_planning_call(self):
        state = {"task": self.task, "repo_dir": str(self.repo), "raw_code_files": {"main.py": ""}}
        plan = {"run": "true", "done": False, "path": "main.py", "command": "python main.py", "reason": ""}
        blocked = DynamicRunResult(executed=False, exit_code=-3, error_summary="DEPENDENCY_SECURITY_VIOLATION")
        with patch.object(nodes, "_agent_entry_plan", return_value=plan) as planner, \
             patch.object(nodes, "sandbox_runner_tool", return_value=blocked) as sandbox:
            result = nodes.dynamic_exec_node(state)["dynamic_run"]

        planner.assert_called_once()
        sandbox.assert_called_once()
        self.assertEqual(result.termination, "dependency_blocked")
        self.assertEqual(result.error_summary, "DEPENDENCY_SECURITY_VIOLATION")

    def test_report_format_normalization_does_not_invent_grading_evidence(self):
        response = (
            "核心功能尚未完成。\n\n#### 3. 运行结果\n- 模型称 12 个测试全部通过。\n"
            "\n#### 4. 未满分原因\n- 实现缺失。\n\n**最终评定分数**: **5 / 100.0**"
        )
        report = nodes._student_visible_report(response, DynamicRunResult(executed=True, exit_code=0))
        self.assertIn("核心功能尚未完成", report)
        self.assertIn("进程退出码 0；未提供受信测试结果", report)
        self.assertIn("实现缺失", report)
        self.assertNotIn("12 个测试全部通过", report)
        self.assertNotIn("核心功能和运行结果均已完成", report)
        self.assertEqual(nodes.extract_score_from_llm_output(report), 5.0)

    def test_missing_dependency_attribution_requires_current_source_corroboration(self):
        state = {"task": self.task, "repo_dir": str(self.repo), "raw_code_files": {"main.py": "print('sample')"}}
        plan = {"run": "true", "done": True, "path": "main.py", "command": "python main.py", "reason": ""}
        run = DynamicRunResult(
            executed=True, exit_code=1,
            stderr="ModuleNotFoundError: No module named 'numpy'",
            error_summary="STUDENT_MISSING_REQUIREMENTS_TXT: no manifest found",
        )
        with patch.object(nodes, "_agent_entry_plan", return_value=plan), \
             patch.object(nodes, "sandbox_runner_tool", return_value=run):
            result = nodes.dynamic_exec_node(state)["dynamic_run"]

        self.assertEqual(result.error_summary, "缺失依赖未获独立源码佐证")
        self.assertEqual(result.steps[0].error_summary, result.error_summary)

    def test_later_dependency_block_does_not_claim_nothing_ran(self):
        state = {
            "task": TaskPayload(taskId="test-id", studentId="test-id", assignmentId="test-id", repoUrl=""),
            "repo_dir": str(self.repo), "raw_code_files": {"main.py": ""},
        }
        plan = {"run": "true", "done": False, "path": "main.py", "command": "python main.py", "reason": ""}
        outcomes = [
            DynamicRunResult(executed=True, exit_code=0),
            DynamicRunResult(executed=False, exit_code=-3, error_summary="DEPENDENCY_SECURITY_VIOLATION"),
        ]
        with patch.object(nodes, "_agent_entry_plan", return_value=plan), \
             patch.object(nodes, "sandbox_runner_tool", side_effect=outcomes):
            state.update(nodes.dynamic_exec_node(state))

        report = nodes.rfc_evaluator_node(state)["final_report_payload"]
        self.assertIn("依赖检查发生在前序运行之后", report.details)
        self.assertNotIn("本次没有执行提交代码", report.details)


if __name__ == "__main__":
    unittest.main()
