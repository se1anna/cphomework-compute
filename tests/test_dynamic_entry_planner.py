import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import graph.nodes as nodes


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
        for content in ("", '{"run":', '{"path":"main.py","command":"python main.py --plot"}'):
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


if __name__ == "__main__":
    unittest.main()
