"""
测试用例 9：评分合理性仲裁委员会 (Score Reasonability Arbiter) 与自愈重评回路测试
"""

import sys
import unittest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

# 确保项目根目录在 sys.path 中
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from core.models import TaskPayload, StaticAnalysisResult, DynamicRunResult
from graph.nodes import check_score_reasonability, score_arbiter_node
from graph.workflow import build_audit_graph


class TestCheckScoreReasonabilityRules(unittest.TestCase):
    """测试四大核心仲裁合理性准则"""

    def setUp(self):
        self.task = TaskPayload(
            taskId="task-arbiter-001",
            studentId="student-test-0001",
            assignmentId="hw-arbiter",
            assignmentTitle="数值计算作业",
            currentRound=1,
            currentRoundLabel="第一次评测",
            repoUrl="https://github.com/student/hw-arbiter"
        )

    def test_static_failure_positive_score_rejected(self):
        """规则 0：静态安全扫描未通过时，给分大于0分必须被驳回并纠偏为 0 分"""
        static_fail = StaticAnalysisResult(
            passed=False,
            security_clean=False,
            topic_matched=True,
            violations=["检测到提示词注入攻击", "企图越权逃逸"]
        )
        is_ok, reason, rec_score = check_score_reasonability(
            task=self.task,
            static_res=static_fail,
            dynamic_res=None,
            score=75.0,
            memo="评测通过"
        )
        self.assertFalse(is_ok)
        self.assertIn("静态安全扫描未通过", reason)
        self.assertEqual(rec_score, 0.0)

    def test_static_failure_zero_score_accepted(self):
        """规则 0：静态安全扫描未通过且得分为 0 时直接放行"""
        static_fail = StaticAnalysisResult(
            passed=False,
            security_clean=False,
            topic_matched=True,
            violations=["静态安全扫描未通过"]
        )
        is_ok, reason, rec_score = check_score_reasonability(
            task=self.task,
            static_res=static_fail,
            dynamic_res=None,
            score=0.0,
            memo="REJECTED 安全拒止"
        )
        self.assertTrue(is_ok)
        self.assertIsNone(reason)

    def test_sandbox_crash_high_score_rejected(self):
        """规则 1：沙箱报错崩溃但给分超过 85 分，必须被驳回并建议下调至 80 分以下过程分"""
        static_pass = StaticAnalysisResult(passed=True, security_clean=True, topic_matched=True, violations=[])
        dynamic_crash = DynamicRunResult(
            executed=True,
            exit_code=1,
            stdout="Running...",
            stderr="Traceback (most recent call last): NameError: name 'foo' is not defined",
            error_summary="NameError: name 'foo' is not defined"
        )
        is_ok, reason, rec_score = check_score_reasonability(
            task=self.task,
            static_res=static_pass,
            dynamic_res=dynamic_crash,
            score=95.0,
            memo="代码结构优美"
        )
        self.assertFalse(is_ok)
        self.assertIn("沙箱动态执行异常", reason)
        self.assertEqual(rec_score, 78.0)

    def test_sandbox_crash_moderate_score_accepted(self):
        """规则 1：沙箱报错但给 75 分过程分，合理放行"""
        static_pass = StaticAnalysisResult(passed=True, security_clean=True, topic_matched=True, violations=[])
        dynamic_crash = DynamicRunResult(
            executed=True,
            exit_code=1,
            stdout="",
            stderr="AssertionError",
            error_summary="AssertionError"
        )
        is_ok, reason, rec_score = check_score_reasonability(
            task=self.task,
            static_res=static_pass,
            dynamic_res=dynamic_crash,
            score=75.0,
            memo="过程分 75"
        )
        self.assertTrue(is_ok)

    def test_missing_requirements_manifest_caps_score_at_78(self):
        """A confirmed absent requirements.txt must not be treated as an evaluator outage."""
        static_pass = StaticAnalysisResult(passed=True, security_clean=True, topic_matched=True)
        missing_manifest = DynamicRunResult(
            executed=True,
            exit_code=1,
            stderr="ModuleNotFoundError: No module named 'numpy'",
            error_summary="STUDENT_MISSING_REQUIREMENTS_TXT: numpy is imported but no applicable manifest exists",
        )
        is_ok, reason, rec_score = check_score_reasonability(
            task=self.task,
            static_res=static_pass,
            dynamic_res=missing_manifest,
            score=88.0,
            memo="代码整体完成",
        )
        self.assertFalse(is_ok)
        self.assertIn("缺少 requirements.txt", reason)
        self.assertEqual(rec_score, 78.0)

    def test_declared_dependency_environment_failure_is_not_capped(self):
        """A declared package unavailable at runtime remains an environment issue."""
        static_pass = StaticAnalysisResult(passed=True, security_clean=True, topic_matched=True)
        declared_but_unavailable = DynamicRunResult(
            executed=True,
            exit_code=1,
            stderr="ModuleNotFoundError: No module named 'numpy'",
            error_summary="DECLARED_DEPENDENCY_ENVIRONMENT_FAILURE: numpy is declared but unavailable",
        )
        is_ok, reason, rec_score = check_score_reasonability(
            task=self.task,
            static_res=static_pass,
            dynamic_res=declared_but_unavailable,
            score=88.0,
            memo="依赖已声明",
        )
        self.assertTrue(is_ok)
        self.assertIsNone(reason)
        self.assertIsNone(rec_score)

    def test_all_pass_harsh_low_score_rejected(self):
        """规则 2：沙箱全通无报错但打分低于 85 分苛刻压分，必须被驳回并建议上调至慷慨基准 92 分"""
        static_pass = StaticAnalysisResult(passed=True, security_clean=True, topic_matched=True, violations=[])
        dynamic_pass = DynamicRunResult(
            executed=True,
            exit_code=0,
            stdout="[PASS] Test 1\n[PASS] Test 2",
            stderr="",
            tests_passed=2,
            tests_total=2
        )
        is_ok, reason, rec_score = check_score_reasonability(
            task=self.task,
            static_res=static_pass,
            dynamic_res=dynamic_pass,
            score=68.0,
            memo="代码有些冗长"
        )
        self.assertFalse(is_ok)
        self.assertIn("过于严苛违背慷慨起评分准则", reason)
        self.assertEqual(rec_score, 92.0)

    def test_multiround_score_regression_rejected(self):
        """规则 3：多轮迭代中，上一轮 85 分，本轮代码正常跑通但打出 72 分，严禁倒扣分并建议提分至 >= 88 分"""
        task_round2 = TaskPayload(
            taskId="task-round2",
            studentId="student-test-0001",
            assignmentId="hw-arbiter",
            assignmentTitle="数值计算作业",
            currentRound=2,
            currentRoundLabel="第二次评测",
            history=[{"round": 1, "score": 85.0, "details": "很好"}],
            repoUrl="https://github.com/student/hw-arbiter"
        )
        static_pass = StaticAnalysisResult(passed=True, security_clean=True, topic_matched=True, violations=[])
        dynamic_pass = DynamicRunResult(
            executed=True,
            exit_code=0,
            stdout="[PASS] All tests passed",
            stderr=""
        )
        is_ok, reason, rec_score = check_score_reasonability(
            task=task_round2,
            static_res=static_pass,
            dynamic_res=dynamic_pass,
            score=72.0,
            memo="第二次评测"
        )
        self.assertFalse(is_ok)
        self.assertIn("严重违背多轮迭代递增激励哲学", reason)
        self.assertEqual(rec_score, 88.0)

    def test_verdict_consistency_rejected_memo_with_score(self):
        """规则 4：报告正文声明 REJECTED 但给分 > 0 分，图文矛盾驳回"""
        is_ok, reason, rec_score = check_score_reasonability(
            task=self.task,
            static_res=None,
            dynamic_res=None,
            score=60.0,
            memo="本次作业审核结果：REJECTED，因格式问题。"
        )
        self.assertFalse(is_ok)
        self.assertIn("声明为 REJECTED，但实际回传分数", reason)
        self.assertEqual(rec_score, 0.0)

    def test_verdict_consistency_accepted_memo_with_fail_score(self):
        """规则 4：报告正文声明 ACCEPTED 但给分 < 60 分不及格，图文矛盾驳回"""
        is_ok, reason, rec_score = check_score_reasonability(
            task=self.task,
            static_res=None,
            dynamic_res=None,
            score=50.0,
            memo="综合裁定：ACCEPTED，准予通过。"
        )
        self.assertFalse(is_ok)
        self.assertIn("声明为 ACCEPTED，但实际回传分数", reason)
        self.assertEqual(rec_score, 85.0)


class TestScoreArbiterNode(unittest.TestCase):
    """测试仲裁节点的状态转移、重评触发与强制平滑校准"""

    def setUp(self):
        self.task = TaskPayload(
            taskId="task-arbiter-node-001",
            studentId="student-test-0001",
            assignmentId="hw-arbiter",
            assignmentTitle="数值计算作业",
            currentRound=1,
            currentRoundLabel="第一次评测",
            repoUrl="https://github.com/student/hw-arbiter"
        )

    def test_arbiter_passes_reasonable_score(self):
        """合理分数正常放行，不触发重评"""
        state = {
            "task": self.task,
            "static_analysis": StaticAnalysisResult(passed=True, security_clean=True, topic_matched=True, violations=[]),
            "dynamic_run": DynamicRunResult(executed=True, exit_code=0, stdout="pass", stderr=""),
            "final_score": 93.0,
            "rfc_report": "ACCEPTED 合规通过",
            "arbitration_retries": 0
        }
        res = score_arbiter_node(state)
        self.assertFalse(res["needs_reevaluation"])
        self.assertEqual(res["arbitration_critique"], "")

    def test_arbiter_rejects_and_increments_retry(self):
        """第一次检测到苛刻打分，增加 retries 并生成明确 critique 指令"""
        state = {
            "task": self.task,
            "static_analysis": StaticAnalysisResult(passed=True, security_clean=True, topic_matched=True, violations=[]),
            "dynamic_run": DynamicRunResult(executed=True, exit_code=0, stdout="pass", stderr=""),
            "final_score": 60.0,  # 过于严苛
            "rfc_report": "勉强及格",
            "arbitration_retries": 0
        }
        res = score_arbiter_node(state)
        self.assertTrue(res["needs_reevaluation"])
        self.assertEqual(res["arbitration_retries"], 1)
        self.assertIn("仲裁委员会驳回重评提示 (第 1/2 次)", res["arbitration_critique"])
        self.assertIn("92.0", res["arbitration_critique"])

    def test_arbiter_exhaustion_auto_calibration(self):
        """重试达到上限 (retries >= 2)，执行确定性自动校准，平滑赋予分数并追加修正案，避免死循环"""
        state = {
            "task": self.task,
            "static_analysis": StaticAnalysisResult(passed=True, security_clean=True, topic_matched=True, violations=[]),
            "dynamic_run": DynamicRunResult(executed=True, exit_code=0, stdout="pass", stderr=""),
            "final_score": 60.0,  # 依然不合理
            "rfc_report": "多次打分依然为60",
            "arbitration_retries": 2  # 已重试2次
        }
        res = score_arbiter_node(state)
        self.assertFalse(res["needs_reevaluation"])
        self.assertEqual(res["final_score"], 92.0)
        self.assertIn("[RFC-ARBITRATION-AMENDMENT]", res["rfc_report"])
        self.assertIn("92.0 分", res["rfc_report"])
        self.assertEqual(res["final_report_payload"].score, 92.0)


class TestScoreArbiterGraphLoopE2E(unittest.TestCase):
    """测试端到端 LangGraph 状态图的仲裁循环与自愈能力"""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.graph = build_audit_graph()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("graph.nodes.OPENAI_API_KEY", "mock-key")
    @patch("graph.nodes.requests.post")
    def test_e2e_re_evaluation_loop_success(self, mock_post):
        """
        端到端测试：
        第 1 次评测模型返回 65 分苛刻分 -> Arbiter 驳回并附带 critique；
        第 2 次评测模型收到 critique 并纠偏为 94 分 -> Arbiter 审核通过 -> 顺利结束。
        """
        sol_file = self.temp_dir / "solution.py"
        sol_file.write_text("""
import math

def calculate_physics():
    # 计算物理作业核心算法
    return 42.0

if __name__ == '__main__':
    print('PASS: physics calculations complete')
""", encoding="utf-8")

        task = TaskPayload(
            taskId="task-loop-001",
            studentId="student-test-0001",
            assignmentId="hw-test",
            assignmentTitle="计算物理作业",
            assignmentOverview="完成数值计算并输出正确结果",
            currentRound=1,
            currentRoundLabel="第一次评测",
            repoUrl="https://github.com/student/hw-test"
        )

        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_res = MagicMock()
            mock_res.ok = True
            mock_res.status_code = 200

            # 检查 prompt 是否包含 critique 指令
            messages = kwargs.get("json", {}).get("messages", [])
            user_text = messages[1]["content"] if len(messages) > 1 else ""

            if call_count == 1:
                # 第一次给 65 分 (将被驳回)
                mock_res.json.return_value = {
                    "choices": [{
                        "message": {
                            "content": "# RFC 评阅\n代码略显粗糙。\n**最终评定分数**: **65.0 / 100.0**"
                        }
                    }]
                }
            else:
                # 第二次吸纳 critique，纠偏为 94 分
                self.assertIn("评分合理性仲裁委员会指令", user_text)
                mock_res.json.return_value = {
                    "choices": [{
                        "message": {
                            "content": "# RFC 评阅\n吸纳仲裁意见，代码完全合规跑通。\n**最终评定分数**: **94.0 / 100.0**"
                        }
                    }]
                }
            return mock_res

        mock_post.side_effect = side_effect

        state = {
            "task": task,
            "repo_dir": str(self.temp_dir),
            "nonce": "",
            "retry_count": 0,
            "retry_context": "",
            "arbitration_retries": 0,
            "arbitration_critique": "",
            "needs_reevaluation": False
        }

        result = self.graph.invoke(state)

        # 验证调用了 2 次 LLM
        self.assertEqual(call_count, 2)
        self.assertEqual(result["final_score"], 94.0)
        self.assertEqual(result["arbitration_retries"], 1)
        self.assertIn("94.0", result["rfc_report"])

    @patch("graph.nodes.OPENAI_API_KEY", "mock-key")
    @patch("graph.nodes.requests.post")
    def test_e2e_re_evaluation_exhaustion_auto_calibration(self, mock_post):
        """
        端到端测试：
        若模型固执己见多次返回 65 分 -> 触发 2 次重评 -> 耗尽后自动强制校准为 92 分 -> 保障 Zero-Zombie SLA。
        """
        sol_file = self.temp_dir / "solution.py"
        sol_file.write_text("""
import math

def calculate_physics():
    # 计算物理作业核心算法
    return 42.0

if __name__ == '__main__':
    print('PASS: physics calculations complete')
""", encoding="utf-8")

        task = TaskPayload(
            taskId="task-loop-002",
            studentId="student-test-0001",
            assignmentId="hw-test",
            assignmentTitle="计算物理作业",
            assignmentOverview="完成数值计算并输出正确结果",
            currentRound=1,
            currentRoundLabel="第一次评测",
            repoUrl="https://github.com/student/hw-test"
        )

        mock_res = MagicMock()
        mock_res.ok = True
        mock_res.status_code = 200
        mock_res.json.return_value = {
            "choices": [{
                "message": {
                    "content": "# RFC 评阅\n坚持给低分。\n**最终评定分数**: **65.0 / 100.0**"
                }
            }]
        }
        mock_post.return_value = mock_res

        state = {
            "task": task,
            "repo_dir": str(self.temp_dir),
            "nonce": "",
            "retry_count": 0,
            "retry_context": "",
            "arbitration_retries": 0,
            "arbitration_critique": "",
            "needs_reevaluation": False
        }

        result = self.graph.invoke(state)

        # 验证经历重试耗尽后强制校准出分
        self.assertEqual(result["final_score"], 92.0)
        self.assertIn("[RFC-ARBITRATION-AMENDMENT]", result["rfc_report"])
        self.assertIn("平滑校准为 **92.0 分**", result["rfc_report"])
        self.assertIsNotNone(result.get("final_report_payload"))
        self.assertEqual(result["final_report_payload"].score, 92.0)


if __name__ == "__main__":
    unittest.main()
