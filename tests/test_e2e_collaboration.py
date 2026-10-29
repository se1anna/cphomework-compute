"""
RFC Audit Agent & Control Plane 跨系统全链路协作集成测试套件
真实模拟控制层 (cphomework) 与计算层 (CP) 的完整 HTTP 通信、数据契约、多轮评测递增及异常容灾。
"""

import os
import sys
import json
import time
import shutil
import tempfile
import unittest
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# 将项目根目录加入模块路径
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.models import TaskPayload, RFCReportPayload
from client.control_plane import ControlPlaneClient
from graph.workflow import build_audit_graph


class MockControlPlaneHandler(BaseHTTPRequestHandler):
    """模拟 Cloudflare Workers 控制层 HTTP 接口"""
    
    tasks_queue = []
    submissions_db = {}
    reports_received = []
    auth_token = "test-only-local-token"

    def log_message(self, format, *args):
        # 静默控制台请求日志，保持测试输出清晰
        pass

    def _check_auth(self) -> bool:
        auth_hdr = self.headers.get("Authorization", "")
        custom_hdr = self.headers.get("X-Compute-Token", "")
        token = custom_hdr or (auth_hdr[7:] if auth_hdr.startswith("Bearer ") else "")
        return token == self.auth_token

    def do_GET(self):
        if self.path == "/api/compute/task":
            if not self._check_auth():
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": "Unauthorized"}).encode("utf-8"))
                return

            if not self.tasks_queue:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "hasTask": False}).encode("utf-8"))
                return

            task = self.tasks_queue.pop(0)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "hasTask": True, "task": task}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path == "/api/compute/report":
            if not self._check_auth():
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": "Unauthorized"}).encode("utf-8"))
                return

            content_len = int(self.headers.get("Content-Length", 0))
            body_bytes = self.rfile.read(content_len)
            payload = json.loads(body_bytes.decode("utf-8"))

            task_id = payload.get("taskId")
            student_id = payload.get("studentId")
            assignment_id = payload.get("assignmentId")
            score = payload.get("score")

            sub_key = f"{assignment_id}:{student_id}"
            sub = self.submissions_db.get(sub_key, {})

            # 幂等性检测
            if sub.get("status") == "graded" and sub.get("lastTaskId") == task_id:
                if sub.get("score") == score:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"success": True, "idempotent": True}).encode("utf-8"))
                    return
                else:
                    self.send_response(409)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"success": False, "error": "Score mismatch on completed task"}).encode("utf-8"))
                    return

            # 任务活跃性检测
            if sub.get("activeTaskId") != task_id:
                self.send_response(409)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": "Task mismatch or superseded"}).encode("utf-8"))
                return

            # 正常写回
            sub["status"] = "graded"
            sub["lastTaskId"] = task_id
            sub["activeTaskId"] = None
            sub["score"] = score
            sub["details"] = payload.get("details")
            history = sub.get("history", [])
            history.append({
                "round": len(history) + 1,
                "roundLabel": f"第{len(history) + 1}次评测",
                "taskId": task_id,
                "score": score,
                "details": payload.get("details")
            })
            sub["history"] = history
            self.submissions_db[sub_key] = sub
            self.reports_received.append(payload)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "submission": sub}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()


class TestSystemCollaboration(unittest.TestCase):
    """跨系统协同与契约健壮性回归测试"""

    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), MockControlPlaneHandler)
        cls.port = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        MockControlPlaneHandler.tasks_queue = []
        MockControlPlaneHandler.submissions_db = {}
        MockControlPlaneHandler.reports_received = []
        self.temp_dir = tempfile.mkdtemp(prefix="test_collab_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_null_fields_resilience(self):
        """测试契约健壮性：控制层返回带有大量 null 的 JSON 时，计算层能稳定反序列化"""
        raw_task_with_nulls = {
            "taskId": "task-collab-null-01",
            "studentId": "student-test-0001",
            "assignmentId": "hw-1",
            "assignmentTitle": None,
            "assignmentOverview": None,
            "assignmentDetails": None,
            "title": None,
            "overview": None,
            "details": None,
            "currentRound": None,
            "currentRoundLabel": None,
            "history": None,
            "historyPrompt": None,
            "repoUrl": "https://github.com/student/repo",
            "branch": None,
            "subpath": None,
            "submittedAt": None
        }
        # 不发生 Pydantic 校验中断，安全自动赋予初值
        task = TaskPayload(**raw_task_with_nulls)
        self.assertEqual(task.assignmentTitle, "")
        self.assertEqual(task.currentRound, 1)
        self.assertEqual(task.history, [])
        self.assertEqual(task.get_effective_details(), "")

    def test_multi_round_with_null_history_scores(self):
        """测试多轮历史评分健壮性：前序轮次中包含 score 为 None 的异常记录不引起崩溃"""
        raw_task_with_null_history = {
            "taskId": "task-collab-round2",
            "studentId": "student-test-0001",
            "assignmentId": "hw-1",
            "assignmentTitle": "数值积分",
            "assignmentOverview": "实现积分计算并输出结果",
            "repoUrl": "https://github.com/student/repo",
            "currentRound": 2,
            "currentRoundLabel": "第二次评测",
            "history": [
                {
                    "round": 1,
                    "roundLabel": "第一次评测",
                    "score": None, # 先前发生异常或未出分
                    "details": "上轮未完成"
                }
            ],
            "submittedAt": "2026-09-18T10:00:00Z"
        }
        task = TaskPayload(**raw_task_with_null_history)
        self.assertEqual(len(task.history), 1)

        # 验证 LangGraph 状态图全链路在存在 score: None 历史时能平稳运行
        local_repo = Path(self.temp_dir) / "student_repo"
        local_repo.mkdir()
        code = """
import math

# 数值积分：测试夹具的题目语义证据

def calculate_integral_solution():
    x = 1.0
    return math.sin(x)

if __name__ == "__main__":
    print(calculate_integral_solution())
"""
        (local_repo / "solution.py").write_text(code, encoding="utf-8")

        graph = build_audit_graph()
        initial_state = {
            "task": task,
            "repo_dir": str(local_repo),
            "nonce": "",
            "retry_count": 0,
            "retry_context": ""
        }
        res = graph.invoke(initial_state)
        report = res.get("final_report_payload")
        self.assertIsNotNone(report)
        self.assertGreaterEqual(report.score, 80.0)

    def test_end_to_end_http_client_cycle(self):
        """测试 HTTP 客户端心跳拉取与幂等回传全链路"""
        client = ControlPlaneClient(
            base_url=self.base_url,
            token="test-only-local-token",
            worker_id="test-worker-01"
        )

        # 1. 队列为空时正确返回 None
        self.assertIsNone(client.fetch_task())

        # 2. 控制层压入新任务
        test_task_id = "task-collab-live-101"
        student_id = "student-test-0001"
        assignment_id = "hw-1"
        MockControlPlaneHandler.submissions_db[f"{assignment_id}:{student_id}"] = {
            "assignmentId": assignment_id,
            "studentId": student_id,
            "activeTaskId": test_task_id,
            "status": "in_progress",
            "history": []
        }
        MockControlPlaneHandler.tasks_queue.append({
            "taskId": test_task_id,
            "studentId": student_id,
            "assignmentId": assignment_id,
            "assignmentTitle": "数值积分与数值微分",
            "repoUrl": "https://github.com/student/hw1",
            "submittedAt": "2026-09-18T12:00:00Z"
        })

        # 3. 客户端成功拉取
        task = client.fetch_task()
        self.assertIsNotNone(task)
        self.assertEqual(task.taskId, test_task_id)

        # 4. 客户端回传合法报告
        report = RFCReportPayload(
            taskId=test_task_id,
            studentId=student_id,
            assignmentId=assignment_id,
            score=94.5,
            details="RFC-AUDIT 评测完成"
        )
        success = client.submit_report(report)
        self.assertTrue(success)

        # 5. 控制层状态正确收敛至 graded
        sub = MockControlPlaneHandler.submissions_db[f"{assignment_id}:{student_id}"]
        self.assertEqual(sub["status"], "graded")
        self.assertEqual(sub["score"], 94.5)
        self.assertEqual(len(sub["history"]), 1)

        # 6. 幂等性重试测试：因网络抖动再次提交相同报告，仍成功返回 (idempotent: true)
        idempotent_success = client.submit_report(report)
        self.assertTrue(idempotent_success)

    def test_url_normalization_handles_subpaths(self):
        """测试控制层 URL 格式化容错：带 /api 尾缀时自动归一化，避免 /api/api 路由 404"""
        client = ControlPlaneClient(
            base_url=f"{self.base_url}/api",
            token="test-only-local-token"
        )
        self.assertEqual(client.base_url, self.base_url)


if __name__ == "__main__":
    unittest.main()
