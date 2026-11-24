"""
测试用例 10：沙箱白名单环境变量隔离、Git 受限克隆与配置安全加固专项测试
"""

import os
import sys
import unittest
import tempfile
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

# 确保项目根目录在 sys.path 中
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from core.models import TaskPayload
from sandbox.runner import execute_code_sandbox
from security.cloner import prepare_student_workspace
from security.clone_planner import is_safe_checkout_path


class TestSandboxSecurityHardening(unittest.TestCase):
    """测试沙箱执行期间环境变量隔离与机密防泄露"""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        workspace = patch("security.cloner.WORKSPACE_DIR", self.temp_dir / "workspaces")
        workspace.start()
        self.addCleanup(workspace.stop)

    def git_tree(self, *paths):
        return b"".join(b"100644 blob " + b"0" * 40 + b"\t" + path.encode() + b"\0" for path in paths)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # Synthetic, non-parseable test input; split markers to avoid secret scanners
    # mistaking the fixture for a publishable private key.
    DEPLOY_KEY = (
        "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n"
        + "unit-test-key-material\n"
        + "-----END " + "OPENSSH PRIVATE KEY-----"
    )

    def test_sandbox_env_isolation_shields_all_internal_secrets(self):
        """测试沙箱白名单环境变量注入：学生代码无法读取父进程机密环境变量"""
        sol_file = self.temp_dir / "solution.py"
        sol_file.write_text("""
import os

key = os.environ.get("OPENAI_API_KEY")
token = os.environ.get("COMPUTE_AUTH_TOKEN")
plane_url = os.environ.get("CONTROL_PLANE_URL")
worker_id = os.environ.get("WORKER_ID")

print(f"OPENAI_API_KEY={key}")
print(f"COMPUTE_AUTH_TOKEN={token}")
print(f"CONTROL_PLANE_URL={plane_url}")
print(f"WORKER_ID={worker_id}")
""", encoding="utf-8")

        # 在父进程模拟敏感环境变量
        with patch.dict(os.environ, {
            "OPENAI_API_KEY": "sk-secret-leaked-key-12345",
            "COMPUTE_AUTH_TOKEN": "secret-compute-token-9999",
            "CONTROL_PLANE_URL": "http://internal-kubernetes-control-plane:8787",
            "WORKER_ID": "secret-worker-id-internal-01"
        }):
            res = execute_code_sandbox(self.temp_dir, language="python")

        self.assertTrue(res.executed)
        self.assertEqual(res.exit_code, 0)
        self.assertIn("OPENAI_API_KEY=None", res.stdout)
        self.assertIn("COMPUTE_AUTH_TOKEN=None", res.stdout)
        self.assertIn("CONTROL_PLANE_URL=None", res.stdout)
        self.assertIn("WORKER_ID=None", res.stdout)

    @patch("security.cloner.SSH_KNOWN_HOSTS_FILE", __file__)
    @patch("security.cloner.choose_sparse_paths", return_value=(["week_3/main.py", "requirements.txt"], "test planner"))
    @patch("security.cloner.subprocess.run")
    def test_git_cloner_security_parameters_and_env(self, mock_run, _mock_planner):
        """测试 Git 克隆受限参数：禁止跟随重定向、限制大对象、浅克隆且隔离机密环境变量"""
        def fake_run(cmd, **kwargs):
            mock_res = MagicMock(returncode=0, stderr="")
            if "ls-tree" in cmd:
                mock_res.stdout = self.git_tree("week_3/main.py", "requirements.txt")
            elif "checkout-index" in cmd:
                worktree = Path(cmd[2])
                (worktree / "week_3").mkdir(parents=True, exist_ok=True)
                (worktree / "week_3" / "main.py").write_text("print('ok')", encoding="utf-8")
                (worktree / "requirements.txt").write_text("", encoding="utf-8")
            else:
                mock_res.stdout = "Cloned"
            return mock_res
        mock_run.side_effect = fake_run

        task = TaskPayload(
            taskId="task-clone-test-01",
            studentId="student-test-0001",
            assignmentId="hw-test",
            assignmentTitle="测试作业",
            repoUrl="https://github.com/whu-student/hw1",
            branch="main",
            deployKey=self.DEPLOY_KEY,
        )

        with patch.dict(os.environ, {
            "OPENAI_API_KEY": "sk-top-secret-token",
            "COMPUTE_AUTH_TOKEN": "compute-secret-xyz"
        }):
            success, target_dir, log = prepare_student_workspace(task)

        self.assertTrue(success)
        self.assertTrue(mock_run.called)
        clone_call = next(call for call in mock_run.call_args_list if "clone" in call.args[0])
        cmd = clone_call.args[0]
        env = clone_call.kwargs.get("env", {})

        # 校验关键安全标志
        self.assertIn("-c", cmd)
        self.assertIn("http.followRedirects=false", cmd)
        self.assertIn("--filter=blob:none", cmd)
        self.assertIn("--no-checkout", cmd)
        self.assertIn("--depth", cmd)
        self.assertIn("1", cmd)

        # 校验环境变量脱敏
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertNotIn("COMPUTE_AUTH_TOKEN", env)
        self.assertEqual(env.get("GIT_TERMINAL_PROMPT"), "0")
        self.assertIn("GIT_SSH_COMMAND", env)
        self.assertIn("IdentitiesOnly=yes", env["GIT_SSH_COMMAND"])
        self.assertNotIn(self.DEPLOY_KEY, env["GIT_SSH_COMMAND"])
        index_call = next(call for call in mock_run.call_args_list if "update-index" in call.args[0])
        self.assertEqual(index_call.args[0][3:], ["update-index", "-z", "--index-info"])
        self.assertEqual(index_call.kwargs["input"], self.git_tree("week_3/main.py", "requirements.txt"))
        checkout_call = next(call for call in mock_run.call_args_list if "checkout-index" in call.args[0])
        self.assertEqual(checkout_call.args[0][3:], ["checkout-index", "--all"])

    @patch("security.cloner.Path.is_file", return_value=True)
    @patch("security.cloner.choose_sparse_paths", return_value=(["main.py"], "test planner"))
    @patch("security.cloner.subprocess.run")
    def test_https_github_url_is_converted_to_ssh(self, mock_run, _mock_planner, _mock_is_file):
        def fake_run(cmd, **kwargs):
            result = MagicMock(returncode=0, stdout=self.git_tree("requirements.txt", "main.py"), stderr="")
            if "checkout-index" in cmd:
                worktree = Path(cmd[2])
                (worktree / "main.py").write_text("print('ok')", encoding="utf-8")
            return result
        mock_run.side_effect = fake_run
        task = TaskPayload(
            taskId="task-ssh-url-01", studentId="s", assignmentId="a",
            repoUrl="https://github.com/student/private-hw",
            deployKey=self.DEPLOY_KEY,
        )
        success, _, _ = prepare_student_workspace(task)
        self.assertTrue(success)
        clone_call = next(call for call in mock_run.call_args_list if "clone" in call.args[0])
        cmd = clone_call.args[0]
        self.assertIn("git@github.com:student/private-hw.git", cmd)

    def test_checkout_paths_reject_control_characters_and_bytecode(self):
        for path in ("bad\nname.py", "bad\rname.py", "bad\tname.py", "a\\b.py",
                     "project/__pycache__/example.py", "project/example.pyc"):
            with self.subTest(path=path):
                self.assertFalse(is_safe_checkout_path(path))

    def test_checkout_materializes_only_exact_selected_files(self):
        repo = self.temp_dir / "origin"
        repo.mkdir()
        tracked = ("项目/结果[1].py", "项目/结果1.py", "项目/requirements.txt", "README.md")
        for name in tracked:
            path = repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"# inert fixture: {name}\n", encoding="utf-8")

        git = ["git", "-C", str(repo)]
        subprocess.run(git + ["init", "-q"], check=True)
        subprocess.run(git + ["config", "uploadpack.allowFilter", "true"], check=True)
        subprocess.run(git + ["config", "uploadpack.allowAnySHA1InWant", "true"], check=True)
        subprocess.run(git + ["add", "."], check=True)
        subprocess.run(
            git + ["-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                   "commit", "-qm", "inert fixture"],
            check=True,
        )

        task = TaskPayload(
            taskId="task-literal-checkout", studentId="s", assignmentId="a",
            repoUrl=repo.as_uri(), subpath="项目",
        )
        selected = [tracked[0], tracked[2], tracked[3]]
        with patch("security.cloner.choose_sparse_paths", return_value=(selected, "test planner")):
            success, target, log = prepare_student_workspace(task)

        self.assertTrue(success, log)
        self.assertEqual(target.name, "项目")
        files = {p.relative_to(target.parent).as_posix() for p in target.parent.rglob("*")
                 if p.is_file() and ".git" not in p.relative_to(target.parent).parts}
        self.assertEqual(files, set(selected))

    @patch("security.cloner.SSH_KNOWN_HOSTS_FILE", __file__)
    @patch("security.cloner.subprocess.run")
    def test_ssh_clone_requires_per_task_deploy_key(self, mock_run):
        task = TaskPayload(
            taskId="task-ssh-no-key-01", studentId="s", assignmentId="a",
            repoUrl="git@github.com:student/private-hw.git",
        )
        success, _, log = prepare_student_workspace(task)
        self.assertFalse(success)
        self.assertIn("deployKey", log)
        mock_run.assert_not_called()

    @patch("security.cloner.SSH_KNOWN_HOSTS_FILE", __file__)
    @patch("security.cloner.subprocess.run")
    def test_double_escaped_deploy_key_newlines_are_normalized(self, mock_run):
        def fake_run(cmd, **kwargs):
            result = MagicMock(returncode=0, stdout="", stderr="")
            if "ls-tree" in cmd:
                result.stdout = self.git_tree("main.py")
            elif "checkout-index" in cmd:
                worktree = Path(cmd[2])
                (worktree / "main.py").write_text("print('ok')", encoding="utf-8")
            return result
        mock_run.side_effect = fake_run
        task = TaskPayload(
            taskId="task-ssh-escaped-key-01", studentId="s", assignmentId="a",
            repoUrl="git@github.com:student/private-hw.git",
            deployKey=self.DEPLOY_KEY.replace("\n", "\\n"),
        )
        success, _, _ = prepare_student_workspace(task)
        self.assertTrue(success)
        self.assertIn("-i", mock_run.call_args.kwargs["env"]["GIT_SSH_COMMAND"])

    def test_student_pass_output_is_not_counted_as_trusted_tests(self):
        (self.temp_dir / "solution.py").write_text("print('PASS OK passed')\n", encoding="utf-8")
        result = execute_code_sandbox(
            self.temp_dir, language="python", entry_file="solution.py", timeout_sec=5
        )
        self.assertTrue(result.executed)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.tests_passed, 0)
        self.assertEqual(result.tests_total, 0)
        self.assertIn("PASS OK passed", result.stdout)

    @patch("security.cloner.SSH_KNOWN_HOSTS_FILE", __file__)
    @patch("security.cloner.subprocess.run")
    def test_mixed_escaped_and_real_deploy_key_newlines_are_normalized(self, mock_run):
        def fake_run(cmd, **kwargs):
            result = MagicMock(returncode=0, stdout="", stderr="")
            if "ls-tree" in cmd:
                result.stdout = self.git_tree("main.py")
            elif "checkout-index" in cmd:
                worktree = Path(cmd[2])
                (worktree / "main.py").write_text("print('ok')", encoding="utf-8")
            return result
        mock_run.side_effect = fake_run
        mixed_key = self.DEPLOY_KEY.replace("\n", "\\n", 1)
        task = TaskPayload(
            taskId="task-ssh-mixed-key-01", studentId="s", assignmentId="a",
            repoUrl="git@github.com:student/private-hw.git",
            deployKey=mixed_key,
        )
        success, _, _ = prepare_student_workspace(task)
        self.assertTrue(success)
        self.assertIn("-i", mock_run.call_args.kwargs["env"]["GIT_SSH_COMMAND"])


if __name__ == "__main__":
    unittest.main()
