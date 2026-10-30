"""
测试用例 5：Python 虚拟环境依赖哈希持久化复用测试
"""

import unittest
import tempfile
import shutil
import zipfile
from unittest.mock import patch, MagicMock
from pathlib import Path
from env_manager.python_venv import compute_requirements_hash, get_or_create_cached_venv
from security.dependency_audit import audit_wheelhouse, parse_dependency_manifest
from core.exceptions import DependencyRiskException


class TestPythonVenv(unittest.TestCase):

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_requirements_hash_consistency(self):
        req1 = "numpy>=1.20\nscipy>=1.7\n# Some comments\n"
        req2 = "# Different comment\nnumpy>=1.20\nscipy>=1.7\n"
        hash1 = compute_requirements_hash(req1)
        hash2 = compute_requirements_hash(req2)
        self.assertEqual(hash1, hash2)

    def test_fallback_to_system_python_when_empty(self):
        py_exe, log = get_or_create_cached_venv(self.temp_dir)
        self.assertTrue(Path(py_exe).exists())
        self.assertIn("默认 Python", log)

    def test_requirements_rejects_pip_directives_and_urls_before_install(self):
        for content in ("-e git+https://example.invalid/repo\n", "demo @ https://example.invalid/demo.whl\n", "./local-package\n"):
            manifest = self.temp_dir / "requirements.txt"
            manifest.write_text(content, encoding="utf-8")
            with self.assertRaises(ValueError):
                parse_dependency_manifest(manifest)

    def test_pyproject_requires_pep621_dependencies_without_building(self):
        manifest = self.temp_dir / "pyproject.toml"
        manifest.write_text('[build-system]\nrequires = ["arbitrary-backend"]\nbuild-backend = "backend"\n', encoding="utf-8")
        with self.assertRaises(ValueError):
            parse_dependency_manifest(manifest)

    def test_wheelhouse_rejects_startup_hooks_and_backslash_paths(self):
        for wheel_member in ("demo.pth", "..\\outside.py"):
            wheelhouse = self.temp_dir / "wheelhouse"
            shutil.rmtree(wheelhouse, ignore_errors=True)
            wheelhouse.mkdir()
            wheel_path = wheelhouse / "demo-1.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel_path, "w") as archive:
                archive.writestr(wheel_member, "passive test data")
            with self.assertRaises(DependencyRiskException):
                audit_wheelhouse(wheelhouse)

    def test_installer_uses_secret_free_wheel_only_pipeline(self):
        repo = self.temp_dir / "repo"
        repo.mkdir()
        (repo / "requirements.txt").write_text("demo-package>=1\n", encoding="utf-8")
        venv_root = self.temp_dir / "venvs"
        pip_cache = self.temp_dir / "pip-cache"

        def fake_run(command, **kwargs):
            result = MagicMock(returncode=0, stdout="", stderr="")
            if command[1:3] == ["-m", "venv"]:
                target = Path(command[-1])
                (target / "bin").mkdir(parents=True, exist_ok=True)
                (target / "bin" / "python").touch()
            elif "download" in command:
                destination = Path(command[command.index("--dest") + 1])
                with zipfile.ZipFile(destination / "demo_package-1.0-py3-none-any.whl", "w") as archive:
                    archive.writestr("demo_package/__init__.py", "VALUE = 1\n")
            return result

        with patch("env_manager.python_venv.VENV_CACHE_DIR", venv_root), \
             patch("env_manager.python_venv.PIP_CACHE_DIR", pip_cache), \
             patch("env_manager.python_venv.subprocess.run", side_effect=fake_run) as run, \
             patch("env_manager.python_venv.audit_venv_dependencies", return_value=[]):
            get_or_create_cached_venv(repo, requirements_file="requirements.txt")

        self.assertEqual(run.call_count, 3)
        calls = [call.args[0] for call in run.call_args_list]
        self.assertIn("download", calls[1])
        self.assertIn("--only-binary=:all:", calls[1])
        self.assertIn("--no-index", calls[2])
        for call in run.call_args_list:
            env = call.kwargs["env"]
            self.assertNotIn("OPENAI_API_KEY", env)
            self.assertNotIn("COMPUTE_AUTH_TOKEN", env)
            self.assertNotIn("GITLABAPIKEY", env)

    def test_installer_propagates_configured_ustc_mirror_and_retries(self):
        repo = self.temp_dir / "repo"
        repo.mkdir()
        (repo / "requirements.txt").write_text("demo-package>=1\n", encoding="utf-8")
        venv_root = self.temp_dir / "venvs"
        pip_cache = self.temp_dir / "pip-cache"

        def fake_run(command, **kwargs):
            if command[1:3] == ["-m", "venv"]:
                target = Path(command[-1])
                (target / "bin").mkdir(parents=True, exist_ok=True)
                (target / "bin" / "python").touch()
            elif "download" in command:
                destination = Path(command[command.index("--dest") + 1])
                with zipfile.ZipFile(destination / "demo_package-1.0-py3-none-any.whl", "w") as archive:
                    archive.writestr("demo_package/__init__.py", "VALUE = 1\n")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch.dict("os.environ", {
            "PIP_INDEX_URL": "https://pypi.mirrors.ustc.edu.cn/simple",
            "PIP_DEFAULT_TIMEOUT": "30",
            "PIP_RETRIES": "5",
            "OPENAI_API_KEY": "must-not-propagate",
        }), patch("env_manager.python_venv.VENV_CACHE_DIR", venv_root), \
             patch("env_manager.python_venv.PIP_CACHE_DIR", pip_cache), \
             patch("env_manager.python_venv.subprocess.run", side_effect=fake_run) as run, \
             patch("env_manager.python_venv.audit_venv_dependencies", return_value=[]):
            get_or_create_cached_venv(repo, requirements_file="requirements.txt")

        download_env = run.call_args_list[1].kwargs["env"]
        self.assertEqual(download_env["PIP_INDEX_URL"], "https://pypi.mirrors.ustc.edu.cn/simple")
        self.assertEqual(download_env["PIP_DEFAULT_TIMEOUT"], "30")
        self.assertEqual(download_env["PIP_RETRIES"], "5")
        self.assertNotIn("OPENAI_API_KEY", download_env)


if __name__ == "__main__":
    unittest.main()
