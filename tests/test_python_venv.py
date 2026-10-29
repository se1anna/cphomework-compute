"""
测试用例 5：Python 虚拟环境依赖哈希持久化复用测试
"""

import unittest
import tempfile
import shutil
from pathlib import Path
from env_manager.python_venv import compute_requirements_hash, get_or_create_cached_venv


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


if __name__ == "__main__":
    unittest.main()
