"""
测试用例 2：远端预检与大型非代码资产过滤测试
"""

import unittest
import tempfile
import shutil
from pathlib import Path
from security.preflight import inspect_repository_tree


class TestPreflightFilter(unittest.TestCase):

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_preflight_filters_large_assets(self):
        # 创建合法代码文件
        (self.temp_dir / "solution.py").write_text("print('hello')", encoding="utf-8")
        (self.temp_dir / "README.md").write_text("# My Homework", encoding="utf-8")

        # 创建大型数据集与多媒体模拟文件
        (self.temp_dir / "model_weights.pt").write_bytes(b"0" * 1024)
        (self.temp_dir / "dataset.h5").write_bytes(b"0" * 1024)
        (self.temp_dir / "output.png").write_bytes(b"0" * 1024)
        (self.temp_dir / "large_archive.zip").write_bytes(b"0" * 1024)

        result = inspect_repository_tree(self.temp_dir)

        self.assertTrue(result.passed)
        self.assertIn("solution.py", result.code_files)
        self.assertEqual(result.primary_language, "python")
        
        # 验证大文件被识别并过滤
        filtered_str = " ".join(result.filtered_assets)
        self.assertIn("model_weights.pt", filtered_str)
        self.assertIn("dataset.h5", filtered_str)
        self.assertIn("output.png", filtered_str)
        self.assertIn("large_archive.zip", filtered_str)

    def test_preflight_blocks_empty_repo(self):
        # 空仓库
        result = inspect_repository_tree(self.temp_dir)
        self.assertFalse(result.passed)


if __name__ == "__main__":
    unittest.main()
