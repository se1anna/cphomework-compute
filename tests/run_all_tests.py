"""
RFC Audit Agent - 全量单元测试与端到端集成回归套件
"""

import sys
import unittest
from pathlib import Path

# 确保项目根目录在 sys.path 中
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))


def run_test_suite():
    print("=================================================================")
    print("  RFC 审计 Agent (LangGraph) - 全量安全加固与流程回归测试")
    print("=================================================================\n")

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # 加载所有测试用例
    tests_dir = Path(__file__).resolve().parent
    discovered = loader.discover(start_dir=str(tests_dir), pattern="test_*.py")
    suite.addTests(discovered)

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n=================================================================")
    if result.wasSuccessful():
        print(f"  测试结果: 全部通过 ({result.testsRun} / {result.testsRun} PASS)")
    else:
        print(f"  测试结果: 存在失败 (通过: {result.testsRun - len(result.failures) - len(result.errors)}, 失败: {len(result.failures)}, 错误: {len(result.errors)})")
    print("=================================================================\n")

    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    run_test_suite()
