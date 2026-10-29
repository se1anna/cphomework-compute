"""
测试用例 6：旁路资源监控器实时采样测试
"""

import sys
import time
import subprocess
import unittest
from core.sidecar_monitor import SidecarProcessMonitor


class TestSidecarMonitor(unittest.TestCase):

    def test_sidecar_captures_metrics(self):
        # 启动一个简短的子进程
        code = "import time; data = [0]*1000000; time.sleep(0.3)"
        proc = subprocess.Popen([sys.executable, "-c", code])

        monitor = SidecarProcessMonitor(proc.pid, sample_interval_sec=0.05)
        monitor.start()

        proc.wait(timeout=5)
        metrics = monitor.stop()

        self.assertGreaterEqual(metrics.wall_time_sec, 0.2)
        self.assertGreater(metrics.peak_rss_mb, 1.0)
        self.assertIsInstance(metrics.cuda_available, bool)


if __name__ == "__main__":
    unittest.main()
