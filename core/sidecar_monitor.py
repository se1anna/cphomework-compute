"""
RFC Audit Agent - 旁路资源监控器 (Sidecar Resource Monitor)
高频实时采样目标进程的 CPU、内存 (RSS) 以及 CUDA 显存开销。
"""

import time
import threading
import psutil
from typing import Optional
from .models import RuntimeMetrics

try:
    import torch
    TORCH_CUDA_AVAILABLE = torch.cuda.is_available()
    CUDA_DEVICE_NAME = torch.cuda.get_device_name(0) if TORCH_CUDA_AVAILABLE else "N/A"
except Exception:
    TORCH_CUDA_AVAILABLE = False
    CUDA_DEVICE_NAME = "N/A"


class SidecarProcessMonitor:
    """进程级旁路资源监视器"""
    
    def __init__(self, pid: int, sample_interval_sec: float = 0.1):
        self.pid = pid
        self.sample_interval = sample_interval_sec
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        
        self.start_time = 0.0
        self.end_time = 0.0
        self.peak_rss_bytes = 0
        self.cpu_samples = []
        self.cuda_peak_vram_bytes = 0

    def start(self):
        self.start_time = time.time()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self) -> RuntimeMetrics:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2.0)
        self.end_time = time.time()
        
        wall_time = max(0.001, self.end_time - self.start_time)
        avg_cpu = sum(self.cpu_samples) / max(1, len(self.cpu_samples))
        peak_rss_mb = round(self.peak_rss_bytes / (1024 * 1024), 2)
        peak_vram_mb = round(self.cuda_peak_vram_bytes / (1024 * 1024), 2)

        return RuntimeMetrics(
            wall_time_sec=round(wall_time, 2),
            cpu_percent_avg=round(avg_cpu, 1),
            peak_rss_mb=peak_rss_mb,
            cuda_available=TORCH_CUDA_AVAILABLE,
            cuda_peak_vram_mb=peak_vram_mb,
            cuda_device_name=CUDA_DEVICE_NAME
        )

    def _monitor_loop(self):
        try:
            parent = psutil.Process(self.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return

        while not self._stop_event.is_set():
            try:
                # 采样主进程及所有派生子进程 (例如编译工具链、容器驱动子进程)
                all_procs = [parent] + parent.children(recursive=True)
                total_rss = 0
                total_cpu = 0.0
                
                for p in all_procs:
                    try:
                        mem = p.memory_info().rss
                        total_rss += mem
                        total_cpu += p.cpu_percent(interval=None)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                if total_rss > self.peak_rss_bytes:
                    self.peak_rss_bytes = total_rss
                self.cpu_samples.append(total_cpu)

                # CUDA 显存采样 (若启用 GPU)
                if TORCH_CUDA_AVAILABLE:
                    try:
                        curr_vram = torch.cuda.max_memory_allocated()
                        if curr_vram > self.cuda_peak_vram_bytes:
                            self.cuda_peak_vram_bytes = curr_vram
                    except Exception:
                        pass

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            except Exception:
                pass
            
            time.sleep(self.sample_interval)
