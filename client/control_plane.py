"""
RFC Audit Agent - 控制层解耦心跳客户端
与控制层保持无状态、解耦通信契约，支持断网指数退避与幂等回传。
"""

import time
import requests
from core.llm_response_cache import cache_llm_response
from typing import Optional
from config import (
    CONTROL_PLANE_URL,
    COMPUTE_AUTH_TOKEN,
    WORKER_ID,
    POLL_TIMEOUT_SEC
)
from core.models import TaskPayload, RFCReportPayload
from core.exceptions import ControlPlaneException
from config import OPENAI_API_BASE, OPENAI_API_KEY, OPENAI_MODEL


class ControlPlaneClient:
    """与服务端控制层进行任务拉取与成绩回传的通信客户端"""

    def __init__(
        self,
        base_url: str = CONTROL_PLANE_URL,
        token: str = COMPUTE_AUTH_TOKEN,
        worker_id: str = WORKER_ID
    ):
        clean_url = base_url.rstrip("/")
        if clean_url.endswith("/api"):
            clean_url = clean_url[:-4]
        self.base_url = clean_url
        self.token = token
        self.worker_id = worker_id
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "X-Compute-Token": self.token,
            "X-Worker-Id": self.worker_id,
            "Content-Type": "application/json"
        }
        self._llm_health_cache = None
        self._llm_health_checked_at = 0.0

    def llm_available(self, cache_sec: int = 30) -> bool:
        """轻量探活；生产轮询前调用，失败时不领取新任务。"""
        now = time.monotonic()
        if self._llm_health_cache is not None and now - self._llm_health_checked_at < cache_sec:
            return self._llm_health_cache
        if not OPENAI_API_BASE or not OPENAI_API_KEY:
            self._llm_health_cache = False
            self._llm_health_checked_at = now
            return False
        try:
            response = requests.post(
                OPENAI_API_BASE.rstrip("/") + "/chat/completions",
                headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"},
                json={"model": OPENAI_MODEL, "messages": [{"role": "user", "content": "Reply with exactly OK."}], "max_tokens": 128, "temperature": 1.0},
                timeout=min(POLL_TIMEOUT_SEC, 15),
            )
            cache_llm_response(response, "llm_health_probe")
            if response.ok:
                data = response.json()
                content = ((data.get("choices") or [{}])[0].get("message") or {}).get("content")
                self._llm_health_cache = isinstance(content, str) and bool(content.strip())
            else:
                self._llm_health_cache = False
        except requests.RequestException:
            self._llm_health_cache = False
        self._llm_health_checked_at = now
        return self._llm_health_cache

    def fetch_task(self) -> Optional[TaskPayload]:
        """从控制层安全拉取待评测任务 (带租约独占抢占)"""
        url = f"{self.base_url}/api/compute/task"
        try:
            res = requests.get(url, headers=self.headers, timeout=POLL_TIMEOUT_SEC)
            if res.status_code == 401:
                raise ControlPlaneException("计算层鉴权失败：COMPUTE_AUTH_TOKEN 与控制层不匹配")

            if not res.ok:
                print(f"[ControlPlane Warn] 拉取任务接口返回 HTTP {res.status_code}，稍后重试...")
                return None

            data = res.json()
            if not data.get("hasTask") or not data.get("task"):
                return None

            raw_task = data["task"]
            try:
                return TaskPayload(**raw_task)
            except Exception as pe:
                print(f"[ControlPlane Error] 解析任务契约数据失败: {pe}")
                return None

        except requests.RequestException as e:
            print(f"[ControlPlane Network] 连接控制层异常: {str(e)}")
            return None

    def submit_report(self, report: RFCReportPayload, max_retries: int = 3) -> bool:
        """将最终 RFC 审计报告与分数回传控制层 (带幂等重试与指数退避)"""
        url = f"{self.base_url}/api/compute/report"
        payload = report.model_dump()

        for attempt in range(1, max_retries + 1):
            try:
                res = requests.post(url, headers=self.headers, json=payload, timeout=POLL_TIMEOUT_SEC)
                if res.status_code == 200:
                    resp_json = res.json()
                    # Some control-plane deployments return HTTP 200 with
                    # {"success": false} for a state/lease rejection.  Do
                    # not acknowledge that as a completed grade.
                    if resp_json.get("success") is False:
                        error_text = resp_json.get("error") or resp_json.get("message") or "控制层返回 success=false"
                        print(f"[ControlPlane Warn] 成绩回传被控制层拒绝: {error_text} (尝试 {attempt}/{max_retries})")
                        if attempt < max_retries:
                            time.sleep(attempt * 2)
                        continue
                    is_idempotent = resp_json.get("idempotent", False)
                    if is_idempotent:
                        print(f"[ControlPlane Success] 成绩回传成功 (网络重试幂等放行): {report.taskId}")
                    else:
                        print(f"[ControlPlane Success] 成绩回传成功: {report.taskId}, 分数: {report.score}")
                    return True

                elif res.status_code == 409:
                    print(f"[ControlPlane Notice] 任务已被覆盖或已完结 (409 Conflict): {report.taskId}")
                    return True  # 状态已在服务端收敛，无需继续重试

                else:
                    print(f"[ControlPlane Warn] 回传接口返回异常 HTTP {res.status_code} (尝试 {attempt}/{max_retries}): {res.text}")

            except requests.RequestException as e:
                print(f"[ControlPlane Network] 回传网络超时或异常 (尝试 {attempt}/{max_retries}): {str(e)}")

            if attempt < max_retries:
                time.sleep(attempt * 2)  # 指数退避

        print(f"[ControlPlane Error] 任务 {report.taskId} 最终写回失败！")
        return False
