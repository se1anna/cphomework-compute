"""
RFC Audit Agent - 衔尾蛇 (Ouroboros) 持续生命周期守护主入口
保证控制层与计算层完全解耦，提供 15秒/10秒精准时钟与铁律级任务闭环 (Zero-Zombie SLA)。
"""

import sys
import time
import signal
import shutil
from pathlib import Path
from typing import Optional

from config import (
    CONTROL_PLANE_URL,
    COMPUTE_AUTH_TOKEN,
    WORKER_ID,
    POLL_INTERVAL_EMPTY,
    COOLDOWN_AFTER_TASK,
    WORKSPACE_DIR
)
from core.models import TaskPayload, RFCReportPayload
from core.fallback import (
    build_security_rejection_report,
    build_emergency_fallback_report,
    build_source_unavailable_report,
)
from core.exceptions import SecurityRiskException
from core.exceptions import LLMUnavailableException
from core.fallback import build_llm_unavailable_report
from security.cloner import prepare_student_workspace
from graph.direct_pipeline import run_direct_audit
from client.control_plane import ControlPlaneClient
from core.audit_log import write_event


# 优雅停机信号处理
running = True

def handle_shutdown_signal(sig, frame):
    global running
    print("\n[Ouroboros] 接收到退出信号，正在平稳退出守护进程...")
    running = False

signal.signal(signal.SIGINT, handle_shutdown_signal)
signal.signal(signal.SIGTERM, handle_shutdown_signal)


def run_ouroboros_daemon():
    """衔尾蛇持续自主循环守护进程"""
    print("=================================================================")
    print("  RFC 规范审计 Agent - 衔尾蛇 (Ouroboros) 自主守护服务启动")
    print(f"  Worker 标识: {WORKER_ID}")
    print(f"  控制层端点:  {CONTROL_PLANE_URL}")
    print(f"  空队列退避:  {POLL_INTERVAL_EMPTY} 秒")
    print(f"  完结冷却期:  {COOLDOWN_AFTER_TASK} 秒")
    print("=================================================================\n")

    client = ControlPlaneClient()
    print("[Ouroboros] 正在装配直接审计流水线（不启用 LangGraph）...")
    print("[Ouroboros] 直接流水线就绪，进入持续轮询主循环。\n")

    while running:
        task: Optional[TaskPayload] = None
        try:
            if not client.llm_available():
                print("[Ouroboros] LLM 不可用，暂停拉取新任务，等待恢复...")
                time.sleep(POLL_INTERVAL_EMPTY)
                continue
            # 1. 带鉴权心跳拉取任务 (独占抢占租约)
            task = client.fetch_task()
            if task:
                write_event("task_claimed", task=task, phase="fetch")
        except Exception as e:
            print(f"[Ouroboros Exception] 拉取任务异常: {e}")
            write_event("task_fetch_error", phase="fetch", error=str(e))

        # 2. 空队列处理：休眠 15 秒
        if not task:
            curr_time = time.strftime("%H:%M:%S")
            print(f"[{curr_time}] 评测队列暂无待办作业，休眠 {POLL_INTERVAL_EMPTY} 秒...")
            
            # 细粒度可中断休眠，方便 Ctrl+C 快速响应
            slept = 0
            while running and slept < POLL_INTERVAL_EMPTY:
                time.sleep(min(2, POLL_INTERVAL_EMPTY - slept))
                slept += 2
            continue

        # 3. 成功获取任务：启动审计与铁律级闭环保证 (Zero-Zombie SLA)
        print("-----------------------------------------------------------------")
        print(f"[Task Claimed] 成功认领任务: {task.taskId}")
        print(f"  学生学号:   {task.studentId}")
        print(f"  作业编号:   {task.assignmentId} ({task.get_effective_title()})")
        print(f"  评测轮次:   {task.currentRoundLabel} (第 {task.currentRound} 次)")
        print(f"  代码仓库:   {task.repoUrl} (分支: {task.branch or 'default'}, 目录: {task.subpath or '.'})")

        report_payload: Optional[RFCReportPayload] = None
        task_workspace: Optional[Path] = None

        try:
            # Step A: 安全浅克隆与工作区准备
            print("- 正在检出学生代码仓库...")
            clone_success, target_workdir, clone_log = prepare_student_workspace(task)
            task_workspace = WORKSPACE_DIR / f"run_{task.taskId}"

            if not clone_success:
                print(f"[Preflight Block] 检出失败，直接出具拒止报告: {clone_log}")
                report_payload = build_source_unavailable_report(
                    task=task,
                    reason=clone_log
                )
            else:
                print(f"[Clone Plan] {clone_log}")
                # Step B: 运行直接顺序流水线
                print("- 启动直接审计流水线 (预检 -> 静态门禁 -> 依赖审计/沙箱 -> RFC多轮评估)...")
                initial_state = {
                    "task": task,
                    "repo_dir": str(target_workdir),
                    "nonce": "",
                    "retry_count": 0,
                    "retry_context": ""
                }
                pipeline_result = run_direct_audit(initial_state)
                report_payload = pipeline_result.get("final_report_payload")

                if not report_payload:
                    report_payload = build_emergency_fallback_report(
                        task=task,
                        error_msg="直接审计流水线完成但未产生合法 report_payload"
                    )

        except SecurityRiskException as se:
            print(f"[Risk Control Alert] 触发安全风控拦截: {se.reason}")
            report_payload = build_security_rejection_report(
                task=task,
                reason=se.reason,
                violations=[se.details or str(se)]
            )
        except LLMUnavailableException as le:
            print(f"[LLM Unavailable] {le}")
            report_payload = build_llm_unavailable_report(task, str(le))
            # 回传后主循环会在下一轮探活；期间不领取新任务。
        except Exception as ex:
            # 铁律：终极全局捕获，绝对不漏单卡死任务
            print(f"[Fatal Pipeline Error] 评测流水线未捕获异常: {str(ex)}")
            report_payload = build_emergency_fallback_report(
                task=task,
                error_msg=f"评测执行器发生系统级中断: {str(ex)}"
            )
        finally:
            # 无论成功、风控还是发生异常，必须回传控制层闭环！
            if report_payload:
                print(f"- 正在回传评测结果至控制层 (得分: {report_payload.score})...")
                submitted = client.submit_report(report_payload)
                write_event(
                    "grade_result",
                    task=task,
                    report=report_payload,
                    phase="report",
                    report_submitted=submitted,
                )
            else:
                write_event("task_without_report", task=task, phase="report", error="未生成 report_payload")
            
            # 清理临时工作区 (保留持久化 venvs 缓存)
            if task_workspace and task_workspace.exists():
                shutil.rmtree(task_workspace, ignore_errors=True)

            print(f"- 任务 {task.taskId} 评测周期结束。按规范冷却 {COOLDOWN_AFTER_TASK} 秒后继续...\n")
            time.sleep(COOLDOWN_AFTER_TASK)

    print("[Ouroboros] 服务已安全关闭。")


if __name__ == "__main__":
    run_ouroboros_daemon()
