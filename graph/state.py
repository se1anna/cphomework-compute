"""
RFC Audit Agent - LangGraph 状态图模型定义
"""

from typing import TypedDict, Optional, Dict, Any
from core.models import (
    TaskPayload,
    PreflightResult,
    StaticAnalysisResult,
    DynamicRunResult,
    RFCReportPayload
)


class AuditState(TypedDict, total=False):
    """LangGraph 全局审计状态"""
    # 基础任务信息
    task: TaskPayload
    repo_dir: str
    nonce: str

    # 阶段 0：预检与代码加载
    preflight: Optional[PreflightResult]
    raw_code_files: Dict[str, str]
    isolated_code_payload: str

    # 阶段 1：静态审计与题目契约
    static_analysis: Optional[StaticAnalysisResult]

    # 阶段 2：动态沙箱运行与旁路指标
    dynamic_run: Optional[DynamicRunResult]

    # 容错与上下文重试
    retry_count: int
    retry_context: str

    # 阶段 3：RFC 评测结果与回传 Payload
    rfc_report: str
    final_score: float
    final_report_payload: Optional[RFCReportPayload]

    # 阶段 4：评分合理性仲裁与重评机制 (Score Arbiter)
    arbitration_retries: int
    arbitration_critique: str
    needs_reevaluation: bool
