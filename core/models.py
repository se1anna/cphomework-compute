"""
RFC Audit Agent - Pydantic 数据模型定义
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, model_validator


class EvaluationRound(BaseModel):
    """历史评测单轮记录"""
    round: int
    roundLabel: str
    taskId: Optional[str] = None
    score: Optional[float] = None
    details: str
    repoUrl: Optional[str] = None
    branch: Optional[str] = None
    subpath: Optional[str] = None
    submittedAt: Optional[str] = None
    gradedAt: Optional[str] = None


class TaskPayload(BaseModel):
    """控制层派发的任务 Payload"""
    taskId: str
    studentId: str
    assignmentId: str
    assignmentTitle: Optional[str] = ""
    assignmentOverview: Optional[str] = ""
    assignmentDetails: Optional[str] = ""
    title: Optional[str] = None
    overview: Optional[str] = None
    details: Optional[str] = None
    currentRound: int = 1
    currentRoundLabel: str = "第一次评测"
    history: List[Dict[str, Any]] = Field(default_factory=list)
    historyPrompt: Optional[str] = ""
    repoUrl: str
    branch: Optional[str] = None
    subpath: Optional[str] = None
    submittedAt: Optional[str] = None
    # Per-task deploy key.  It is deliberately excluded from repr/log-style output.
    deployKey: Optional[str] = Field(default="", repr=False, exclude=True)

    @model_validator(mode="before")
    @classmethod
    def _normalize_null_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if data.get("assignmentTitle") is None:
                data["assignmentTitle"] = ""
            if data.get("assignmentOverview") is None:
                data["assignmentOverview"] = ""
            if data.get("assignmentDetails") is None:
                data["assignmentDetails"] = ""
            if data.get("history") is None:
                data["history"] = []
            if data.get("historyPrompt") is None:
                data["historyPrompt"] = ""
            if data.get("currentRound") is None:
                data["currentRound"] = 1
            if data.get("currentRoundLabel") is None:
                data["currentRoundLabel"] = "第一次评测"
        return data

    def get_effective_details(self) -> str:
        return self.assignmentDetails or self.details or self.assignmentOverview or ""

    def get_effective_title(self) -> str:
        return self.assignmentTitle or self.title or self.assignmentId


class PreflightResult(BaseModel):
    """阶段 0：远端预检与文件过滤结果"""
    passed: bool
    total_files: int = 0
    code_files: List[str] = Field(default_factory=list)
    filtered_assets: List[str] = Field(default_factory=list)
    repo_size_bytes: int = 0
    risk_reasons: List[str] = Field(default_factory=list)
    security_risks: List[str] = Field(default_factory=list)
    submission_issues: List[str] = Field(default_factory=list)
    primary_language: str = "python"


class RuntimeMetrics(BaseModel):
    """沙箱旁路资源监控指标"""
    wall_time_sec: float = 0.0
    cpu_percent_avg: float = 0.0
    peak_rss_mb: float = 0.0
    cuda_available: bool = False
    cuda_peak_vram_mb: float = 0.0
    cuda_device_name: str = "N/A"


class StaticAnalysisResult(BaseModel):
    """阶段 1：静态安全审计与题目契约校验结果"""
    passed: bool
    security_clean: bool
    topic_matched: bool
    primary_language: str = "python"
    scanned_files: List[str] = Field(default_factory=list)
    violations: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    topic_evidence: str = ""
    topic_decision: str = "UNKNOWN"
    completed_items: List[str] = Field(default_factory=list)
    missing_items: List[str] = Field(default_factory=list)
    topic_defects: List[str] = Field(default_factory=list)
    security_decision: str = "UNKNOWN"
    security_evidence: str = ""
    security_findings: List[str] = Field(default_factory=list)
    block_category: str = ""


class DynamicRunResult(BaseModel):
    """阶段 2：动态沙箱运行与用例断言结果"""
    executed: bool = False
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    tests_total: int = 0
    tests_passed: int = 0
    error_summary: Optional[str] = None
    agent_command: str = ""
    agent_reason: str = ""
    entry_file: str = ""
    agent_trace: List[str] = Field(default_factory=list)
    metrics: RuntimeMetrics = Field(default_factory=RuntimeMetrics)


class RFCReportPayload(BaseModel):
    """回传至控制层的批改结果契约"""
    taskId: str
    studentId: str
    assignmentId: str
    score: float
    details: str

    @model_validator(mode="before")
    @classmethod
    def _validate_score_and_details(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # 1. 约束 score 在 0.0 ~ 100.0 之间，防非法 NaN 或超界
            raw_score = data.get("score")
            try:
                score_num = float(raw_score)
                if score_num != score_num:  # check NaN
                    score_num = 0.0
                score_num = max(0.0, min(100.0, round(score_num, 1)))
            except (TypeError, ValueError):
                score_num = 0.0
            data["score"] = score_num

            # 2. 净化 details：去除空字符 \x00 与截断至 32000 字符 (适配控制层 32KB 上限)
            raw_details = data.get("details", "")
            if not isinstance(raw_details, str):
                raw_details = str(raw_details) if raw_details is not None else ""
            clean_details = raw_details.replace("\x00", "").strip()
            if len(clean_details) > 32000:
                clean_details = clean_details[:32000] + "\n\n...[报告内容过长，已被自动截断]..."
            data["details"] = clean_details
        return data
