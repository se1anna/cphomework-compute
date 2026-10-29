"""
RFC Audit Agent - 终态闭环兜底报告生成器 (Zero-Zombie SLA)
保证无论发生风控拦截、超时还是任何未捕获致命异常，均能组装合法 RFC 报告闭环回传。
"""

from datetime import datetime
import re
from .models import TaskPayload, RFCReportPayload


def build_security_rejection_report(
    task: TaskPayload,
    reason: str,
    violations: list[str] = None
) -> RFCReportPayload:
    """仅为有具体证据的安全违规生成拒止报告 (0分)。"""
    violations = violations or [reason]
    def clean(value: str, limit: int = 800) -> str:
        return " ".join(str(value).replace("\x00", "").split())[:limit]

    v_lines = "\n".join([f"- {clean(v)}" for v in violations[:12]])
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    memo = f"""### 作业评测报告：安全检查未通过
- **文档编号**: `RFC-SEC-{task.taskId[-8:]}`
- **目标学号**: `{task.studentId}` | **作业**: `{task.assignmentId}` ({task.get_effective_title()})
- **提交轮次**: `{task.currentRoundLabel}`
- **审计裁决**: `REJECTED (0.0 / 100.0)`
- **生成时间**: `{timestamp}`

---

#### 1. 安全检查结果
静态安全检查发现以下具体风险证据，因此本次没有执行提交代码：

{v_lines}

---

#### 2. 需要核对的具体位置/行为
{clean(reason)}

#### 3. 后续处理建议
请先核对上面列出的文件及行为。若这是作业所需的正常操作，请说明用途并联系课程负责人复核；若确为不需要的危险行为，请移除或改为安全实现后重新提交。普通文件读写或库导入本身不构成安全违规。

**最终评定成绩**: **0.0 / 100.0**
"""
    return RFCReportPayload(
        taskId=task.taskId,
        studentId=task.studentId,
        assignmentId=task.assignmentId,
        score=0.0,
        details=memo.strip()
    )


def _report_lines(items: list[str], fallback: str, limit: int = 10) -> str:
    clean_items = [" ".join(str(item).replace("\x00", "").split())[:600]
                   for item in items if str(item).strip()]
    return "\n".join(f"- {item}" for item in clean_items[:limit]) or f"- {fallback}"


def build_assignment_mismatch_report(
    task: TaskPayload,
    evidence: str,
    repository_files: list[str] = None,
    completed_items: list[str] = None,
    missing_items: list[str] = None,
    defects: list[str] = None,
) -> RFCReportPayload:
    """作业内容不匹配拒止；明确不是安全违规。"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    files = _report_lines(repository_files or [], "未发现可列出的提交文件", limit=20)
    completed = _report_lines(completed_items or [], "未确认有作业核心要求完成")
    missing = _report_lines(missing_items or [], "请对照题目说明补充核心实现")
    defect_lines = _report_lines(defects or [], "未提供其他明确缺陷")
    evidence = " ".join(str(evidence or "未找到与题目核心目标相符的实现证据").split())[:1600]
    requirements = " ".join(task.get_effective_details().split())[:1800] or "未提供详细题目说明"
    memo = f"""### 作业评测报告：提交内容与题目不匹配
- **文档编号**: `RFC-MISMATCH-{task.taskId[-8:]}`
- **目标学号**: `{task.studentId}` | **作业**: `{task.assignmentId}` ({task.get_effective_title()})
- **评测轮次**: `{task.currentRoundLabel}`
- **本次状态**: `未进入代码执行与评分`
- **生成时间**: `{timestamp}`

#### 1. 判定依据
本次拒止原因是**目前检出的提交内容没有体现题目要求的核心实现**，不是安全违规判定。题目要求摘要：{requirements}

#### 2. 仓库与实现证据
评测到的文件：
{files}

相关性审查结论：{evidence}

#### 3. 已识别的完成项与缺失项
已确认：
{completed}

尚缺/不匹配：
{missing}

其他明确问题：
{defect_lines}

#### 4. 建议
请确认评测系统绑定的是正确仓库、分支和作业子目录，并把本次作业要求的实现提交到该位置。若代码已存在，请确认推送的 commit 与绑定路径一致后再发起评测。

**结果说明**：本次因内容不匹配而未执行代码；回传的 0 分表示本轮未通过，不代表系统发现了安全攻击。
"""
    return RFCReportPayload(taskId=task.taskId, studentId=task.studentId,
                            assignmentId=task.assignmentId, score=0.0,
                            details=memo.strip())


def build_safety_block_report(task: TaskPayload, reasons: list[str], category: str = "SAFETY_PRECHECK") -> RFCReportPayload:
    """安全边界/资源限制拦截；与确认的恶意行为区分。"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    reason_lines = _report_lines(reasons, "未提供具体阻断原因")
    memo = f"""### 作业评测报告：安全预检阻断
- **文档编号**: `RFC-PREFLIGHT-{task.taskId[-8:]}`
- **目标学号**: `{task.studentId}` | **作业**: `{task.assignmentId}` ({task.get_effective_title()})
- **评测轮次**: `{task.currentRoundLabel}`
- **状态类别**: `{category}`
- **生成时间**: `{timestamp}`

安全预检因以下边界条件未通过，本次没有执行提交代码：
{reason_lines}

这表示触发了计算环境保护限制，**不等于确认存在恶意行为**。请根据上述具体路径/限制调整提交范围，或联系课程负责人复核后再提交。
"""
    return RFCReportPayload(taskId=task.taskId, studentId=task.studentId,
                            assignmentId=task.assignmentId, score=0.0,
                            details=memo.strip())


def build_source_unavailable_report(task: TaskPayload, reason: str) -> RFCReportPayload:
    """仓库访问/克隆失败时报告不可评测，而不是错误标注安全违规。"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_reason = " ".join(str(reason).replace("\x00", "").split())[:2400]
    safe_reason = re.sub(r"(https?://)[^/@\s]+@", r"\1[redacted]@", safe_reason, flags=re.I)
    safe_reason = re.sub(r"(?i)\b(token|password|deploykey|authorization)\s*[:=]\s*\S+", r"\1=[redacted]", safe_reason)
    memo = f"""### 作业评测报告：暂时无法读取提交
- **文档编号**: `RFC-SOURCE-{task.taskId[-8:]}`
- **目标学号**: `{task.studentId}` | **作业**: `{task.assignmentId}` ({task.get_effective_title()})
- **评测轮次**: `{task.currentRoundLabel}`
- **生成时间**: `{timestamp}`

计算层未能读取本轮仓库内容，因此没有检查或执行学生代码，**本次不是安全违规判定，也不能据此判断作业内容不匹配**。

读取失败信息：
> {safe_reason}

请核对仓库地址、目标分支/子目录及访问授权后再提交评测。本轮记录的 0 分表示无法完成评测，不代表代码质量或安全结论。
"""
    return RFCReportPayload(taskId=task.taskId, studentId=task.studentId,
                            assignmentId=task.assignmentId, score=0.0,
                            details=memo.strip())


def build_assessment_inconclusive_report(task: TaskPayload, evidence: str, files: list[str] = None) -> RFCReportPayload:
    """仓库可读但证据不足以作内容或安全结论时，不冒称违规/不匹配。"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_lines = _report_lines(files or [], "无可列出的文件")
    safe_evidence = " ".join(str(evidence or "评测证据不足").replace("\x00", "").split())[:1600]
    memo = f"""### 作业评测报告：证据不足，暂无法判定
- **文档编号**: `RFC-REVIEW-{task.taskId[-8:]}`
- **目标学号**: `{task.studentId}` | **作业**: `{task.assignmentId}` ({task.get_effective_title()})
- **评测轮次**: `{task.currentRoundLabel}`
- **生成时间**: `{timestamp}`

本轮未能获得足够证据判断作业内容是否符合要求或完成安全审查，因此没有执行代码并暂不作出“不符合要求”或“安全违规”结论。

已检查的文件：
{file_lines}

评测信息：{safe_evidence}

请确认提交路径正确且核心实现文件已纳入仓库；评测服务恢复后可重新提交。本轮 0 分仅用于标记未完成评测，不代表学生表现。
"""
    return RFCReportPayload(taskId=task.taskId, studentId=task.studentId,
                            assignmentId=task.assignmentId, score=0.0,
                            details=memo.strip())


def build_emergency_fallback_report(
    task: TaskPayload,
    error_msg: str
) -> RFCReportPayload:
    """生成系统异常应急闭环诊断报告 (0分，释放排队锁)"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    memo = f"""### 作业评测报告：执行异常
- **文档编号**: `RFC-ERR-{task.taskId[-8:]}`
- **目标学号**: `{task.studentId}` | **作业**: `{task.assignmentId}` ({task.get_effective_title()})
- **提交轮次**: `{task.currentRoundLabel}`
- **审计状态**: `SYSTEM_DIAGNOSTIC_HALT (0.0 / 100.0)`
- **诊断时间**: `{timestamp}`

---

#### 1. 执行故障摘要
沙箱评测执行器在处理您的提交代码时遭遇异常中断，系统已启动自动容错兜底机制确保状态闭环：

```text
{error_msg[:2048]}
```

---

#### 2. 排查与建议
1. 请检查您的代码仓库是否包含未初始化的子模块、无法访问的私有依赖或编译入口异常；
2. 若为 Python 代码，请在本次作业对应目录提供依赖清单（如 `hw3/requirements.txt`），并确认清单中的库可在 Linux x86_64 环境安装；
3. 本次提交未获得有效分数，排队互斥锁已正常释放，请检查后重新提交代码版本。

**最终评定成绩**: **0.0 / 100.0**
"""
    return RFCReportPayload(
        taskId=task.taskId,
        studentId=task.studentId,
        assignmentId=task.assignmentId,
        score=0.0,
        details=memo.strip()
    )


def build_llm_unavailable_report(task: TaskPayload, error_msg: str) -> RFCReportPayload:
    """LLM 中途不可用：闭环回传 0 分诊断，但明确这是计算层故障而非学生成绩。"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    memo = f"""### 作业评测报告：计算服务暂不可用
- **任务**: `{task.taskId}` | **作业**: `{task.assignmentId}` ({task.get_effective_title()})
- **状态**: `COMPUTE_LAYER_UNAVAILABLE`
- **暂记分数**: **0.0 / 100.0**（非学生成绩）
- **时间**: `{timestamp}`

LLM 评测服务在本次任务处理中不可用，系统未能完成安全审计、题目判断或 RFC 评分，
因此没有生成有效成绩。请稍后自动重试；这次 0 分仅用于释放任务闭环，不代表学生表现。

```text
{error_msg[:2048]}
```
"""
    return RFCReportPayload(taskId=task.taskId, studentId=task.studentId,
                            assignmentId=task.assignmentId, score=0.0,
                            details=memo.strip())
