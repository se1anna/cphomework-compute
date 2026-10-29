"""
RFC Audit Agent - 异常体系定义
"""


class AuditAgentException(Exception):
    """审计系统基础异常"""
    pass


class SecurityRiskException(AuditAgentException):
    """命中安全风控异常 (直接赋0分并生成风控报告)"""
    def __init__(self, reason: str, details: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.details = details


class DependencyRiskException(SecurityRiskException):
    """依赖安装后审计发现高置信恶意行为。"""
    pass


class PreflightException(AuditAgentException):
    """预检与元数据拉取异常"""
    pass


class SandboxExecutionException(AuditAgentException):
    """沙箱编译或执行异常"""
    pass


class ControlPlaneException(AuditAgentException):
    """控制层通信网络或协议异常"""
    pass


class LLMUnavailableException(AuditAgentException):
    """生产评测所需的 LLM 不可用；不得降级为评分。"""
    pass
