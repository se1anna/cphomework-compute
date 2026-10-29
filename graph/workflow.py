"""
RFC Audit Agent - LangGraph 状态图构建与条件路由
"""

from langgraph.graph import StateGraph, END
from graph.state import AuditState
from graph.nodes import (
    preflight_node,
    static_audit_node,
    dynamic_exec_node,
    rfc_evaluator_node,
    score_arbiter_node
)


def route_after_preflight(state: AuditState) -> str:
    """预检后路由：若预检未通过，直接跳转至 RFC 裁决生成拒止报告，跳过静态和动态"""
    preflight = state.get("preflight")
    if not preflight or not preflight.passed:
        return "rfc_evaluator"
    return "static_audit"


def route_after_static(state: AuditState) -> str:
    """静态审计后路由：若检出安全注入或严重违规，直接熔断跳转至 RFC 裁决，跳过动态运行"""
    static_res = state.get("static_analysis")
    if not static_res or not static_res.passed:
        return "rfc_evaluator"
    return "dynamic_exec"


def route_after_arbiter(state: AuditState) -> str:
    """仲裁后路由：若仲裁判定评分不合理且重试未超限，循环回退至 rfc_evaluator 重评；否则结束"""
    if state.get("needs_reevaluation") and state.get("arbitration_retries", 0) <= 2:
        return "rfc_evaluator"
    return END


def build_audit_graph():
    """装配 LangGraph 状态图并编译"""
    builder = StateGraph(AuditState)

    # 添加各阶段节点
    builder.add_node("preflight", preflight_node)
    builder.add_node("static_audit", static_audit_node)
    builder.add_node("dynamic_exec", dynamic_exec_node)
    builder.add_node("rfc_evaluator", rfc_evaluator_node)
    builder.add_node("score_arbiter", score_arbiter_node)

    # 设置起点与条件边
    builder.set_entry_point("preflight")

    builder.add_conditional_edges(
        "preflight",
        route_after_preflight,
        {
            "static_audit": "static_audit",
            "rfc_evaluator": "rfc_evaluator"
        }
    )

    builder.add_conditional_edges(
        "static_audit",
        route_after_static,
        {
            "dynamic_exec": "dynamic_exec",
            "rfc_evaluator": "rfc_evaluator"
        }
    )

    builder.add_edge("dynamic_exec", "rfc_evaluator")
    builder.add_edge("rfc_evaluator", "score_arbiter")

    builder.add_conditional_edges(
        "score_arbiter",
        route_after_arbiter,
        {
            "rfc_evaluator": "rfc_evaluator",
            END: END
        }
    )

    return builder.compile()

