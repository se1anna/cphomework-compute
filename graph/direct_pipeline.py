"""不依赖 LangGraph 的顺序审计流水线。

保留原有节点实现与路由语义，但在生产入口中直接调用，减少状态图
依赖、编译开销和额外调度层。
"""

from typing import Any, Dict

from graph.nodes import (
    preflight_node,
    static_audit_node,
    dynamic_exec_node,
    rfc_evaluator_node,
    score_arbiter_node,
)


def run_direct_audit(initial_state: Dict[str, Any]) -> Dict[str, Any]:
    """执行与原状态图等价的预检→静态→动态→评分→仲裁流程。"""
    state: Dict[str, Any] = dict(initial_state)
    state.setdefault("arbitration_retries", 0)
    state.setdefault("needs_reevaluation", False)

    state.update(preflight_node(state))

    preflight = state.get("preflight")
    if preflight and preflight.passed:
        state.update(static_audit_node(state))

        static_result = state.get("static_analysis")
        if static_result and static_result.passed:
            state.update(dynamic_exec_node(state))

    # 预检/静态不通过时，评测节点会生成 0 分安全报告；通过时生成正常报告。
    state.update(rfc_evaluator_node(state))

    # 保留原仲裁回路，但不再经 LangGraph 重新编译/调度。
    while True:
        arbitration = score_arbiter_node(state)
        state.update(arbitration)
        if not state.get("needs_reevaluation"):
            break
        state.update(rfc_evaluator_node(state))

    return state
