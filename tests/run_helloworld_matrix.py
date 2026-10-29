"""Manual integration matrix for the semantic gate and RFC evaluator."""
import json
import shutil
import tempfile
from pathlib import Path

from core.models import TaskPayload
from graph.workflow import build_audit_graph


CASES = [
    ("01_unrunnable", "print('Hello, World!'", "syntax error"),
    ("02_malicious", "import os\nos.system('echo malicious')\nprint('Hello, World!')", "malicious payload"),
    ("03_unrelated", "print(2 + 2)\nprint('calculator')", "unrelated program"),
    ("04_normal", "print('Hello, World!')", "normal hello world"),
    ("05_ascii_loop", """codes = [72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33]
for code in codes:
    print(chr(code), end='')
print()
""", "ASCII loop hello world"),
]


def main():
    root = Path(tempfile.mkdtemp(prefix="helloworld-matrix-"))
    graph = build_audit_graph()
    results = []
    try:
        for index, (name, code, label) in enumerate(CASES, 1):
            repo = root / name
            repo.mkdir()
            (repo / "solution.py").write_text(code, encoding="utf-8")
            task = TaskPayload(
                taskId=f"helloworld-{index}", studentId="matrix-test",
                assignmentId="hello-world", assignmentTitle="写一个 Hello World 程序",
                assignmentOverview="程序运行后必须向标准输出输出 Hello, World!",
                assignmentDetails="只要求完成 Hello World 行为；允许使用任意等价实现方式。",
                repoUrl="https://example.invalid/helloworld", currentRound=1,
                currentRoundLabel="矩阵测试"
            )
            result = graph.invoke({
                "task": task, "repo_dir": str(repo), "nonce": "",
                "retry_count": 0, "retry_context": ""
            })
            static = result.get("static_analysis")
            dynamic = result.get("dynamic_run")
            results.append({
                "case": name, "label": label,
                "topic_decision": static.topic_decision if static else None,
                "topic_evidence": static.topic_evidence if static else None,
                "completed_items": static.completed_items if static else [],
                "missing_items": static.missing_items if static else [],
                "topic_defects": static.topic_defects if static else [],
                "dynamic_executed": dynamic.executed if dynamic else False,
                "dynamic_exit_code": dynamic.exit_code if dynamic else None,
                "stdout": (dynamic.stdout[-500:] if dynamic else ""),
                "score": result.get("final_score"),
                "report_tail": (result.get("rfc_report") or "")[-1200:],
            })
        print(json.dumps(results, ensure_ascii=False, indent=2))
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
