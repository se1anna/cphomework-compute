"""
RFC Audit Agent - 多语言通用静态特征安全扫描器 (Polyglot Security Scanner)
支持 Python (AST 深度解析)、C/C++、Rust 静态特征扫描与全语言 Prompt 注入模式拦截。
"""

import ast
import re
from typing import Dict, List, Tuple


# 针对代码注释与字符串字面量的 Prompt 注入探测正则
PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"system\s+directive\s*:",
    r"give\s+(this\s+student|me)?\s*(a\s+)?(score\s+of\s+)?100",
    r"you\s+are\s+now\s+in\s+developer\s+mode",
    r"override\s+(all\s+)?grading\s+rubrics?",
    r"bypass\s+(all\s+)?security\s+checks?",
    r"disregard\s+(all\s+)?evaluat(ion|or)\s+rules",
    r"output\s+only\s+[:\"']?PASS",
    r"ignore\s+rfc\s+2119",
]

# Python 禁用模块与危险调用。文件/结果产出属于正常作业能力，不能因为
# `import os` 本身就拒绝；危险能力按模块和具体调用分别判断。
PY_DANGEROUS_MODULES = {
    "subprocess", "pty", "socket", "ctypes",
    "importlib", "commands", "builtin_impl", "_posixsubprocess"
}

PY_DANGEROUS_BUILTINS = {
    "eval", "exec", "__import__", "compile"
}

# C/C++ 危险系统调用与内联汇编
CPP_DANGEROUS_PATTERNS = [
    r"\bsystem\s*\(",
    r"\bexecve\s*\(",
    r"\bexecvp\s*\(",
    r"\bfork\s*\(",
    r"\bsocket\s*\(",
    r"\bconnect\s*\(",
    r"\bkill\s*\(",
    r"__asm__\s*(volatile)?",
    r"\basm\s*(volatile)?"
]

# Rust 危险调用
RUST_DANGEROUS_PATTERNS = [
    r"std::process::Command",
    r"libc::system",
    r"libc::fork",
    r"libc::exec",
    r"std::net::TcpStream",
    r"std::net::UdpSocket"
]


class PythonAstSecurityVisitor(ast.NodeVisitor):
    """Python AST 语法树安全审查访问器"""
    def __init__(self, filename: str):
        self.filename = filename
        self.violations: List[str] = []
        self.warnings: List[str] = []

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            base_mod = alias.name.split(".")[0]
            if base_mod in PY_DANGEROUS_MODULES:
                self.violations.append(f"{self.filename}:{node.lineno} 引入受限危险系统模块: `{alias.name}`")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            base_mod = node.module.split(".")[0]
            if base_mod in PY_DANGEROUS_MODULES:
                self.violations.append(f"{self.filename}:{node.lineno} 从受限模块导入: `from {node.module} import ...`")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # 检查是否直接调用危险内建函数
        if isinstance(node.func, ast.Name):
            if node.func.id in PY_DANGEROUS_BUILTINS:
                self.violations.append(f"{self.filename}:{node.lineno} 调用禁止的动态执行函数: `{node.func.id}()`")
        # 检查属性调用如 os.system
        elif isinstance(node.func, ast.Attribute):
            attr_name = node.func.attr
            if attr_name in {"system", "popen", "spawn", "fork", "kill"}:
                self.violations.append(f"{self.filename}:{node.lineno} 疑似系统级命令调用: `.{attr_name}()`")
        self.generic_visit(node)


def scan_file_content_for_prompt_injection(filename: str, content: str) -> List[str]:
    """扫描文件内容中的对抗性 Prompt 注入特征"""
    violations = []
    lines = content.splitlines()
    for idx, line in enumerate(lines, 1):
        for pat in PROMPT_INJECTION_PATTERNS:
            if re.search(pat, line, re.IGNORECASE):
                violations.append(
                    f"{filename}:{idx} 检出对抗性 Prompt 提示词注入特征 (匹配规则: `{pat}`)"
                )
                break
    return violations


def scan_code_files(
    code_files: Dict[str, str],
    primary_language: str = "python"
) -> Tuple[bool, List[str], List[str]]:
    """
    对提取到的代码文件进行全量静态多语言安全扫描
    返回: (security_clean: bool, violations: list[str], warnings: list[str])
    """
    violations: List[str] = []
    warnings: List[str] = []

    for fname, content in code_files.items():
        # 1. 通用 Prompt 注入扫描
        inj_hits = scan_file_content_for_prompt_injection(fname, content)
        violations.extend(inj_hits)

        # 2. 语言专项扫描
        if fname.endswith(".py"):
            try:
                tree = ast.parse(content, filename=fname)
                visitor = PythonAstSecurityVisitor(fname)
                visitor.visit(tree)
                violations.extend(visitor.violations)
                warnings.extend(visitor.warnings)
            except SyntaxError as se:
                warnings.append(f"{fname}:{se.lineno} Python 静态语法错误 (将在沙箱编译阶段复核): {se.msg}")
            except Exception as e:
                warnings.append(f"{fname} AST 解析异常: {str(e)}")

        elif fname.endswith((".c", ".cpp", ".cc", ".cxx", ".h", ".hpp")):
            for pat in CPP_DANGEROUS_PATTERNS:
                matches = re.finditer(pat, content)
                for m in matches:
                    violations.append(f"{fname} 检出 C/C++ 受限系统或汇编调用: `{m.group(0)}`")

        elif fname.endswith(".rs"):
            for pat in RUST_DANGEROUS_PATTERNS:
                matches = re.finditer(pat, content)
                for m in matches:
                    violations.append(f"{fname} 检出 Rust 受限系统或网络指令: `{m.group(0)}`")

    security_clean = len(violations) == 0
    return security_clean, violations, warnings
