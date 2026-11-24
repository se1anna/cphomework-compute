"""Corroborate runtime missing-module claims without trusting program output alone."""

import ast
import re


def corroborates_missing_import(stderr: str, sources: dict[str, str]) -> bool:
    """Require a reported missing module and an absolute import in audited source."""
    lines = stderr.rstrip().splitlines()
    if not lines:
        return False
    error = re.fullmatch(r"ModuleNotFoundError: No module named ['\"]([\w.]+)['\"]", lines[-1])
    if not error:
        return False
    missing = error[1]
    for path, source in sources.items():
        if not path.lower().endswith(".py"):
            continue
        try:
            tree = ast.parse(source, filename=path)
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
                modules = [node.module]
            else:
                continue
            if any(module == missing or module.startswith(missing + ".") for module in modules):
                return True
    return False
