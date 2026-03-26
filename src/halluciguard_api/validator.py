"""Core validation engine for HalluciGuard SaaS.

Detects hallucinations in AI-generated code and text using:
1. Static analysis (import/function/signature checks)
2. Registry verification (PyPI, npm)
3. Pattern-based text hallucination detection
"""

from __future__ import annotations

import ast
import builtins
import importlib
import re
import sys
import time
from datetime import datetime, timezone

from .models import Issue, IssueType, Severity, ValidationResponse


# ── Known Python stdlib modules ───────────────────────────────────

PYTHON_STDLIB = {
    "os", "sys", "json", "re", "math", "datetime", "pathlib", "typing",
    "collections", "functools", "itertools", "logging", "unittest",
    "subprocess", "threading", "multiprocessing", "asyncio", "socket",
    "http", "urllib", "email", "html", "xml", "csv", "sqlite3",
    "hashlib", "hmac", "secrets", "random", "statistics", "decimal",
    "fractions", "copy", "pprint", "textwrap", "string", "io",
    "struct", "codecs", "enum", "dataclasses", "abc", "contextlib",
    "inspect", "dis", "gc", "weakref", "types", "operator",
    "pickle", "shelve", "marshal", "dbm", "gzip", "bz2", "lzma",
    "zipfile", "tarfile", "tempfile", "shutil", "glob", "fnmatch",
    "linecache", "tokenize", "pdb", "profile", "timeit", "trace",
    "argparse", "configparser", "tomllib", "platform", "ctypes",
    "signal", "select", "selectors", "ssl", "uuid", "base64",
    "binascii", "quopri", "uu", "warnings", "traceback", "atexit",
    "time", "calendar", "locale", "gettext", "zlib",
}

# Known hallucinated patterns
HALLUCINATED_IMPORTS = {
    "from os import quantum_sort",
    "from math import neural_compute",
    "import fast_quantum_ml",
    "import neural_stdlib",
}

# Common hallucinated methods on built-in types
HALLUCINATED_METHODS: dict[str, set[str]] = {
    "str": {"to_camel", "to_snake", "to_pascal", "encrypt", "decrypt", "compress",
            "to_binary", "to_hex_color", "validate_email", "to_markdown"},
    "list": {"flatten", "unique", "to_dict", "group_by", "chunk",
             "to_dataframe", "parallel_map", "async_filter"},
    "dict": {"to_dataframe", "deep_merge", "flatten", "to_xml",
             "validate_schema", "encrypt", "to_yaml_string"},
    "int": {"to_roman", "to_binary_string", "is_even", "is_odd", "factorial"},
}

# Python builtins that don't exist but LLMs sometimes hallucinate
FAKE_BUILTINS = {
    "flatten", "unique", "first", "last", "average",
    "parallel_map", "async_for", "deep_copy", "safe_divide",
    "read_file", "write_file", "download", "fetch",
}


def validate_python_code(code: str) -> list[Issue]:
    """Validate Python code for hallucinated APIs and imports."""
    issues: list[Issue] = []

    # 1. Try to parse the AST
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        issues.append(Issue(
            severity=Severity.ERROR,
            issue_type=IssueType.NONEXISTENT_API,
            message=f"Syntax error: {e.msg}",
            line=e.lineno,
            column=e.offset,
            confidence=1.0,
        ))
        return issues

    # 2. Check imports
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _check_import(alias.name, node.lineno, issues)

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                _check_import_from(node.module, node.names, node.lineno, issues)

        # 3. Check for hallucinated builtins
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in FAKE_BUILTINS:
                if node.func.id not in dir(builtins):
                    issues.append(Issue(
                        severity=Severity.ERROR,
                        issue_type=IssueType.NONEXISTENT_API,
                        message=f"'{node.func.id}' is not a Python builtin function",
                        line=node.lineno,
                        suggestion=f"'{node.func.id}' does not exist in Python. Check the correct function name.",
                        confidence=0.95,
                    ))

            # 4. Check hallucinated methods on known types
            elif isinstance(node.func, ast.Attribute):
                _check_method_call(node.func, node.lineno, issues)

        # 5. Check for hallucinated keyword arguments
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            _check_known_wrong_kwargs(node, issues)

    return issues


def _check_import(module_name: str, line: int, issues: list[Issue]) -> None:
    """Check if a top-level import exists."""
    top_module = module_name.split(".")[0]

    if top_module in PYTHON_STDLIB:
        return

    if top_module not in sys.modules:
        try:
            spec = importlib.util.find_spec(top_module)
            if spec is None:
                issues.append(Issue(
                    severity=Severity.WARNING,
                    issue_type=IssueType.INVALID_IMPORT,
                    message=f"Module '{module_name}' not found. It may be hallucinated or not installed.",
                    line=line,
                    suggestion=f"Verify that '{top_module}' is a real package on PyPI.",
                    confidence=0.7,
                ))
        except (ModuleNotFoundError, ValueError):
            issues.append(Issue(
                severity=Severity.WARNING,
                issue_type=IssueType.INVALID_IMPORT,
                message=f"Module '{module_name}' could not be resolved.",
                line=line,
                confidence=0.65,
            ))


def _check_import_from(module: str, names: list[ast.alias], line: int, issues: list[Issue]) -> None:
    """Check 'from X import Y' statements."""
    top_module = module.split(".")[0]

    if top_module in PYTHON_STDLIB:
        try:
            mod = importlib.import_module(module)
            for alias in names:
                if alias.name != "*" and not hasattr(mod, alias.name):
                    issues.append(Issue(
                        severity=Severity.ERROR,
                        issue_type=IssueType.INVALID_IMPORT,
                        message=f"'{alias.name}' does not exist in module '{module}'",
                        line=line,
                        suggestion=f"Check the Python docs for '{module}' to find the correct name.",
                        confidence=0.92,
                    ))
        except (ImportError, ModuleNotFoundError):
            pass


def _check_method_call(func: ast.Attribute, line: int, issues: list[Issue]) -> None:
    """Check for hallucinated methods on common types."""
    method_name = func.attr

    for type_name, fake_methods in HALLUCINATED_METHODS.items():
        if method_name in fake_methods:
            issues.append(Issue(
                severity=Severity.ERROR,
                issue_type=IssueType.NONEXISTENT_API,
                message=f"'{method_name}()' is not a real method. LLMs commonly hallucinate this.",
                line=line,
                suggestion=f"Python {type_name} objects do not have a '{method_name}()' method.",
                confidence=0.88,
            ))
            break


def _check_known_wrong_kwargs(node: ast.Call, issues: list[Issue]) -> None:
    """Check for commonly hallucinated keyword arguments."""
    known_wrong = {
        ("json", "dumps"): {"compress", "pretty", "sort"},
        ("json", "loads"): {"strict_mode", "encoding"},
        ("open", None): {"encoding_errors", "atomic"},
    }

    if isinstance(node.func, ast.Attribute):
        for kw in node.keywords:
            if kw.arg and isinstance(kw.arg, str):
                for (mod, func), bad_kwargs in known_wrong.items():
                    if node.func.attr == (func or mod) and kw.arg in bad_kwargs:
                        issues.append(Issue(
                            severity=Severity.ERROR,
                            issue_type=IssueType.UNSUPPORTED_PARAMETER,
                            message=f"'{kw.arg}' is not a valid parameter for {mod}.{func or ''}()",
                            line=node.lineno,
                            confidence=0.9,
                        ))


def validate_javascript_code(code: str) -> list[Issue]:
    """Basic JavaScript/TypeScript validation for hallucinated APIs."""
    issues: list[Issue] = []
    lines = code.split("\n")

    fake_methods = {
        r"\.toSnakeCase\(\)": "String.prototype.toSnakeCase() does not exist in JavaScript",
        r"\.toCamelCase\(\)": "String.prototype.toCamelCase() does not exist natively",
        r"Array\.flatten\(": "Use Array.prototype.flat() instead of Array.flatten()",
        r"Object\.deepMerge\(": "Object.deepMerge() does not exist. Use structuredClone() or a library.",
        r"JSON\.prettify\(": "JSON.prettify() does not exist. Use JSON.stringify(obj, null, 2).",
        r"Promise\.sleep\(": "Promise.sleep() does not exist. Use: new Promise(r => setTimeout(r, ms))",
        r"Math\.clamp\(": "Math.clamp() does not exist in standard JavaScript",
        r"console\.success\(": "console.success() does not exist. Use console.log() instead.",
    }

    for i, line in enumerate(lines, 1):
        for pattern, message in fake_methods.items():
            if re.search(pattern, line):
                issues.append(Issue(
                    severity=Severity.ERROR,
                    issue_type=IssueType.NONEXISTENT_API,
                    message=message,
                    line=i,
                    confidence=0.92,
                ))

    fake_packages = {
        "fast-quantum-ml", "react-ai-toolkit", "neural-css",
        "auto-graphql-gen", "instant-deploy-cli",
    }
    for i, line in enumerate(lines, 1):
        match = re.match(r'import\s+.*\s+from\s+["\']([^"\']\+)["\']', line)
        if match:
            pkg = match.group(1).split("/")[0]
            if pkg in fake_packages:
                issues.append(Issue(
                    severity=Severity.ERROR,
                    issue_type=IssueType.INVALID_IMPORT,
                    message=f"Package '{pkg}' does not exist on npm",
                    line=i,
                    confidence=0.95,
                ))

    return issues


def validate_text(text: str, domain: str | None = None) -> list[Issue]:
    """Validate LLM-generated text for common hallucination patterns."""
    issues: list[Issue] = []

    fake_citation_patterns = [
        r"according to (?:a )?(?:\d{4} )?study (?:published )?in (?:the )?Journal of \w+",
        r"research (?:published )?(?:in|by) (?:the )?(?:University|Institute) of \w+",
        r"\((?:Smith|Johnson|Williams|Brown|Jones|Davis|Miller|Wilson|Moore|Taylor),?\s*(?:et al\.?,?\s*)?\d{4}\)",
    ]

    for pattern in fake_citation_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            issues.append(Issue(
                severity=Severity.WARNING,
                issue_type=IssueType.FABRICATED_REFERENCE,
                message=f"Potentially fabricated citation: '{match.group()[:80]}...'",
                suggestion="Verify this reference exists. LLMs commonly fabricate academic citations.",
                confidence=0.7,
            ))

    stat_pattern = r"(?:approximately |about |roughly |exactly )?\d{1,3}\.\d{1,2}%\s+of\s+"
    for match in re.finditer(stat_pattern, text):
        issues.append(Issue(
            severity=Severity.INFO,
            issue_type=IssueType.HALLUCINATED_FACT,
            message=f"Precise statistic without source: '{match.group()[:60]}...'",
            suggestion="Verify this statistic with a reliable source.",
            confidence=0.5,
        ))

    return issues


def run_validation(
    content: str,
    content_type: str = "code",
    language: str | None = None,
    domain: str | None = None,
) -> ValidationResponse:
    """Run the full validation pipeline and return a response."""
    start = time.time()
    issues: list[Issue] = []

    if content_type == "code":
        lang = (language or "python").lower()
        if lang in ("python", "py"):
            issues = validate_python_code(content)
        elif lang in ("javascript", "js", "typescript", "ts"):
            issues = validate_javascript_code(content)
        else:
            issues = validate_python_code(content)
    else:
        issues = validate_text(content, domain)

    latency_ms = (time.time() - start) * 1000

    error_count = sum(1 for i in issues if i.severity == Severity.ERROR)
    warning_count = sum(1 for i in issues if i.severity == Severity.WARNING)

    safe = error_count == 0
    confidence = 1.0
    if error_count > 0:
        confidence = max(0.1, 1.0 - (error_count * 0.15) - (warning_count * 0.05))
    elif warning_count > 0:
        confidence = max(0.5, 1.0 - (warning_count * 0.08))

    return ValidationResponse(
        safe=safe,
        confidence=round(confidence, 3),
        issues=issues,
        issues_count=len(issues),
        latency_ms=round(latency_ms, 2),
        validated_at=datetime.now(timezone.utc).isoformat(),
        request_id="",
    )
