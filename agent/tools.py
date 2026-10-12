"""Explicit, constrained tools available to the AgentGuard agent."""

from __future__ import annotations

import ast
import operator
import os
import re
from pathlib import Path
from typing import Any

DOCUMENT_DIR = Path(__file__).resolve().parent.parent / "data" / "document"
MAX_FILE_BYTES = 1_000_000
MAX_SEARCH_RESULTS = 50
MAX_EXPRESSION_LENGTH = 256
MAX_EXPONENT = 100
MAX_ABS_VALUE = 1e100

_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}


class ToolError(ValueError):
    """Safe, user-facing tool validation or execution failure."""


def calculator(expression: str) -> dict[str, Any]:
    if not isinstance(expression, str) or not expression.strip():
        raise ToolError("expression must be a non-empty string")
    if len(expression) > MAX_EXPRESSION_LENGTH:
        raise ToolError("expression is too long")
    try:
        tree = ast.parse(expression, mode="eval")
        result = _calculate(tree.body)
    except (SyntaxError, ValueError, TypeError, OverflowError, ZeroDivisionError) as exc:
        if isinstance(exc, ToolError):
            raise
        raise ToolError(f"invalid arithmetic expression: {exc}") from exc
    if not isinstance(result, (int, float)) or isinstance(result, bool):
        raise ToolError("expression did not produce a number")
    if abs(result) > MAX_ABS_VALUE:
        raise ToolError("result exceeds the allowed numeric range")
    if isinstance(result, float) and not __import__("math").isfinite(result):
        raise ToolError("result must be finite")
    return {"result": result}


def _calculate(node: ast.AST) -> int | float:
    if isinstance(node, ast.Constant) and type(node.value) in (int, float):
        if abs(node.value) > MAX_ABS_VALUE:
            raise ToolError("number exceeds the allowed numeric range")
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        left = _calculate(node.left)
        right = _calculate(node.right)
        if isinstance(node.op, ast.Pow) and (abs(right) > MAX_EXPONENT or abs(left) > MAX_ABS_VALUE):
            raise ToolError("exponent is outside the allowed range")
        return _OPS[type(node.op)](left, right)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_calculate(node.operand))
    raise ToolError("unsupported expression; only basic arithmetic is allowed")


def _document_root() -> Path:
    return Path(DOCUMENT_DIR).resolve(strict=True)


def _safe_file(name: str) -> Path:
    if not isinstance(name, str) or not name or len(name) > 255 or "\x00" in name:
        raise ToolError("filename must be a non-empty string of at most 255 characters")
    root = _document_root()
    candidate = Path(name)
    if candidate.is_absolute() or re.match(r"^[A-Za-z]:", name) or "\\" in name:
        raise ToolError("only relative document filenames are allowed")
    if any(part in ("..", "") for part in candidate.parts) or len(candidate.parts) != 1:
        raise ToolError("path traversal and subdirectories are not allowed")
    try:
        resolved = (root / candidate).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ToolError(f"file not found or inaccessible: {name}") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ToolError("file resolves outside the document directory") from exc
    if not resolved.is_file():
        raise ToolError("requested path is not a file")
    if resolved.suffix.lower() not in {".txt", ".md", ".csv", ".json", ".log"}:
        raise ToolError("unsupported document type")
    try:
        if resolved.stat().st_size > MAX_FILE_BYTES:
            raise ToolError("document exceeds the maximum allowed size")
    except OSError as exc:
        raise ToolError(f"file is inaccessible: {name}") from exc
    return resolved


def search_files(query: str) -> dict[str, Any]:
    if not isinstance(query, str) or not query.strip() or len(query) > 255:
        raise ToolError("query must be a non-empty string of at most 255 characters")
    root = _document_root()
    q = query.casefold()
    matches = []
    try:
        for item in root.iterdir():
            if item.is_file() and q in item.name.casefold():
                try:
                    safe = _safe_file(item.name)
                except ToolError:
                    continue
                matches.append(safe.name)
                if len(matches) >= MAX_SEARCH_RESULTS:
                    break
    except OSError as exc:
        raise ToolError(f"document directory cannot be searched: {exc}") from exc
    return {"files": matches}


def read_file(filename: str) -> dict[str, Any]:
    path = _safe_file(filename)
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ToolError("document is not valid UTF-8 text") from exc
    except (OSError, PermissionError) as exc:
        raise ToolError(f"document cannot be read: {exc}") from exc
    return {"filename": path.name, "content": text}


TOOL_REGISTRY = {
    "search_files": {"function": search_files, "description": "Find document filenames by a name fragment.", "parameters": {"query": "string"}},
    "read_file": {"function": read_file, "description": "Read one text document by its filename.", "parameters": {"filename": "string"}},
    "calculator": {"function": calculator, "description": "Evaluate basic arithmetic safely.", "parameters": {"expression": "string"}},
}


def dispatch_tool(name: str, arguments: Any) -> dict[str, Any]:
    spec = TOOL_REGISTRY.get(name) if isinstance(name, str) else None
    if spec is None:
        raise ToolError(f"unknown tool: {name}")
    if not isinstance(arguments, dict) or set(arguments) != set(spec["parameters"]):
        raise ToolError(f"{name} expects exactly these arguments: {', '.join(spec['parameters'])}")
    return spec["function"](**arguments)
