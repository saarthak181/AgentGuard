"""Explicit, constrained tools available to the AgentGuard agent."""

from __future__ import annotations

import ast
import csv
import json
import operator
import os
import re
import shutil
import statistics
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
    if resolved.suffix.lower() not in {".txt", ".md", ".csv", ".json", ".log", ".svg"}:
        raise ToolError("unsupported document type")
    try:
        if resolved.stat().st_size > MAX_FILE_BYTES:
            raise ToolError("document exceeds the maximum allowed size")
    except OSError as exc:
        raise ToolError(f"file is inaccessible: {name}") from exc
    return resolved


def _safe_destination(name: str) -> Path:
    if not isinstance(name, str) or not name or len(name) > 255 or "\x00" in name:
        raise ToolError("filename must be a non-empty string of at most 255 characters")
    root = _document_root()
    candidate = Path(name)
    if candidate.is_absolute() or re.match(r"^[A-Za-z]:", name) or "\\" in name or len(candidate.parts) != 1 or candidate.name != name:
        raise ToolError("only a relative filename in the document directory is allowed")
    if candidate.suffix.lower() not in {".txt", ".md", ".csv", ".json", ".log", ".svg"}:
        raise ToolError("unsupported document type")
    destination = (root / candidate).resolve()
    try: destination.relative_to(root)
    except ValueError as exc: raise ToolError("destination resolves outside the document directory") from exc
    return destination


def list_files() -> dict[str, Any]:
    root = _document_root()
    files=[]
    for item in sorted(root.iterdir(), key=lambda path:path.name.casefold()):
        try: files.append(_file_info(_safe_file(item.name)))
        except ToolError: continue
    return {"files": files[:MAX_SEARCH_RESULTS]}


def _file_info(path: Path) -> dict[str, Any]:
    stat=path.stat()
    return {"filename":path.name,"size_bytes":stat.st_size,"extension":path.suffix.lower(),"modified_at":int(stat.st_mtime)}


def get_file_info(filename: str) -> dict[str, Any]: return _file_info(_safe_file(filename))
def read_file_metadata(filename: str) -> dict[str, Any]: return _file_info(_safe_file(filename))


def write_file(filename: str, content: str) -> dict[str, Any]:
    if not isinstance(content,str) or len(content.encode("utf-8"))>MAX_FILE_BYTES: raise ToolError("content must be UTF-8 text within the file-size limit")
    path=_safe_destination(filename); path.write_text(content,encoding="utf-8",newline="\n")
    return {"filename":path.name,"size_bytes":path.stat().st_size}


def copy_file(source: str, destination: str) -> dict[str, Any]:
    src=_safe_file(source); dst=_safe_destination(destination)
    if dst.exists(): raise ToolError("destination already exists")
    shutil.copyfile(src,dst); return {"source":src.name,"destination":dst.name}


def move_file(source: str, destination: str) -> dict[str, Any]:
    src=_safe_file(source); dst=_safe_destination(destination)
    if dst.exists(): raise ToolError("destination already exists")
    src.replace(dst); return {"source":src.name,"destination":dst.name}


def delete_file(filename: str) -> dict[str, Any]:
    path=_safe_file(filename); path.unlink(); return {"deleted":path.name}


def summarize_text(text: str) -> dict[str, Any]:
    if not isinstance(text,str) or not text.strip() or len(text)>MAX_FILE_BYTES: raise ToolError("text must be non-empty and within the size limit")
    sentences=re.split(r"(?<=[.!?])\s+",text.strip()); return {"summary":" ".join(sentences[:3])[:1200],"characters":len(text)}


def _csv_rows(filename: str) -> tuple[list[str],list[dict[str,str]]]:
    path=_safe_file(filename)
    if path.suffix.lower()!=".csv": raise ToolError("a CSV document is required")
    try:
        with path.open(encoding="utf-8",newline="") as stream:
            reader=csv.DictReader(stream); rows=list(reader); fields=reader.fieldnames or []
    except (OSError,csv.Error,UnicodeError) as exc: raise ToolError("CSV cannot be read") from exc
    if not fields or len(rows)>10000: raise ToolError("CSV must have headers and no more than 10000 rows")
    return fields,rows


def analyze_csv(filename: str) -> dict[str, Any]:
    fields,rows=_csv_rows(filename); return {"filename":filename,"columns":fields,"row_count":len(rows),"missing":{field:sum(not (row.get(field) or "").strip() for row in rows) for field in fields}}


def filter_records(filename: str, column: str, value: str) -> dict[str, Any]:
    fields,rows=_csv_rows(filename)
    if column not in fields: raise ToolError("unknown CSV column")
    matches=[row for row in rows if row.get(column)==value][:500]
    return {"columns":fields,"records":matches,"matched":len(matches)}


def calculate_statistics(filename: str, column: str) -> dict[str, Any]:
    fields,rows=_csv_rows(filename)
    if column not in fields: raise ToolError("unknown CSV column")
    try: values=[float(row[column]) for row in rows if (row.get(column) or "").strip()]
    except ValueError as exc: raise ToolError("selected column contains non-numeric values") from exc
    if not values: raise ToolError("selected column has no numeric values")
    return {"count":len(values),"min":min(values),"max":max(values),"mean":statistics.fmean(values),"median":statistics.median(values)}


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
    "search_files": {"function": search_files, "description": "Find document filenames by a name fragment.", "parameters": {"query": "string"}, "inherent_risk": 15},
    "read_file": {"function": read_file, "description": "Read one text document by its filename.", "parameters": {"filename": "string"}, "inherent_risk": 20},
    "calculator": {"function": calculator, "description": "Evaluate basic arithmetic safely.", "parameters": {"expression": "string"}, "inherent_risk": 0},
    "list_files": {"function": list_files, "description": "List permitted document files.", "parameters": {}},
    "get_file_info": {"function": get_file_info, "description": "Get permitted file information.", "parameters": {"filename": "string"}},
    "read_file_metadata": {"function": read_file_metadata, "description": "Read permitted file metadata.", "parameters": {"filename": "string"}},
    "write_file": {"function": write_file, "description": "Write a permitted text file after review.", "parameters": {"filename": "string", "content": "string"}, "minimum_decision": "REVIEW", "inherent_risk": 75},
    "copy_file": {"function": copy_file, "description": "Copy a permitted file after review.", "parameters": {"source": "string", "destination": "string"}, "minimum_decision": "REVIEW"},
    "move_file": {"function": move_file, "description": "Move a permitted file after review.", "parameters": {"source": "string", "destination": "string"}, "minimum_decision": "REVIEW"},
    "delete_file": {"function": delete_file, "description": "Delete a permitted file after review.", "parameters": {"filename": "string"}, "minimum_decision": "REVIEW"},
    "summarize_text": {"function": summarize_text, "description": "Create a deterministic short text summary.", "parameters": {"text": "string"}},
    "analyze_csv": {"function": analyze_csv, "description": "Inspect a permitted CSV file.", "parameters": {"filename": "string"}},
    "filter_records": {"function": filter_records, "description": "Filter permitted CSV rows by an exact value.", "parameters": {"filename": "string", "column": "string", "value": "string"}},
    "calculate_statistics": {"function": calculate_statistics, "description": "Calculate statistics for a numeric permitted CSV column.", "parameters": {"filename": "string", "column": "string"}},
}


def dispatch_tool(name: str, arguments: Any) -> dict[str, Any]:
    spec = TOOL_REGISTRY.get(name) if isinstance(name, str) else None
    if spec is None:
        raise ToolError(f"unknown tool: {name}")
    if not isinstance(arguments, dict) or set(arguments) != set(spec["parameters"]):
        raise ToolError(f"{name} expects exactly these arguments: {', '.join(spec['parameters'])}")
    return spec["function"](**arguments)
