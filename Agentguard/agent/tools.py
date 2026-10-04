from pathlib import Path
import ast
import operator


# ============================================================
# SAFE CALCULATOR
# ============================================================

_ALLOWED_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.Mod: operator.mod,
    ast.USub: operator.neg,
}


def _safe_eval(node):
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)):
            return node.value
        raise ValueError("Only numbers are allowed.")

    if isinstance(node, ast.BinOp):
        left = _safe_eval(node.left)
        right = _safe_eval(node.right)

        operation = _ALLOWED_OPERATORS.get(type(node.op))

        if operation is None:
            raise ValueError("Operator not allowed.")

        return operation(left, right)

    if isinstance(node, ast.UnaryOp):
        operand = _safe_eval(node.operand)

        operation = _ALLOWED_OPERATORS.get(type(node.op))

        if operation is None:
            raise ValueError("Operator not allowed.")

        return operation(operand)

    raise ValueError("Invalid mathematical expression.")


def calculator(expression: str):
    """
    Safely evaluate a basic mathematical expression.
    """

    try:
        tree = ast.parse(expression, mode="eval")
        result = _safe_eval(tree.body)

        return f"Result: {result}"

    except Exception as e:
        return f"Calculator error: {str(e)}"


# ============================================================
# FILE SEARCH
# ============================================================

DOCUMENT_FOLDER = Path("data/documents")


def search_files(keyword: str):
    """
    Search for a keyword inside files located in
    data/documents/.
    """

    if not DOCUMENT_FOLDER.exists():
        return "Document folder does not exist."

    matches = []

    for file in DOCUMENT_FOLDER.iterdir():

        if not file.is_file():
            continue

        try:
            content = file.read_text(encoding="utf-8")

            if keyword.lower() in content.lower():
                matches.append(file.name)

        except Exception:
            continue

    if not matches:
        return f"No documents found containing: {keyword}"

    return "Matching documents:\n" + "\n".join(matches)


# ============================================================
# FILE READER
# ============================================================

def read_file(filename: str):
    """
    Read a file only from data/documents/.
    """

    file_path = DOCUMENT_FOLDER / filename

    if not file_path.exists():
        return f"File not found: {filename}"

    if not file_path.is_file():
        return "The requested path is not a file."

    try:
        return file_path.read_text(encoding="utf-8")

    except Exception as e:
        return f"File reading error: {str(e)}"


# ============================================================
# TOOL REGISTRY
# ============================================================

TOOLS = {
    "calculator": calculator,
    "search_files": search_files,
    "read_file": read_file,
}