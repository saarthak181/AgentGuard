import ast
import operator
from pathlib import Path


DOCUMENT_FOLDER = Path("data/documents").resolve()


# =========================================================
# SAFE CALCULATOR
# =========================================================

ALLOWED_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def _safe_calculate(node):

    if isinstance(node, ast.Constant):

        if isinstance(node.value, (int, float)):
            return node.value

        raise ValueError("Only numbers are allowed.")

    if isinstance(node, ast.UnaryOp):

        operator_type = type(node.op)

        if operator_type not in ALLOWED_OPERATORS:
            raise ValueError("Operator not allowed.")

        return ALLOWED_OPERATORS[operator_type](
            _safe_calculate(node.operand)
        )

    if isinstance(node, ast.BinOp):

        operator_type = type(node.op)

        if operator_type not in ALLOWED_OPERATORS:
            raise ValueError("Operator not allowed.")

        left = _safe_calculate(node.left)
        right = _safe_calculate(node.right)

        return ALLOWED_OPERATORS[operator_type](
            left,
            right
        )

    raise ValueError("Invalid mathematical expression.")


def calculator(expression):

    if not isinstance(expression, str):
        raise ValueError("Expression must be a string.")

    expression = expression.strip()

    if not expression:
        raise ValueError("Expression cannot be empty.")

    tree = ast.parse(expression, mode="eval")

    return str(_safe_calculate(tree.body))


# =========================================================
# SEARCH FILES
# =========================================================

def search_files(query=None, filename=None):

    # Accept either query or filename.
    search_term = query if query is not None else filename

    if not isinstance(search_term, str):
        raise ValueError(
            "A search query or filename is required."
        )

    search_term = search_term.strip().lower()

    if not search_term:
        return "Please provide a search query."

    if not DOCUMENT_FOLDER.exists():
        return "The documents directory does not exist."

    # Make searching tolerant of spaces vs underscores.
    normalized_search = search_term.replace("_", " ")

    matches = []

    for file_path in DOCUMENT_FOLDER.rglob("*"):

        if not file_path.is_file():
            continue

        filename_lower = file_path.name.lower()

        normalized_filename = filename_lower.replace(
            "_",
            " "
        )

        if (
            search_term in filename_lower
            or normalized_search in normalized_filename
            or normalized_filename in normalized_search
        ):
            matches.append(file_path.name)

    if not matches:
        return (
            f"No files found matching "
            f"'{search_term}'."
        )

    return "\n".join(matches)


# =========================================================
# READ FILE
# =========================================================

def read_file(filename):

    if not isinstance(filename, str):
        raise ValueError("Filename must be a string.")

    filename = filename.strip()

    if not filename:
        raise ValueError("Filename cannot be empty.")

    # Normalize spaces and underscores.
    # This allows:
    # sales report.txt
    # sales_report.txt
    normalized_filename = filename.replace(
        " ",
        "_"
    )

    requested_path = (
        DOCUMENT_FOLDER / normalized_filename
    ).resolve()

    # Security check against path traversal.
    try:
        requested_path.relative_to(DOCUMENT_FOLDER)
    except ValueError:
        raise ValueError(
            "Access to this file is not allowed."
        )

    if not requested_path.exists():

        # Try to find a matching file.
        matches = []

        for file_path in DOCUMENT_FOLDER.rglob("*"):

            if not file_path.is_file():
                continue

            if file_path.name.lower().replace(
                "_",
                " "
            ) == filename.lower().replace(
                "_",
                " "
            ):
                matches.append(file_path)

        if matches:
            requested_path = matches[0]

        else:
            return f"File not found: {filename}"

    if not requested_path.is_file():
        return f"Not a file: {filename}"

    try:

        with open(
            requested_path,
            "r",
            encoding="utf-8"
        ) as file:

            return file.read()

    except UnicodeDecodeError:

        return (
            "Unable to read this file "
            "as a text document."
        )


# =========================================================
# AVAILABLE TOOLS
# =========================================================

TOOLS = {
    "calculator": calculator,
    "search_files": search_files,
    "read_file": read_file,
}