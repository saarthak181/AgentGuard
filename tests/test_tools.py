import pytest

from agent.tools import ToolError, calculator, read_file, search_files


@pytest.mark.parametrize(("expr", "expected"), [("2+3", 5), ("9-4", 5), ("3*4", 12), ("20/4", 5), ("-(2+3)*2", -10)])
def test_calculator_arithmetic(expr, expected):
    assert calculator(expr)["result"] == expected


@pytest.mark.parametrize("expr", ["", "2+", "__import__('os')", "2//1", "2**101", "9**9**9", "1/0", "1" * 300, "float('inf')"])
def test_calculator_rejects_unsafe_or_invalid(expr):
    with pytest.raises(ToolError):
        calculator(expr)


def test_calculator_malformed_input():
    for value in (None, 2, [], {}):
        with pytest.raises(ToolError):
            calculator(value)


def test_search_existing_and_no_match(documents):
    assert search_files("sales")["files"] == ["sales_report.txt"]
    assert search_files("absent")["files"] == []


def test_read_valid_and_missing(documents):
    assert "January: 12000" in read_file("sales_report.txt")["content"]
    with pytest.raises(ToolError):
        read_file("missing.txt")


@pytest.mark.parametrize("name", ["../secret.txt", "..\\secret.txt", "nested\\x.txt", "C:\\secret.txt", "/etc/passwd", "", None, 7])
def test_reject_paths_and_malformed_names(documents, name):
    with pytest.raises(ToolError):
        read_file(name)


def test_symlink_escape_rejected(documents, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    try:
        (documents / "escape.txt").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(ToolError):
        read_file("escape.txt")


def test_invalid_encoding_rejected(documents):
    (documents / "bad.txt").write_bytes(b"\xff\xfe")
    with pytest.raises(ToolError, match="UTF-8"):
        read_file("bad.txt")


def test_permission_failure_reported(documents, monkeypatch):
    from pathlib import Path

    original = Path.read_text

    def denied(path, *args, **kwargs):
        if path.name == "sales_report.txt":
            raise PermissionError("access denied")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", denied)
    with pytest.raises(ToolError, match="cannot be read"):
        read_file("sales_report.txt")


def test_unsupported_and_oversized_rejected(documents, monkeypatch):
    (documents / "data.exe").write_text("x")
    with pytest.raises(ToolError, match="unsupported"):
        read_file("data.exe")
    (documents / "big.txt").write_text("0123456789")
    monkeypatch.setattr("agent.tools.MAX_FILE_BYTES", 5)
    with pytest.raises(ToolError, match="maximum"):
        read_file("big.txt")
