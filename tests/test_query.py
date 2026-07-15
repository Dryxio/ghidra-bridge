"""Tests for query engine."""

import json
import os
import tempfile

import pytest

from ghidra_ai_bridge.config import Config
from ghidra_ai_bridge.query import (
    cmd_asm,
    cmd_context,
    cmd_ir,
    normalize_address,
    find_function_file,
    load_json,
    cmd_search,
    cmd_decompile_class,
    cmd_remaining,
)


# ---------------------------------------------------------------------------
# Helper to build a mock export directory
# ---------------------------------------------------------------------------

def _make_exports(tmpdir, *, functions=None, index=None, address_map=None):
    """Create mock export files in tmpdir. Returns Config."""
    if functions:
        for addr, data in functions.items():
            with open(os.path.join(tmpdir, f"{addr}.json"), "w") as f:
                json.dump(data, f)

    if index is not None:
        with open(os.path.join(tmpdir, "_index.json"), "w") as f:
            json.dump(index, f)

    map_path = os.path.join(tmpdir, "address_map.json")
    with open(map_path, "w") as f:
        json.dump(address_map or {}, f)

    return Config(export_dir=tmpdir, address_map_path=map_path)


# ---------------------------------------------------------------------------
# Unit tests for helpers
# ---------------------------------------------------------------------------

def test_normalize_address():
    assert normalize_address("0x401000") == "00401000"
    assert normalize_address("401000") == "00401000"
    assert normalize_address("0x00401000") == "00401000"
    assert normalize_address("5fb010") == "005fb010"
    assert normalize_address("0") == "00000000"


def test_normalize_address_segmented():
    """Should handle Ghidra segmented address formats like ram:00401000."""
    assert normalize_address("ram:00401000") == "00401000"
    assert normalize_address("CODE:00500000") == "00500000"
    assert normalize_address("mem:0x401000") == "00401000"
    assert normalize_address("ram:401000") == "00401000"


def test_load_json_missing():
    result = load_json("/nonexistent/path.json")
    assert result == {}


def test_load_json_valid():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({"key": "value"}, f)
        f.flush()
        result = load_json(f.name)

    os.unlink(f.name)
    assert result == {"key": "value"}


def test_find_function_file_by_address():
    """Should find function file by direct address lookup."""
    with tempfile.TemporaryDirectory() as tmpdir:
        func_data = {"address": "00401000", "name": "test_func", "decompiled": "void test() {}"}
        with open(os.path.join(tmpdir, "00401000.json"), "w") as f:
            json.dump(func_data, f)

        cfg = Config(export_dir=tmpdir, address_map_path=os.path.join(tmpdir, "nomap.json"))
        result = find_function_file("0x401000", cfg)
        assert result is not None
        assert "00401000.json" in result


def test_find_function_file_not_found():
    """Should return None for missing function."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = Config(export_dir=tmpdir, address_map_path=os.path.join(tmpdir, "nomap.json"))
        result = find_function_file("0xDEADBEEF", cfg)
        assert result is None


def test_find_function_file_by_name():
    """Should find function by name via address map."""
    with tempfile.TemporaryDirectory() as tmpdir:
        address_map = {
            "00401000": {
                "name": "MyFunc",
                "class": "MyClass",
                "full_name": "MyClass::MyFunc",
                "file": "MyClass.cpp",
            }
        }
        map_path = os.path.join(tmpdir, "address_map.json")
        with open(map_path, "w") as f:
            json.dump(address_map, f)

        func_data = {"address": "00401000", "name": "FUN_00401000", "decompiled": "void test() {}"}
        with open(os.path.join(tmpdir, "00401000.json"), "w") as f:
            json.dump(func_data, f)

        cfg = Config(export_dir=tmpdir, address_map_path=map_path)
        result = find_function_file("MyClass::MyFunc", cfg)
        assert result is not None
        assert "00401000.json" in result


def test_cmd_ir_prints_versioned_json(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = _make_exports(
            tmpdir,
            functions={
                "00401000": {
                    "address": "00401000",
                    "name": "test_func",
                    "pcode": [{"opcode": "RETURN"}],
                },
            },
            address_map={},
        )
        assert cmd_ir("0x401000", cfg, "pcode") == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["schema_version"] == 1
        assert payload["data"][0]["opcode"] == "RETURN"


def test_cmd_ir_rejects_extraction_error_objects(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = _make_exports(
            tmpdir,
            functions={
                "00401000": {
                    "address": "00401000",
                    "name": "test_func",
                    "pcode": [{"error": "HighFunction unavailable"}],
                    "pcode_errors": ["HighFunction unavailable"],
                },
            },
            address_map={},
        )
        assert cmd_ir("0x401000", cfg, "pcode") == 1
        assert "HighFunction unavailable" in capsys.readouterr().out


def test_cmd_ir_rejects_partial_export_with_errors(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = _make_exports(
            tmpdir,
            functions={
                "00401000": {
                    "address": "00401000",
                    "name": "test_func",
                    "pcode": [{"opcode": "RETURN"}],
                    "pcode_errors": ["iteration stopped early"],
                },
            },
            address_map={},
        )
        assert cmd_ir("0x401000", cfg, "pcode") == 1
        assert "iteration stopped early" in capsys.readouterr().out


def test_cmd_context_collects_referenced_strings_and_globals(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = _make_exports(
            tmpdir,
            functions={
                "00401000": {
                    "address": "00401000",
                    "name": "test_func",
                    "signature": "void test_func()",
                    "callees": [],
                    "callers": [],
                    "cfg": [],
                },
            },
            address_map={},
        )
        with open(cfg.strings_file, "w") as f:
            json.dump({"00500000": {
                "address": "00500000",
                "value": "hello",
                "references": [{"func_addr": "00401000"}],
            }}, f)
        with open(cfg.globals_file, "w") as f:
            json.dump({"00600000": {
                "address": "00600000",
                "name": "gValue",
                "references": [{"func_addr": "00401000"}],
            }}, f)

        assert cmd_context("0x401000", cfg) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["kind"] == "function-context"
        assert payload["strings"][0]["value"] == "hello"
        assert payload["globals"][0]["name"] == "gValue"


def test_cmd_asm_prints_exported_instructions(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = _make_exports(
            tmpdir,
            functions={
                "00401000": {
                    "address": "00401000",
                    "name": "test_func",
                    "assembly": ["00401000  PUSH EBP", "00401001  RET"],
                },
            },
            address_map={},
        )
        assert cmd_asm("0x401000", cfg) == 0
        assert "PUSH EBP" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# cmd_search: address map + index fallback
# ---------------------------------------------------------------------------

def test_cmd_search_address_map(capsys):
    """search should find functions from address map."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = _make_exports(tmpdir, address_map={
            "00401000": {"name": "Foo", "class": "CBar", "full_name": "CBar::Foo", "file": "CBar.cpp"},
        })
        ret = cmd_search("CBar", cfg)
        assert ret == 0
        out = capsys.readouterr().out
        assert "CBar::Foo" in out


def test_cmd_search_index_fallback(capsys):
    """search should fall back to Ghidra index when address map has no match."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = _make_exports(
            tmpdir,
            index={"00501000": {"name": "GhidraOnly::Method", "address": "00501000"}},
            address_map={},
        )
        ret = cmd_search("GhidraOnly", cfg)
        assert ret == 0
        out = capsys.readouterr().out
        assert "GhidraOnly::Method" in out


def test_cmd_search_no_match(capsys):
    """search should return 1 when nothing matches."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = _make_exports(tmpdir, index={}, address_map={})
        ret = cmd_search("Nonexistent", cfg)
        assert ret == 1


# ---------------------------------------------------------------------------
# cmd_decompile_class: address map + index fallback
# ---------------------------------------------------------------------------

def test_cmd_decompile_class_address_map(capsys):
    """decompile-class should find methods from address map."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = _make_exports(
            tmpdir,
            functions={
                "00401000": {
                    "address": "00401000", "name": "FUN_00401000",
                    "decompiled": "void CMyClass_Foo() {}", "signature": "void()",
                },
            },
            address_map={
                "00401000": {"name": "Foo", "class": "CMyClass", "full_name": "CMyClass::Foo", "file": "x.cpp"},
            },
        )
        ret = cmd_decompile_class("CMyClass", cfg)
        assert ret == 0
        out = capsys.readouterr().out
        assert "CMyClass::Foo" in out
        assert "CMyClass_Foo" in out


def test_cmd_decompile_class_index_fallback(capsys):
    """decompile-class should fall back to Ghidra index."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = _make_exports(
            tmpdir,
            functions={
                "00601000": {
                    "address": "00601000", "name": "CAlpha::Beta",
                    "decompiled": "void beta() {}", "signature": "void()",
                },
            },
            index={"00601000": {"name": "CAlpha::Beta", "address": "00601000"}},
            address_map={},
        )
        ret = cmd_decompile_class("CAlpha", cfg)
        assert ret == 0
        out = capsys.readouterr().out
        assert "CAlpha::Beta" in out


def test_cmd_decompile_class_not_found(capsys):
    """decompile-class should return 1 when no methods found."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = _make_exports(tmpdir, index={}, address_map={})
        ret = cmd_decompile_class("NoSuchClass", cfg)
        assert ret == 1


# ---------------------------------------------------------------------------
# cmd_remaining: live scan using configured extensions
# ---------------------------------------------------------------------------

def test_cmd_remaining_respects_extensions(capsys, tmp_path):
    """remaining should scan all configured file extensions, not just .cpp."""
    # Create a .inl file with a stub pattern
    (tmp_path / "Foo.inl").write_text("MY_STUB<0x700000>();\n")

    cfg = Config(
        export_dir=str(tmp_path),
        address_map_path=str(tmp_path / "nomap.json"),
        source_root=str(tmp_path),
        stub_patterns=[r'MY_STUB\w*<[^>]*(0x[0-9A-Fa-f]+)[^>]*>'],
        file_extensions=[".inl"],
    )

    ret = cmd_remaining(cfg)
    assert ret == 0
    out = capsys.readouterr().out
    assert "1" in out  # total should be 1


def test_cmd_remaining_no_source(capsys):
    """remaining should fall back to cached file when no source configured."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Write a cached stubs file
        stubs_path = os.path.join(tmpdir, "_remaining_stubs.json")
        with open(stubs_path, "w") as f:
            json.dump({"total": 42, "by_class": {"CTest": 42}, "stubs": []}, f)

        cfg = Config(export_dir=tmpdir, address_map_path=os.path.join(tmpdir, "nomap.json"))
        ret = cmd_remaining(cfg)
        assert ret == 0
        out = capsys.readouterr().out
        assert "42" in out


# ---------------------------------------------------------------------------
# Segmented address handling in decompile-class
# ---------------------------------------------------------------------------

def test_cmd_decompile_class_segmented_index(capsys):
    """decompile-class should handle segmented addresses from Ghidra index."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = _make_exports(
            tmpdir,
            functions={
                "00601000": {
                    "address": "00601000", "name": "CAlpha::Method",
                    "decompiled": "void method() {}", "signature": "void()",
                },
            },
            # Ghidra index uses segmented address format
            index={"ram:00601000": {"name": "CAlpha::Method", "address": "ram:00601000"}},
            address_map={},
        )
        ret = cmd_decompile_class("CAlpha", cfg)
        assert ret == 0
        out = capsys.readouterr().out
        assert "CAlpha::Method" in out


def test_cmd_decompile_class_segmented_safe_filename(capsys):
    """decompile-class should find ram_00601000.json files from segmented exports."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Exporter writes segmented-safe filenames: ram_00601000.json
        func_data = {
            "address": "ram:00601000", "name": "CBeta::Run",
            "decompiled": "void run() { return; }", "signature": "void()",
        }
        with open(os.path.join(tmpdir, "ram_00601000.json"), "w") as f:
            json.dump(func_data, f)

        map_path = os.path.join(tmpdir, "address_map.json")
        with open(map_path, "w") as f:
            json.dump({}, f)

        # Index uses segmented keys (matching exporter)
        index_path = os.path.join(tmpdir, "_index.json")
        with open(index_path, "w") as f:
            json.dump({"ram:00601000": {"name": "CBeta::Run", "address": "ram:00601000"}}, f)

        cfg = Config(export_dir=tmpdir, address_map_path=map_path)
        ret = cmd_decompile_class("CBeta", cfg)
        assert ret == 0
        out = capsys.readouterr().out
        assert "CBeta::Run" in out
        assert "void run()" in out  # Should show decompiled body, not "// (not exported)"
        assert "(not exported)" not in out
