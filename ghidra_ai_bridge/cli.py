"""CLI dispatcher for ghidra-ai-bridge.

Usage:
    ghidra-bridge <command> [args...]

Commands:
    init                              Interactive setup wizard
    export [all|structs|decompiled|vtables|globals|strings|source-types]
    build-map                         Build address map from source
    decompile <addr|name>             Get decompiled code
    search <pattern>                  Search function names
    xrefs-to <addr|name>             Who calls this function?
    xrefs-from <addr|name>           What does this function call?
    struct <name>                     Show struct/class definition
    enum <name>                       Show enum values
    vtable <class>                    Show virtual function table
    global <addr|name>                Show global variable info
    strings <pattern>                 Search strings
    containing <addr>                 Find function containing address
    decompile-class <class>           Decompile all methods of a class
    unimplemented [pattern]           List functions not yet reversed
    remaining [class]                 Show remaining stubs
    source-struct <name>              Query struct from reversed source
    source-enum <name>                Query enum from reversed source
    dump-asm <addr|name> <output>     Dump assembly for a function
    info                              Show export stats
    list                              List all exported functions
"""

from __future__ import annotations

import argparse
import os
import sys

from ghidra_ai_bridge.config import load_config


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ghidra-bridge",
        description="AI-powered Ghidra query interface for reverse engineering agents",
    )
    parser.add_argument("--config", help="Path to config file")
    parser.add_argument("--export-dir", dest="export_dir", help="Override export directory")
    parser.add_argument("--source-root", dest="source_root", help="Override source root")

    sub = parser.add_subparsers(dest="command")

    # init
    sub.add_parser("init", help="Interactive setup wizard")

    # export
    p_export = sub.add_parser("export", help="Run Ghidra export scripts")
    p_export.add_argument("type", nargs="?", default="all",
                          choices=["all", "structs", "decompiled", "vtables",
                                   "globals", "strings", "source-types",
                                   "create-functions", "fix-all"],
                          help="Export type (default: all)")

    # build-map
    sub.add_parser("build-map", help="Build address map from source")

    # Query commands with required argument
    for cmd in ["decompile", "search", "xrefs-to", "xrefs-from", "struct",
                "enum", "vtable", "global", "strings", "containing",
                "decompile-class", "source-struct", "source-enum", "context",
                "pcode", "cfg", "asm"]:
        p = sub.add_parser(cmd)
        p.add_argument("target", help="Address, name, or pattern")

    # Commands with optional argument
    for cmd in ["unimplemented", "remaining"]:
        p = sub.add_parser(cmd)
        p.add_argument("filter", nargs="?", default=None, help="Optional filter pattern")

    # No-arg commands
    sub.add_parser("info", help="Show export statistics")
    sub.add_parser("list", help="List all exported functions")

    # dump-asm
    p_asm = sub.add_parser("dump-asm", help="Dump assembly for a function")
    p_asm.add_argument("target", help="Function address or name")
    p_asm.add_argument("output", help="Output file for instruction dump")
    p_asm.add_argument("--refs-out", help="Optional output file for refs-from summary")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    # Build CLI overrides dict
    cli_overrides = {}
    if args.export_dir:
        cli_overrides["export_dir"] = args.export_dir
    if args.source_root:
        cli_overrides["source_root"] = args.source_root

    cfg = load_config(config_path=args.config, cli_overrides=cli_overrides or None)

    # Dispatch
    cmd = args.command

    if cmd == "init":
        from ghidra_ai_bridge.init_wizard import run_wizard
        return run_wizard()

    if cmd == "export":
        from ghidra_ai_bridge.exporters.runner import run_export
        return run_export(args.type, cfg)

    if cmd == "build-map":
        from ghidra_ai_bridge.address_map import build_address_map
        return build_address_map(cfg)

    if cmd == "dump-asm":
        from ghidra_ai_bridge.asm import dump_asm
        return dump_asm(args.target, args.output, refs_out=args.refs_out, cfg=cfg)

    # Query commands
    from ghidra_ai_bridge import query

    dispatch = {
        "decompile":       lambda: query.cmd_decompile(args.target, cfg),
        "search":          lambda: query.cmd_search(args.target, cfg),
        "xrefs-to":        lambda: query.cmd_xrefs_to(args.target, cfg),
        "xrefs-from":      lambda: query.cmd_xrefs_from(args.target, cfg),
        "struct":          lambda: query.cmd_struct(args.target, cfg),
        "enum":            lambda: query.cmd_enum(args.target, cfg),
        "vtable":          lambda: query.cmd_vtable(args.target, cfg),
        "global":          lambda: query.cmd_global(args.target, cfg),
        "strings":         lambda: query.cmd_strings(args.target, cfg),
        "containing":      lambda: query.cmd_containing(args.target, cfg),
        "decompile-class": lambda: query.cmd_decompile_class(args.target, cfg),
        "source-struct":   lambda: query.cmd_source_struct(args.target, cfg),
        "source-enum":     lambda: query.cmd_source_enum(args.target, cfg),
        "context":         lambda: query.cmd_context(args.target, cfg),
        "pcode":           lambda: query.cmd_ir(args.target, cfg, "pcode"),
        "cfg":             lambda: query.cmd_ir(args.target, cfg, "cfg"),
        "asm":             lambda: query.cmd_asm(args.target, cfg),
        "unimplemented":   lambda: query.cmd_unimplemented(cfg, args.filter),
        "remaining":       lambda: query.cmd_remaining(cfg, args.filter),
        "info":            lambda: query.cmd_info(cfg),
        "list":            lambda: query.cmd_list(cfg),
    }

    handler = dispatch.get(cmd)
    if handler:
        return handler()

    parser.print_help()
    return 1
