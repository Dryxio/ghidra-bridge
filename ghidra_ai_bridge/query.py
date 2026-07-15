"""Core query engine for Ghidra exports.

All commands read from pre-exported JSON files and an optional address map
built from reversed source code. No Ghidra runtime dependency.
"""

from __future__ import annotations

import glob
import json
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra_ai_bridge.config import Config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_json(filepath: str, default=None):
    """Load a JSON file if it exists."""
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return json.load(f)
    return default or {}


def normalize_address(addr: str) -> str:
    """Normalize address to 8-char lowercase hex.

    Handles plain hex (``401000``), ``0x`` prefix (``0x401000``),
    and Ghidra segmented format (``ram:00401000``, ``CODE:00401000``).
    """
    addr = addr.strip().lower()
    # Strip Ghidra segment prefix (e.g. "ram:", "code:", "mem:")
    if ":" in addr:
        addr = addr.rsplit(":", 1)[1]
    if addr.startswith("0x"):
        addr = addr[2:]
    return addr.zfill(8)


def _addr_sort_key(addr: str) -> int:
    """Convert address string to int for sorting, handling segmented formats."""
    try:
        return int(normalize_address(addr), 16)
    except ValueError:
        return 0


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

def _load_address_map(cfg: Config):
    return load_json(cfg.address_map_path)


def _load_index(cfg: Config):
    return load_json(cfg.index_file)


def find_function_file(target: str, cfg: Config) -> str | None:
    """Find function file by address or name using tiered lookup."""
    index = _load_index(cfg)
    address_map = _load_address_map(cfg)

    norm_addr = normalize_address(target)

    # 1. Direct file lookup by normalized address
    direct_path = os.path.join(cfg.export_dir, f"{norm_addr}.json")
    if os.path.exists(direct_path):
        return direct_path

    # 2. Check in ghidra export index by address
    if index:
        for addr, info in index.items():
            addr_norm = normalize_address(addr)
            if addr_norm == norm_addr:
                safe_addr = addr.replace(":", "_")
                filepath = os.path.join(cfg.export_dir, f"{safe_addr}.json")
                if os.path.exists(filepath):
                    return filepath

    # 3. Try as known function name from address map
    target_lower = target.lower()
    for addr, info in address_map.items():
        full_name = info.get("full_name", "")
        name = info.get("name", "")
        if (full_name.lower() == target_lower or
            name.lower() == target_lower or
            target_lower in full_name.lower()):
            safe_addr = addr.zfill(8)
            filepath = os.path.join(cfg.export_dir, f"{safe_addr}.json")
            if os.path.exists(filepath):
                return filepath

    # 4. Try as function name in ghidra index
    if index:
        for addr, info in index.items():
            name = info.get("name", "")
            if name.lower() == target_lower or target_lower in name.lower():
                safe_addr = addr.replace(":", "_")
                filepath = os.path.join(cfg.export_dir, f"{safe_addr}.json")
                if os.path.exists(filepath):
                    return filepath

    # 5. Last resort: glob search
    pattern = os.path.join(cfg.export_dir, f"*{norm_addr[-6:]}*.json")
    matches = glob.glob(pattern)
    if len(matches) == 1:
        return matches[0]

    return None


def get_known_name(address: str, cfg: Config) -> tuple[str, str]:
    """Look up known name from address map. Returns (full_name, file)."""
    address_map = _load_address_map(cfg)
    addr_raw = address.lstrip('0') or '0'
    info = address_map.get(addr_raw, {})
    if not info:
        info = address_map.get(normalize_address(address), {})
    return info.get("full_name", ""), info.get("file", "")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_decompile(target: str, cfg: Config) -> int:
    """Show decompiled code for a function."""
    filepath = find_function_file(target, cfg)

    if not filepath or not os.path.exists(filepath):
        print(f"ERROR: Function not found: {target}")
        print("Try: ghidra-bridge search <pattern>")
        return 1

    with open(filepath, "r") as f:
        data = json.load(f)

    known_name, source_file = get_known_name(data['address'], cfg)

    print(f"// ===========================================")
    if known_name:
        print(f"// Known as:  {known_name}")
        if source_file:
            if cfg.source_root:
                print(f"// Source:    {cfg.source_root}/{source_file}")
            else:
                print(f"// Source:    {source_file}")
    print(f"// Ghidra:    {data['name']}")
    print(f"// Address:   0x{data['address']}")
    print(f"// Signature: {data['signature']}")

    callers = data.get('callers', [])
    callees = data.get('callees', [])
    if callers or callees:
        print(f"// Callers:   {len(callers)}  |  Callees: {len(callees)}")

    print(f"// ===========================================")
    print()
    print(data["decompiled"])
    return 0


def cmd_ir(target: str, cfg: Config, key: str) -> int:
    """Print exported P-code or CFG JSON for a function."""
    if key not in {"pcode", "cfg"}:
        print(f"ERROR: Unsupported IR kind: {key}")
        return 1
    filepath = find_function_file(target, cfg)
    if not filepath:
        print(f"ERROR: Function not found: {target}")
        return 1
    data = load_json(filepath)
    artifact = data.get(key)
    errors = data.get(f"{key}_errors", data.get("ir_errors", []))
    valid = [
        item
        for item in artifact or []
        if isinstance(item, dict) and "error" not in item
    ]
    if errors or not valid:
        detail = f" ({'; '.join(str(error) for error in errors)})" if errors else ""
        print(f"ERROR: No {key} export for {target}. Run: ghidra-bridge export decompiled")
        if detail:
            print(f"IR extraction detail:{detail}")
        return 1
    print(json.dumps({"schema_version": 1, "kind": key, "target": target, "data": valid}, indent=2))
    return 0


def cmd_context(target: str, cfg: Config) -> int:
    """Print a machine-readable evidence bundle for one function."""
    filepath = find_function_file(target, cfg)
    if not filepath:
        print(f"ERROR: Function not found: {target}")
        return 1
    function = load_json(filepath)
    target_addr = normalize_address(str(function.get("address", target)))

    strings_data = load_json(cfg.strings_file)
    string_index = load_json(cfg.string_refs_by_function_file)
    strings = _context_items(target_addr, strings_data, string_index)

    globals_data = load_json(cfg.globals_file)
    global_index = load_json(cfg.global_refs_by_function_file)
    globals_found = _context_items(target_addr, globals_data, global_index)

    bundle = {
        "schema_version": 1,
        "kind": "function-context",
        "target": target,
        "function": {
            "address": function.get("address"),
            "name": function.get("name"),
            "signature": function.get("signature"),
            "calling_convention": function.get("calling_convention"),
            "callers": function.get("callers", []),
            "callees": function.get("callees", []),
        },
        "strings": strings[:50],
        "globals": globals_found[:50],
        "cfg": (
            []
            if function.get("cfg_errors") or function.get("ir_errors")
            else [
                item
                for item in function.get("cfg", [])
                if isinstance(item, dict) and "index" in item
            ]
        ),
    }
    print(json.dumps(bundle, indent=2))
    return 0


def _context_items(target_addr: str, data: dict, by_function: dict) -> list[dict]:
    """Resolve function-linked artifacts through an index, with legacy fallback."""
    indexed_addresses = []
    for func_addr, addresses in by_function.items():
        if normalize_address(str(func_addr)) == target_addr and isinstance(addresses, list):
            indexed_addresses.extend(str(address) for address in addresses)
    if indexed_addresses:
        normalized = {normalize_address(address) for address in indexed_addresses}
        return [
            item
            for address, item in data.items()
            if isinstance(item, dict) and normalize_address(str(address)) in normalized
        ]

    found = []
    for item in data.values():
        refs = item.get("references", []) if isinstance(item, dict) else []
        if any(normalize_address(str(ref.get("func_addr", ""))) == target_addr for ref in refs):
            found.append(item)
    return found


def cmd_asm(target: str, cfg: Config) -> int:
    """Print assembly stored with a decompiled function export."""
    filepath = find_function_file(target, cfg)
    if not filepath:
        print(f"ERROR: Function not found: {target}")
        return 1
    data = load_json(filepath)
    assembly = data.get("assembly", [])
    if not assembly:
        print(f"ERROR: No assembly export for {target}. Run: ghidra-bridge export decompiled")
        return 1
    print("\n".join(str(line) for line in assembly))
    return 0


def cmd_search(pattern: str, cfg: Config) -> int:
    """Search for functions by name (address map + Ghidra index)."""
    address_map = _load_address_map(cfg)
    index = _load_index(cfg)
    pattern_lower = pattern.lower()
    matches = []
    seen_addrs: set[str] = set()

    # 1. Search address map (has richer metadata)
    for addr, info in address_map.items():
        full_name = info.get("full_name", "")
        name = info.get("name", "")
        class_name = info.get("class", "")

        if (pattern_lower in full_name.lower() or
            pattern_lower in name.lower() or
            pattern_lower in class_name.lower()):
            matches.append((addr, full_name, info.get("file", "")))
            seen_addrs.add(normalize_address(addr))

    # 2. Fallback: search Ghidra index for functions not in address map
    for addr, info in index.items():
        addr_norm = normalize_address(addr)
        if addr_norm in seen_addrs:
            continue
        name = info.get("name", "")
        if pattern_lower in name.lower():
            matches.append((addr, name, ""))
            seen_addrs.add(addr_norm)

    if not matches:
        print(f"No functions matching '{pattern}'")
        return 1

    print(f"Found {len(matches)} functions matching '{pattern}':\n")
    for addr, name, file in sorted(matches, key=lambda x: x[1])[:100]:
        print(f"  0x{addr}  {name}")

    if len(matches) > 100:
        print(f"\n  ... and {len(matches) - 100} more")

    return 0


def cmd_xrefs_to(target: str, cfg: Config) -> int:
    """Show functions that call this function (callers)."""
    filepath = find_function_file(target, cfg)

    if not filepath or not os.path.exists(filepath):
        print(f"ERROR: Function not found: {target}")
        return 1

    with open(filepath, "r") as f:
        data = json.load(f)

    callers = data.get('callers', [])
    known_name, _ = get_known_name(data['address'], cfg)

    print(f"// Cross-references TO: {known_name or data['name']}")
    print(f"// Address: 0x{data['address']}")
    print(f"// {len(callers)} caller(s)\n")

    if not callers:
        print("  (no callers found - may be entry point or unreferenced)")
        print("\n  Note: If callers should exist, re-run decompiled export")
        return 0

    address_map = _load_address_map(cfg)
    for caller in callers:
        addr = caller['addr'].lstrip('0') or '0'
        known = address_map.get(addr, {}).get("full_name", "")
        ref_type = caller.get('ref_type', 'CALL')
        if known:
            print(f"  0x{caller['addr']}  {known}  [{ref_type}]")
        else:
            print(f"  0x{caller['addr']}  {caller['name']}  [{ref_type}]")

    return 0


def cmd_xrefs_from(target: str, cfg: Config) -> int:
    """Show functions that this function calls (callees)."""
    filepath = find_function_file(target, cfg)

    if not filepath or not os.path.exists(filepath):
        print(f"ERROR: Function not found: {target}")
        return 1

    with open(filepath, "r") as f:
        data = json.load(f)

    callees = data.get('callees', [])
    known_name, _ = get_known_name(data['address'], cfg)

    print(f"// Cross-references FROM: {known_name or data['name']}")
    print(f"// Address: 0x{data['address']}")
    print(f"// {len(callees)} callee(s)\n")

    if not callees:
        print("  (no calls found - may be leaf function)")
        print("\n  Note: If callees should exist, re-run decompiled export")
        return 0

    address_map = _load_address_map(cfg)
    for callee in callees:
        addr = callee['addr'].lstrip('0') or '0'
        known = address_map.get(addr, {}).get("full_name", "")
        if known:
            print(f"  0x{callee['addr']}  {known}")
        else:
            print(f"  0x{callee['addr']}  {callee['name']}")

    return 0


def cmd_struct(name: str, cfg: Config) -> int:
    """Show struct/class definition from Ghidra exports."""
    structs = load_json(cfg.structs_file)

    if not structs:
        print("ERROR: No structs exported. Run export scripts in Ghidra first.")
        return 1

    if name in structs:
        s = structs[name]
    else:
        name_lower = name.lower()
        matches = [(k, v) for k, v in structs.items() if name_lower in k.lower()]

        if not matches:
            print(f"ERROR: Struct not found: {name}")
            print("\nAvailable structs (sample):")
            for k in sorted(structs.keys())[:20]:
                print(f"  {k}")
            return 1

        if len(matches) == 1:
            name, s = matches[0]
        else:
            print(f"Multiple matches for '{name}':\n")
            for k, v in sorted(matches, key=lambda x: x[0])[:20]:
                print(f"  {k}  (size: 0x{v['size']:x})")
            return 0

    print(f"// Struct: {s['name']}")
    print(f"// Path:   {s['path']}")
    print(f"// Size:   0x{s['size']:x} ({s['size']} bytes)")
    print(f"// Fields: {len(s['fields'])}")
    print()

    for fld in s['fields']:
        comment = f"  // {fld['comment']}" if fld.get('comment') else ""
        print(f"  +0x{fld['offset']:03x}  {fld['type']:24}  {fld['name']}{comment}")

    return 0


def cmd_enum(name: str, cfg: Config) -> int:
    """Show enum values from Ghidra exports."""
    enums = load_json(cfg.enums_file)

    if not enums:
        print("ERROR: No enums exported. Run export scripts in Ghidra first.")
        return 1

    if name in enums:
        e = enums[name]
    else:
        name_lower = name.lower()
        matches = [(k, v) for k, v in enums.items() if name_lower in k.lower()]

        if not matches:
            print(f"ERROR: Enum not found: {name}")
            return 1

        if len(matches) == 1:
            name, e = matches[0]
        else:
            print(f"Multiple matches for '{name}':\n")
            for k, v in sorted(matches, key=lambda x: x[0])[:20]:
                print(f"  {k}")
            return 0

    print(f"// Enum: {e['name']}")
    print(f"// Size: {e['size']} bytes")
    print()

    for val in sorted(e['values'], key=lambda x: x['value']):
        print(f"  {val['name']} = {val['value']}")

    return 0


def cmd_vtable(class_name: str, cfg: Config) -> int:
    """Show virtual function table for a class."""
    vtables = load_json(cfg.vtables_file)

    if not vtables:
        print("ERROR: No vtables exported. Run export scripts in Ghidra first.")
        return 1

    matches = []
    class_lower = class_name.lower()

    for sym, vtbl in vtables.items():
        if vtbl.get('class_name', '').lower() == class_lower:
            matches.append((sym, vtbl))
        elif class_lower in sym.lower():
            matches.append((sym, vtbl))

    if not matches:
        print(f"ERROR: No vtable found for: {class_name}")
        print("\nAvailable vtables (sample):")
        for sym in sorted(vtables.keys())[:20]:
            cn = vtables[sym].get('class_name', '')
            print(f"  {cn or sym}")
        return 1

    address_map = _load_address_map(cfg)

    for sym, vtbl in matches:
        print(f"// VTable: {vtbl.get('class_name', sym)}")
        print(f"// Symbol: {sym}")
        print(f"// Address: 0x{vtbl['address']}")
        print(f"// Entries: {vtbl['entry_count']}")
        print()

        for entry in vtbl['entries']:
            addr = entry['address'].lstrip('0') or '0'
            known = address_map.get(addr, {}).get("full_name", "")
            if known:
                print(f"  [{entry['index']:2}] +0x{entry['offset']:03x}  {known}")
            else:
                print(f"  [{entry['index']:2}] +0x{entry['offset']:03x}  {entry['name']}")

        print()

    return 0


def cmd_global(target: str, cfg: Config) -> int:
    """Show global variable info."""
    globals_data = load_json(cfg.globals_file)

    if not globals_data:
        print("ERROR: No globals exported. Run export scripts in Ghidra first.")
        return 1

    norm_addr = normalize_address(target)
    for addr, info in globals_data.items():
        if normalize_address(addr) == norm_addr:
            _print_global(info, cfg)
            return 0

    target_lower = target.lower()
    matches = [(a, g) for a, g in globals_data.items()
               if g.get('name', '').lower() == target_lower or
                  target_lower in g.get('name', '').lower()]

    if not matches:
        print(f"ERROR: Global not found: {target}")
        return 1

    if len(matches) == 1:
        _print_global(matches[0][1], cfg)
    else:
        print(f"Multiple matches for '{target}':\n")
        for addr, g in sorted(matches, key=lambda x: x[1].get('name', ''))[:30]:
            print(f"  0x{addr}  {g.get('name', 'unnamed')}  ({g.get('type', '?')})")

    return 0


def _print_global(g: dict, cfg: Config) -> None:
    """Print global variable info."""
    print(f"// Global: {g.get('name', 'unnamed')}")
    print(f"// Address: 0x{g['address']}")
    print(f"// Type: {g.get('type', 'unknown')}")
    print(f"// Size: {g.get('size', '?')} bytes")
    print(f"// Section: {g.get('section', '?')}")
    if g.get('value'):
        print(f"// Value: {g['value']}")
    print()

    refs = g.get('references', [])
    if refs:
        print(f"Referenced by {len(refs)} function(s):")
        address_map = _load_address_map(cfg)
        for ref in refs[:20]:
            addr = ref['func_addr'].lstrip('0') or '0'
            known = address_map.get(addr, {}).get("full_name", "")
            if known:
                print(f"  0x{ref['func_addr']}  {known}")
            else:
                print(f"  0x{ref['func_addr']}  {ref['func_name']}")
        if len(refs) > 20:
            print(f"  ... and {len(refs) - 20} more")


def cmd_strings(pattern: str, cfg: Config) -> int:
    """Search for strings in Ghidra exports."""
    strings_data = load_json(cfg.strings_file)

    if not strings_data:
        print("ERROR: No strings exported. Run export scripts in Ghidra first.")
        return 1

    pattern_lower = pattern.lower()
    matches = []

    for addr, s in strings_data.items():
        if pattern_lower in s.get('value', '').lower():
            matches.append((addr, s))

    if not matches:
        print(f"No strings matching '{pattern}'")
        return 1

    print(f"Found {len(matches)} strings matching '{pattern}':\n")

    address_map = _load_address_map(cfg)
    for addr, s in sorted(matches, key=lambda x: x[1]['value'])[:50]:
        value = s['value']
        if len(value) > 60:
            value = value[:60] + "..."
        print(f"  0x{addr}  \"{value}\"")

        refs = s.get('references', [])
        if refs:
            ref = refs[0]
            ref_addr = ref['func_addr'].lstrip('0') or '0'
            known = address_map.get(ref_addr, {}).get("full_name", "")
            func_name = known or ref['func_name']
            if len(refs) > 1:
                print(f"           -> {func_name} (+{len(refs)-1} more)")
            else:
                print(f"           -> {func_name}")

    if len(matches) > 50:
        print(f"\n  ... and {len(matches) - 50} more")

    return 0


def cmd_decompile_class(class_name: str, cfg: Config) -> int:
    """Decompile all methods of a class (address map + Ghidra index)."""
    address_map = _load_address_map(cfg)
    index = _load_index(cfg)
    class_lower = class_name.lower()

    methods = []
    seen_addrs: set[str] = set()

    # 1. Search address map
    for addr, info in address_map.items():
        if info.get("class", "").lower() == class_lower:
            methods.append((addr, info))
            seen_addrs.add(normalize_address(addr))

    # 2. Fallback: search Ghidra index by name prefix (e.g. "CMyClass::")
    for addr, info in index.items():
        addr_norm = normalize_address(addr)
        if addr_norm in seen_addrs:
            continue
        name = info.get("name", "")
        if name.lower().startswith(class_lower + "::"):
            methods.append((addr, {"full_name": name, "class": class_name}))
            seen_addrs.add(addr_norm)

    if not methods:
        print(f"ERROR: No methods found for class: {class_name}")
        print("\nTry searching: ghidra-bridge search <class_name>")
        return 1

    print(f"// ===========================================")
    print(f"// Class: {class_name}")
    print(f"// Methods: {len(methods)}")
    print(f"// ===========================================\n")

    methods.sort(key=lambda x: _addr_sort_key(x[0]))

    for addr, info in methods:
        addr_norm = normalize_address(addr)
        print(f"// --- {info['full_name']} @ 0x{addr_norm} ---")

        # Try normalized filename first, then segmented-safe (ram_00601000.json)
        filepath = os.path.join(cfg.export_dir, f"{addr_norm}.json")
        if not os.path.exists(filepath):
            safe_addr = addr.replace(":", "_")
            filepath = os.path.join(cfg.export_dir, f"{safe_addr}.json")

        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                data = json.load(f)
            print(data["decompiled"])
        else:
            print("// (not exported)")
        print()

    return 0


def cmd_list(cfg: Config) -> int:
    """List all exported functions."""
    index = _load_index(cfg)
    if not index:
        print("ERROR: No index found. Run decompiled export first.")
        return 1

    print(f"Total functions: {len(index)}\n")
    for addr, info in sorted(index.items())[:50]:
        print(f"  {addr}  {info.get('name', 'unknown')}")

    if len(index) > 50:
        print(f"\n  ... and {len(index) - 50} more")
        print("\nUse 'ghidra-bridge search <pattern>' to find specific functions")

    return 0


def cmd_info(cfg: Config) -> int:
    """Show export statistics."""
    print("Ghidra Export Statistics")
    print("=" * 40)

    index = _load_index(cfg)
    print(f"Functions:    {len(index):,}")

    sample_file = None
    for f in glob.glob(os.path.join(cfg.export_dir, "*.json"))[:1]:
        if "_" not in os.path.basename(f):
            sample_file = f
            break

    if sample_file:
        with open(sample_file, "r") as f:
            sample = json.load(f)
        has_xrefs = "callers" in sample
        print(f"With xrefs:   {'Yes' if has_xrefs else 'No (run decompiled export with xrefs)'}")

    structs = load_json(cfg.structs_file)
    print(f"Structs:      {len(structs):,}")

    enums = load_json(cfg.enums_file)
    print(f"Enums:        {len(enums):,}")

    vtables = load_json(cfg.vtables_file)
    print(f"Vtables:      {len(vtables):,}")

    globals_data = load_json(cfg.globals_file)
    print(f"Globals:      {len(globals_data):,}")

    strings_data = load_json(cfg.strings_file)
    print(f"Strings:      {len(strings_data):,}")

    address_map = _load_address_map(cfg)
    print(f"Known funcs:  {len(address_map):,} (from address map)")

    if cfg.has_source:
        print()
        print("Source Code Data:")
        source_structs = load_json(cfg.source_structs_file)
        source_enums = load_json(cfg.source_enums_file)
        remaining = load_json(cfg.remaining_stubs_file)
        print(f"  Structs:    {len(source_structs):,} (with sizes)")
        print(f"  Enums:      {len(source_enums):,} (with values)")
        if remaining:
            print(f"  Remaining:  {remaining.get('total', 0):,} stubs to reverse")

    print()
    print(f"Export dir:   {cfg.export_dir}")

    return 0


def cmd_unimplemented(cfg: Config, filter_pattern: str | None = None) -> int:
    """List functions that exist in Ghidra but are not in the address map."""
    index = _load_index(cfg)
    address_map = _load_address_map(cfg)

    if not index:
        print("ERROR: No Ghidra export found. Run export scripts first.")
        return 1

    known_addrs = set()
    for addr in address_map.keys():
        known_addrs.add(normalize_address(addr))

    unimplemented = []
    for addr, info in index.items():
        addr_norm = normalize_address(addr)
        if addr_norm not in known_addrs:
            name = info.get("name", "unknown")
            if any(name.startswith(p) for p in ["_", "__", "??", "operator", "std::"]):
                continue
            num_callers = info.get("num_callers", 0)
            unimplemented.append((addr, name, num_callers))

    if filter_pattern:
        filter_lower = filter_pattern.lower()
        unimplemented = [(a, n, c) for a, n, c in unimplemented
                         if filter_lower in n.lower()]

    if not unimplemented:
        if filter_pattern:
            print(f"No unimplemented functions matching '{filter_pattern}'")
        else:
            print("All functions are implemented! (or filtered out)")
        return 0

    unimplemented.sort(key=lambda x: x[2], reverse=True)

    print(f"Unimplemented functions: {len(unimplemented)}")
    print(f"(Sorted by number of callers - most important first)\n")

    for addr, name, callers in unimplemented[:50]:
        caller_str = f"[{callers:3d} callers]" if callers > 0 else "[no callers]"
        print(f"  0x{addr}  {caller_str}  {name}")

    if len(unimplemented) > 50:
        print(f"\n  ... and {len(unimplemented) - 50} more")
        print("\n  Use 'ghidra-bridge unimplemented <pattern>' to filter")

    print("\n--- Summary by prefix ---")
    prefixes: dict[str, int] = {}
    for _, name, _ in unimplemented:
        if name.startswith("FUN_"):
            prefix = "FUN_* (unnamed)"
        elif "::" in name:
            prefix = name.split("::")[0]
        else:
            prefix = "(other)"
        prefixes[prefix] = prefixes.get(prefix, 0) + 1

    for prefix, count in sorted(prefixes.items(), key=lambda x: -x[1])[:15]:
        print(f"  {count:5d}  {prefix}")

    return 0


def cmd_source_struct(name: str, cfg: Config) -> int:
    """Query struct from reversed source (with actual sizes and field offsets)."""
    data = load_json(cfg.source_structs_file)
    if not data:
        print("ERROR: No source struct data. Run: ghidra-bridge export source-types")
        return 1

    if name in data:
        s = data[name]
        print(f"// Struct: {s['name']}")
        print(f"// Size:   {s['size_hex']} ({s['size_dec']} bytes)")
        print(f"// Source: {s['file']}")
        if 'fields' in s and s['fields']:
            print(f"// Known field offsets:")
            for fld in s['fields']:
                print(f"//   {fld['offset_hex']:>6}  {fld['field']}")
        return 0

    matches = [(k, v) for k, v in data.items() if name.lower() in k.lower()]
    if matches:
        print(f"Found {len(matches)} matching structs:\n")
        for k, v in sorted(matches, key=lambda x: x[0])[:30]:
            fields_count = len(v.get('fields', []))
            print(f"  {k:40} size={v['size_hex']:>6}  fields={fields_count}")
        if len(matches) > 30:
            print(f"  ... and {len(matches) - 30} more")
        return 0

    print(f"Struct not found: {name}")
    return 1


def cmd_source_enum(name: str, cfg: Config) -> int:
    """Query enum from reversed source (with actual values)."""
    data = load_json(cfg.source_enums_file)
    if not data:
        print("ERROR: No source enum data. Run: ghidra-bridge export source-types")
        return 1

    if name in data:
        e = data[name]
        print(f"// Enum: {e['name']}")
        print(f"// Source: {e['file']}")
        print(f"// Values: {len(e['values'])}")
        print()
        for v in e['values']:
            print(f"  {v['name']:40} = {v['value']:>6}  ({v['value_hex']})")
        return 0

    matches = [(k, v) for k, v in data.items() if name.lower() in k.lower()]
    if matches:
        print(f"Found {len(matches)} matching enums:\n")
        for k, v in sorted(matches, key=lambda x: x[0])[:30]:
            print(f"  {k:40} ({len(v['values'])} values)")
        if len(matches) > 30:
            print(f"  ... and {len(matches) - 30} more")
        return 0

    print(f"Enum not found: {name}")
    return 1


def cmd_containing(target: str, cfg: Config) -> int:
    """Find which function contains a given address (useful for crash debugging)."""
    json_files = glob.glob(os.path.join(cfg.export_dir, "[0-9a-f]*.json"))
    index = {}
    for f in json_files:
        basename = os.path.basename(f).replace(".json", "")
        if basename.startswith("_"):
            continue
        try:
            int(basename, 16)
            index[basename] = {"name": basename}
        except ValueError:
            continue

    if not index:
        print("ERROR: No function files found in export directory.")
        print("       Run decompiled export first.")
        return 1

    target_norm = normalize_address(target)
    target_int = int(target_norm, 16)

    func_addrs = []
    for addr in index.keys():
        try:
            addr_norm = normalize_address(addr)
            addr_int = int(addr_norm, 16)
            # Apply code range filter if configured
            if cfg.has_code_range:
                if not (cfg.code_range_min <= addr_int <= cfg.code_range_max):
                    continue
            func_addrs.append((addr_int, addr_norm))
        except ValueError:
            continue

    func_addrs.sort(key=lambda x: x[0])

    if not func_addrs:
        print("ERROR: No valid function addresses found")
        if cfg.has_code_range:
            print(f"       Code range: 0x{cfg.code_range_min:08x} - 0x{cfg.code_range_max:08x}")
        return 1

    containing_func = None
    next_func = None

    for i, (addr_int, addr_norm) in enumerate(func_addrs):
        if addr_int <= target_int:
            containing_func = (addr_int, addr_norm)
            if i + 1 < len(func_addrs):
                next_func = func_addrs[i + 1]
        else:
            if containing_func is None:
                print(f"// Address 0x{target_norm} is BEFORE first known function")
                print(f"// First function starts at 0x{addr_norm}")
                return 1
            break

    if containing_func is None:
        if func_addrs:
            containing_func = func_addrs[-1]
        else:
            print(f"ERROR: No function found containing 0x{target_norm}")
            return 1

    func_addr_int, func_addr_norm = containing_func
    offset = target_int - func_addr_int

    filepath = os.path.join(cfg.export_dir, f"{func_addr_norm}.json")
    if not os.path.exists(filepath):
        print(f"ERROR: Function file not found: {filepath}")
        return 1

    with open(filepath, "r") as f:
        data = json.load(f)

    known_name, source_file = get_known_name(data['address'], cfg)

    if next_func:
        next_addr_int, next_addr_norm = next_func
        func_span = next_addr_int - func_addr_int
        if offset > func_span:
            confidence = "LOW (offset exceeds gap to next function!)"
        elif offset > 0x1000:
            confidence = "MEDIUM (large offset - verify manually)"
        elif offset > 0x500:
            confidence = "MEDIUM-HIGH"
        else:
            confidence = "HIGH"
    else:
        if offset > 0x1000:
            confidence = "MEDIUM (large offset, no next function to verify)"
        else:
            confidence = "HIGH (last function in binary)"

    print(f"// ===========================================")
    print(f"// CONTAINING FUNCTION for 0x{target_norm}")
    print(f"// ===========================================")
    print(f"// Confidence:   {confidence}")
    print(f"// Offset:       +0x{offset:x} ({offset} bytes into function)")
    print(f"// ===========================================")
    if known_name:
        print(f"// Known as:     {known_name}")
        if source_file:
            if cfg.source_root:
                print(f"// Source:       {cfg.source_root}/{source_file}")
            else:
                print(f"// Source:       {source_file}")
    print(f"// Ghidra name:  {data['name']}")
    print(f"// Func start:   0x{func_addr_norm}")
    if next_func:
        print(f"// Next func:    0x{next_func[1]} (gap: 0x{next_func[0] - func_addr_int:x})")
    print(f"// Signature:    {data['signature']}")
    print(f"// ===========================================")
    print()
    print(data["decompiled"])
    return 0


def _scan_remaining_stubs_live(cfg: Config):
    """Scan the actual source tree for stub patterns (live, not cached)."""
    if not cfg.has_source:
        return None

    source_root = Path(cfg.source_root)
    stubs = []
    seen_files: set[Path] = set()

    for ext in cfg.file_extensions:
        for src_file in source_root.rglob(f"*{ext}"):
            if src_file in seen_files:
                continue
            seen_files.add(src_file)
            try:
                content = src_file.read_text(errors='ignore')
                for stub_pattern in cfg.stub_patterns:
                    for match in re.finditer(stub_pattern, content):
                        addr = match.group(1) if match.lastindex else "unknown"

                        # Find containing function name from context
                        start = max(0, match.start() - 500)
                        context = content[start:match.start()]
                        func_match = re.search(
                            r'(\w+::\w+)\s*\([^)]*\)\s*(?:const\s*)?\{[^}]*$',
                            context, re.DOTALL
                        )
                        func_name = func_match.group(1) if func_match else "unknown"

                        try:
                            rel_file = str(src_file.relative_to(source_root))
                        except ValueError:
                            rel_file = str(src_file)

                        stubs.append({
                            "function": func_name,
                            "address": addr,
                            "file": rel_file,
                        })
            except Exception:
                pass

    by_class = defaultdict(int)
    for stub in stubs:
        cls = stub["function"].split("::")[0] if "::" in stub["function"] else "Other"
        by_class[cls] += 1

    return {"total": len(stubs), "by_class": dict(by_class), "stubs": stubs}


def cmd_remaining(cfg: Config, filter_pattern: str | None = None) -> int:
    """Show remaining stubs to reverse (live scan of source tree)."""
    data = _scan_remaining_stubs_live(cfg)
    if data is None:
        data = load_json(cfg.remaining_stubs_file)
    if not data:
        print("ERROR: No remaining stubs data and source tree not found.")
        return 1

    total = data.get('total', 0)
    by_class = data.get('by_class', {})
    stubs = data.get('stubs', [])

    if filter_pattern:
        pattern = filter_pattern.lower()
        filtered = [s for s in stubs if pattern in s['function'].lower() or pattern in s['file'].lower()]
        print(f"// Remaining stubs matching '{filter_pattern}': {len(filtered)}")
        print()
        for s in filtered[:50]:
            print(f"    {s['address']:>10}  {s['function']:40}  {s['file']}")
        if len(filtered) > 50:
            print(f"  ... and {len(filtered) - 50} more")
    else:
        print(f"// Total remaining stubs: {total}")
        print()
        print("By class (top 20):")
        for class_name, count in sorted(by_class.items(), key=lambda x: -x[1])[:20]:
            print(f"  {class_name:40} {count:>4} stubs")
        print()
        print("Use 'ghidra-bridge remaining <class>' to see specific stubs")

    return 0
