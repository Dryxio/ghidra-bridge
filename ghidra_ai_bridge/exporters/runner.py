"""PyGhidra headless runner for export scripts.

Provides both the headless orchestration (run_export) and the individual
export functions that run inside the Ghidra environment.
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra_ai_bridge.config import Config


def _ensure_output_dir(cfg: Config) -> None:
    os.makedirs(cfg.export_dir, exist_ok=True)


# ---------------------------------------------------------------------------
# Export functions (run inside PyGhidra context)
# ---------------------------------------------------------------------------

def export_structs(dtm, output_dir: str) -> None:
    """Export all struct/class definitions from Ghidra data type manager."""
    structs = {}
    enums = {}
    typedefs = {}

    print("[ExportStructs] Scanning data types...")

    for dt in dtm.getAllDataTypes():
        dt_name = dt.getName()
        dt_path = str(dt.getCategoryPath())

        # Handle Structures
        try:
            num_components = dt.getNumComponents()
            fields = []
            for i in range(num_components):
                comp = dt.getComponent(i)
                if comp:
                    field_name = comp.getFieldName()
                    if field_name is None:
                        field_name = f"field_0x{comp.getOffset():x}"
                    fields.append({
                        "offset": comp.getOffset(),
                        "name": field_name,
                        "type": str(comp.getDataType().getName()),
                        "size": comp.getLength(),
                        "comment": comp.getComment(),
                    })

            if fields:
                structs[dt_name] = {
                    "name": dt_name,
                    "path": dt_path,
                    "size": dt.getLength(),
                    "fields": fields,
                }
            continue
        except Exception:
            pass

        # Handle Enums
        try:
            names = list(dt.getNames())
            if names:
                values = []
                for name in names:
                    values.append({
                        "name": name,
                        "value": int(dt.getValue(name)),
                    })
                enums[dt_name] = {
                    "name": dt_name,
                    "path": dt_path,
                    "size": dt.getLength(),
                    "values": values,
                }
            continue
        except Exception:
            pass

        # Handle TypeDefs
        try:
            base = dt.getBaseDataType()
            if base:
                typedefs[dt_name] = {
                    "name": dt_name,
                    "path": dt_path,
                    "base_type": str(base.getName()),
                    "size": dt.getLength(),
                }
        except Exception:
            pass

    with open(os.path.join(output_dir, "_structs.json"), "w") as f:
        json.dump(structs, f, indent=2)
    print(f"Exported {len(structs)} structs")

    with open(os.path.join(output_dir, "_enums.json"), "w") as f:
        json.dump(enums, f, indent=2)
    print(f"Exported {len(enums)} enums")

    with open(os.path.join(output_dir, "_typedefs.json"), "w") as f:
        json.dump(typedefs, f, indent=2)
    print(f"Exported {len(typedefs)} typedefs")


def export_vtables(program, fm, sm, mem, output_dir: str) -> None:
    """Export virtual function tables."""
    vtables = {}
    print("[ExportVtables] Scanning for vtables...")

    for symbol in sm.getAllSymbols(True):
        name = symbol.getName()

        is_vtable = False
        class_name = None

        if name.startswith("??_7") and "@@6B" in name:
            is_vtable = True
            match = re.match(r'\?\?_7(\w+)@@', name)
            if match:
                class_name = match.group(1)
        elif "vftable" in name.lower() or "vtable" in name.lower():
            is_vtable = True
            class_name = name.replace("vftable", "").replace("vtable", "").replace("_", "").strip()
        elif name.startswith("vtable_"):
            is_vtable = True
            class_name = name[7:]

        if not is_vtable:
            continue

        addr = symbol.getAddress()
        entries = []
        ptr_size = program.getDefaultPointerSize()

        for i in range(100):
            try:
                entry_addr = addr.add(i * ptr_size)
                if ptr_size == 4:
                    ptr_val = mem.getInt(entry_addr) & 0xFFFFFFFF
                else:
                    ptr_val = mem.getLong(entry_addr) & 0xFFFFFFFFFFFFFFFF

                func_addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(ptr_val)
                func = fm.getFunctionAt(func_addr)

                if func:
                    entries.append({
                        "index": i,
                        "offset": i * ptr_size,
                        "address": str(func_addr),
                        "name": func.getName(),
                        "signature": str(func.getSignature()),
                    })
                else:
                    if i > 0:
                        break
            except Exception:
                break

        if entries:
            vtables[name] = {
                "symbol": name,
                "class_name": class_name,
                "address": str(addr),
                "entry_count": len(entries),
                "entries": entries,
            }

    with open(os.path.join(output_dir, "_vtables.json"), "w") as f:
        json.dump(vtables, f, indent=2)
    print(f"Exported {len(vtables)} vtables")


def export_strings(listing, ref_mgr, fm, output_dir: str) -> None:
    """Export strings and their references."""
    strings_data = {}
    refs_by_function = {}
    print("[ExportStrings] Scanning for strings...")

    count = 0
    for data in listing.getDefinedData(True):
        dt = data.getDataType()
        dt_name = dt.getName().lower()

        if "string" not in dt_name and "char[" not in dt_name:
            continue

        addr = data.getAddress()

        try:
            value = str(data.getValue())
            if not value or len(value) < 2:
                continue
            if not any(c.isalpha() for c in value):
                continue
        except Exception:
            continue

        refs = []
        for ref in ref_mgr.getReferencesTo(addr):
            from_addr = ref.getFromAddress()
            func = fm.getFunctionContaining(from_addr)
            if func:
                func_addr = str(func.getEntryPoint())
                refs.append({
                    "func_addr": func_addr,
                    "func_name": func.getName(),
                    "ref_addr": str(from_addr),
                })
                refs_by_function.setdefault(func_addr, []).append(str(addr))

        strings_data[str(addr)] = {
            "address": str(addr),
            "value": value,
            "length": len(value),
            "type": str(dt.getName()),
            "references": refs,
        }

        count += 1
        if count % 1000 == 0:
            print(f"Processed {count} strings...")

    search_index = {}
    for addr, info in strings_data.items():
        value_lower = info["value"].lower()
        for word in value_lower.split():
            if len(word) >= 3:
                if word not in search_index:
                    search_index[word] = []
                search_index[word].append(addr)

    with open(os.path.join(output_dir, "_strings.json"), "w") as f:
        json.dump(strings_data, f, indent=2)
    with open(os.path.join(output_dir, "_strings_index.json"), "w") as f:
        json.dump(search_index, f, indent=2)
    with open(os.path.join(output_dir, "_string_refs_by_function.json"), "w") as f:
        json.dump(refs_by_function, f, indent=2)
    print(f"Exported {len(strings_data)} strings")


def export_globals(sm, listing, ref_mgr, fm, mem, output_dir: str) -> None:
    """Export global variables."""
    globals_data = {}
    refs_by_function = {}
    print("[ExportGlobals] Scanning for global variables...")

    data_blocks = []
    for block in mem.getBlocks():
        name = block.getName().lower()
        if "data" in name or "bss" in name or "rdata" in name:
            data_blocks.append(block)

    count = 0
    for block in data_blocks:
        data_iter = listing.getDefinedData(block.getStart(), True)

        while data_iter.hasNext():
            data = data_iter.next()
            if not block.contains(data.getAddress()):
                break

            addr = data.getAddress()
            sym = sm.getPrimarySymbol(addr)
            name = sym.getName() if sym else None

            if not name or name.startswith("DAT_") or name.startswith("BYTE_"):
                continue

            dt = data.getDataType()

            refs = []
            for ref in ref_mgr.getReferencesTo(addr):
                from_addr = ref.getFromAddress()
                func = fm.getFunctionContaining(from_addr)
                if func:
                    func_addr = str(func.getEntryPoint())
                    refs.append({
                        "func_addr": func_addr,
                        "func_name": func.getName(),
                    })
                    refs_by_function.setdefault(func_addr, []).append(str(addr))
            refs = refs[:20]

            value = None
            try:
                if dt.getLength() <= 8:
                    value = str(data.getValue())
            except Exception:
                pass

            globals_data[str(addr)] = {
                "address": str(addr),
                "name": name,
                "type": str(dt.getName()),
                "size": dt.getLength(),
                "value": value,
                "section": block.getName(),
                "references": refs,
            }

            count += 1
            if count % 1000 == 0:
                print(f"Processed {count} globals...")

    with open(os.path.join(output_dir, "_globals.json"), "w") as f:
        json.dump(globals_data, f, indent=2)
    with open(os.path.join(output_dir, "_global_refs_by_function.json"), "w") as f:
        json.dump(refs_by_function, f, indent=2)
    print(f"Exported {len(globals_data)} globals")


def export_decompiled(program, fm, ref_mgr, output_dir: str, listing=None) -> None:
    """Export decompiled functions with cross-references."""
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    decomp = DecompInterface()
    decomp.openProgram(program)
    ir_decomp = DecompInterface()
    ir_decomp.setSimplificationStyle("normalize")
    ir_decomp.openProgram(program)
    monitor = ConsoleTaskMonitor()

    functions = list(fm.getFunctions(True))
    total = len(functions)

    print(f"[ExportDecompiled] Exporting {total} functions with xrefs...")

    index = {}

    for i, func in enumerate(functions):
        if i % 500 == 0:
            print(f"Progress: {i}/{total} ({100*i//total}%)")

        addr = str(func.getEntryPoint())
        name = func.getName()

        callers = []
        for ref in ref_mgr.getReferencesTo(func.getEntryPoint()):
            from_addr = ref.getFromAddress()
            caller_func = fm.getFunctionContaining(from_addr)
            if caller_func and caller_func != func:
                callers.append({
                    "addr": str(caller_func.getEntryPoint()),
                    "name": caller_func.getName(),
                    "ref_type": str(ref.getReferenceType()),
                })

        callees = []
        seen_callees = set()
        body = func.getBody()
        for addr_range in body:
            addr_iter = addr_range.getMinAddress()
            while addr_iter and addr_iter.compareTo(addr_range.getMaxAddress()) <= 0:
                for ref in ref_mgr.getReferencesFrom(addr_iter):
                    if ref.getReferenceType().isCall():
                        to_addr = ref.getToAddress()
                        callee_func = fm.getFunctionAt(to_addr)
                        if callee_func and str(callee_func.getEntryPoint()) not in seen_callees:
                            seen_callees.add(str(callee_func.getEntryPoint()))
                            callees.append({
                                "addr": str(callee_func.getEntryPoint()),
                                "name": callee_func.getName(),
                            })
                addr_iter = addr_iter.next()

        index[addr] = {
            "name": name,
            "address": addr,
            "num_callers": len(callers),
            "num_callees": len(callees),
        }

        high_pcode = []
        cfg_blocks = []
        pcode_errors = []
        cfg_errors = []
        assembly = []
        if listing is not None:
            try:
                assembly = [
                    f"{instruction.getAddress()}  {instruction}"
                    for instruction in listing.getInstructions(func.getBody(), True)
                ]
            except Exception:
                assembly = []
        try:
            result = decomp.decompileFunction(func, 60, monitor)
            if result.decompileCompleted():
                c_code = result.getDecompiledFunction().getC()
            else:
                c_code = "// Decompilation failed"
        except Exception as e:
            c_code = f"// Error: {e}"
        try:
            ir_result = ir_decomp.decompileFunction(func, 60, monitor)
            if ir_result.decompileCompleted():
                high_pcode, cfg_blocks, pcode_errors, cfg_errors = _extract_high_ir(
                    ir_result
                )
            else:
                pcode_errors = ["Normalized IR decompilation failed"]
                cfg_errors = ["Normalized IR decompilation failed"]
        except Exception as e:
            pcode_errors = [f"Normalized IR error: {e}"]
            cfg_errors = [f"Normalized IR error: {e}"]

        func_data = {
            "address": addr,
            "name": name,
            "signature": str(func.getSignature()),
            "calling_convention": str(func.getCallingConventionName()),
            "return_type": str(func.getReturnType()),
            "parameter_count": func.getParameterCount(),
            "is_thunk": func.isThunk(),
            "decompiled": c_code,
            "callers": callers,
            "callees": callees,
            "data_refs": [],
            "pcode": high_pcode,
            "cfg": cfg_blocks,
            "pcode_errors": pcode_errors,
            "cfg_errors": cfg_errors,
            "assembly": assembly,
        }

        safe_addr = addr.replace(":", "_")
        filepath = os.path.join(output_dir, f"{safe_addr}.json")

        with open(filepath, "w") as f:
            json.dump(func_data, f, indent=2)

    with open(os.path.join(output_dir, "_index.json"), "w") as f:
        json.dump(index, f, indent=2)

    print(f"[ExportDecompiled] Complete! {total} functions exported")


def _extract_high_ir(
    result,
) -> tuple[list[dict], list[dict], list[str], list[str]]:
    """Extract normalized high P-code operations and CFG edges."""
    operations = []
    blocks = []
    pcode_errors = []
    cfg_errors = []
    try:
        high = result.getHighFunction()
    except Exception as exc:
        message = str(exc)
        return ([], [], [message], [message])
    if high is None:
        message = "Decompiler returned no HighFunction"
        return ([], [], [message], [message])
    try:
        iterator = high.getPcodeOps()
        while iterator.hasNext():
            op = iterator.next()
            output = op.getOutput()
            operations.append({
                "seq": str(op.getSeqnum()),
                "address": str(op.getSeqnum().getTarget()),
                "opcode": str(op.getMnemonic()),
                "output": str(output) if output is not None else None,
                "inputs": [str(op.getInput(i)) for i in range(op.getNumInputs())],
            })

    except Exception as exc:
        pcode_errors.append(f"P-code extraction failed: {exc}")
    try:
        for block in high.getBasicBlocks():
            blocks.append({
                "index": int(block.getIndex()),
                "start": str(block.getStart()),
                "stop": str(block.getStop()),
                "out": [int(block.getOut(i).getIndex()) for i in range(block.getOutSize())],
                "in": [int(block.getIn(i).getIndex()) for i in range(block.getInSize())],
            })
    except Exception as exc:
        cfg_errors.append(f"CFG extraction failed: {exc}")
    return operations, blocks, pcode_errors, cfg_errors


def create_known_functions(flat_api, program, fm, listing, address_map_path: str) -> int:
    """Create functions at known addresses that Ghidra missed."""
    from ghidra.program.model.symbol import SourceType

    if not os.path.exists(address_map_path):
        print(f"ERROR: {address_map_path} not found")
        return 0

    with open(address_map_path, "r") as f:
        address_map = json.load(f)

    addr_factory = program.getAddressFactory()

    created = 0
    skipped = 0
    errors = 0

    total = len(address_map)
    print(f"[CreateKnownFunctions] Processing {total} known addresses...")

    for i, (addr_str, info) in enumerate(sorted(address_map.items())):
        if i % 500 == 0:
            print(f"Progress: {i}/{total} ({100*i//total}%) - Created: {created}, Skipped: {skipped}, Errors: {errors}")

        if addr_str == "00000000" or addr_str == "0" or not addr_str:
            skipped += 1
            continue

        try:
            addr_hex = addr_str.lstrip("0x").zfill(8)
            addr = addr_factory.getAddress("0x" + addr_hex)
            if addr is None:
                errors += 1
                continue

            existing = fm.getFunctionAt(addr)
            if existing:
                skipped += 1
                continue

            full_name = info.get("full_name", f"FUN_{addr_hex}")

            flat_api.disassemble(addr)
            func = flat_api.createFunction(addr, full_name)
            if func:
                created += 1
            else:
                errors += 1
                if errors <= 10:
                    print(f"  Failed to create function at 0x{addr_hex}: {full_name}")

        except Exception as e:
            errors += 1
            if errors <= 10:
                print(f"  Error at {addr_str}: {e}")

    print(f"\n[CreateKnownFunctions] Complete!")
    print(f"  Created:  {created}")
    print(f"  Skipped:  {skipped} (already exist)")
    print(f"  Errors:   {errors}")

    return created


# ---------------------------------------------------------------------------
# Top-level runner
# ---------------------------------------------------------------------------

def run_export(export_type: str, cfg: Config) -> int:
    """Run Ghidra export scripts via PyGhidra headless mode. Returns exit code."""
    try:
        import pyghidra
    except ImportError:
        # For source-types, we don't need pyghidra
        if export_type == "source-types":
            from ghidra_ai_bridge.source_types import export_source_types
            return export_source_types(cfg)
        print("ERROR: pyghidra is required for Ghidra exports. Install with: pip install ghidra-ai-bridge[headless]")
        return 1

    if export_type == "source-types":
        from ghidra_ai_bridge.source_types import export_source_types
        return export_source_types(cfg)

    _ensure_output_dir(cfg)

    if cfg.ghidra_install_dir:
        os.environ['GHIDRA_INSTALL_DIR'] = cfg.ghidra_install_dir

    print("Starting PyGhidra headless mode...")
    print(f"Project: {cfg.ghidra_project_dir}/{cfg.ghidra_project_name}")
    print(f"Program: {cfg.ghidra_program_name}")
    print()

    pyghidra.start(verbose=True)

    with pyghidra.open_program(
        None,
        project_location=cfg.ghidra_project_dir,
        project_name=cfg.ghidra_project_name,
        program_name=cfg.ghidra_program_name,
        analyze=False,
        nested_project_location=False,
    ) as flat_api:
        program = flat_api.getCurrentProgram()

        fm = program.getFunctionManager()
        sm = program.getSymbolTable()
        mem = program.getMemory()
        listing = program.getListing()
        ref_mgr = program.getReferenceManager()
        dtm = program.getDataTypeManager()

        output_dir = cfg.export_dir

        if export_type == "all":
            export_structs(dtm, output_dir)
            export_vtables(program, fm, sm, mem, output_dir)
            export_strings(listing, ref_mgr, fm, output_dir)
            export_globals(sm, listing, ref_mgr, fm, mem, output_dir)
            export_decompiled(program, fm, ref_mgr, output_dir, listing)
        elif export_type == "structs":
            export_structs(dtm, output_dir)
        elif export_type == "vtables":
            export_vtables(program, fm, sm, mem, output_dir)
        elif export_type == "strings":
            export_strings(listing, ref_mgr, fm, output_dir)
        elif export_type == "globals":
            export_globals(sm, listing, ref_mgr, fm, mem, output_dir)
        elif export_type == "decompiled":
            export_decompiled(program, fm, ref_mgr, output_dir, listing)
        elif export_type == "create-functions":
            created = create_known_functions(flat_api, program, fm, listing, cfg.address_map_path)
            if created > 0:
                print(f"\nRe-exporting decompiled functions to include the new ones...")
                export_decompiled(program, fm, ref_mgr, output_dir, listing)
        elif export_type == "fix-all":
            print("=== STEP 1: Creating missing functions ===")
            create_known_functions(flat_api, program, fm, listing, cfg.address_map_path)
            print("\n=== STEP 2: Re-exporting all data ===")
            export_structs(dtm, output_dir)
            export_vtables(program, fm, sm, mem, output_dir)
            export_strings(listing, ref_mgr, fm, output_dir)
            export_globals(sm, listing, ref_mgr, fm, mem, output_dir)
            export_decompiled(program, fm, ref_mgr, output_dir, listing)
        else:
            print(f"Unknown export type: {export_type}")
            return 1

    print("\nExport complete!")
    return 0
