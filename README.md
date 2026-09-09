# Ghidra Bridge

Give your AI access to Ghidra’s program analysis.

Ghidra Bridge provides a CLI and Python API that lets AI agents (or humans) query Ghidra project data — decompiled code, structs, enums, vtables, cross-references, strings, and more — without running Ghidra interactively.

## Get started with your AI

**Give your AI this repo and tell it what you want to do.** It can check your setup, install the tools it needs, and walk you through anything that needs your help. Use an AI coding agent that can access files and run commands on your computer.

Copy this into your agent:

> Help me set up https://github.com/Dryxio/ghidra-ai-bridge. Read the README, check what's already installed on my computer, and help me install and configure the bridge, Ghidra, and any missing requirements. Ask me which program or existing Ghidra project I want to explore. Then get the bridge working and use it to explain one small function in plain language, showing the code and evidence behind your explanation.

Bring a program you want to understand, or an existing Ghidra project. Your agent can help prepare it for analysis.

## Features

- **Query decompiled code** by address or function name
- **Cross-reference lookup** — callers and callees
- **Struct/enum/vtable** inspection from Ghidra exports
- **String search** with reference tracking
- **Address map** integration for reversed source code
- **Source type extraction** — struct sizes, enum values from `VALIDATE_SIZE` / `VALIDATE_OFFSET` macros
- **Remaining stub tracking** — find unreversed functions
- **Crash debugging** — find which function contains a given address
- **Configurable** — works with any Ghidra project via YAML config
- **Headless export** — PyGhidra-based bulk export scripts
- **Normalized IR evidence** — high P-code and CFG exports per function
- **Function context bundles** — machine-readable callees, strings, globals, and CFG

## Manual setup

Prefer to install it yourself? Expand the instructions below.

<details>
<summary>Manual installation, configuration and examples</summary>

## Installation

```bash
pip install ghidra-ai-bridge
```

For headless Ghidra export support:

```bash
pip install ghidra-ai-bridge[headless]
```

## Quick Start

```bash
# Interactive setup
ghidra-bridge init

# Export data from Ghidra project (requires pyghidra)
ghidra-bridge export all

# Build address map from reversed source
ghidra-bridge build-map

# Query
ghidra-bridge decompile 0x401000
ghidra-bridge search CPed
ghidra-bridge xrefs-to 0x5fb010
ghidra-bridge struct CEntity
ghidra-bridge info
```

## Configuration

Create a `ghidra-bridge.yaml` in your project root:

```yaml
ghidra:
  install_dir: ~/Downloads/ghidra_12.0.1_PUBLIC
  project_dir: ~/Documents/Ghidra
  project_name: my-project
  program_name: target.exe

paths:
  export_dir: .ghidra-exports
  address_map: .ghidra-exports/address_map.json

source:                                   # optional
  root: ./source
  hook_patterns:
    - 'RH_ScopedInstall\s*\(\s*(\w+)\s*,\s*(0x[0-9A-Fa-f]+)'
  stub_patterns:
    - 'plugin::Call\w*<[^>]*(0x[0-9A-Fa-f]+)[^>]*>'

binary:                                   # optional
  code_range_min: 0x00401000
  code_range_max: 0x00900000
```

Config priority: CLI args > environment variables > YAML file > defaults.

Environment variables: `GHIDRA_INSTALL_DIR`, `GHIDRA_PROJECT_DIR`, `GHIDRA_PROJECT_NAME`, `GHIDRA_PROGRAM_NAME`, `GHIDRA_EXPORT_DIR`.

</details>

## Commands

| Command | Description |
|---------|-------------|
| `init` | Interactive setup wizard |
| `export <type>` | Run Ghidra export (all, structs, decompiled, vtables, globals, strings, source-types) |
| `build-map` | Build address map from source |
| `decompile <addr\|name>` | Show decompiled code |
| `search <pattern>` | Search function names |
| `xrefs-to <addr\|name>` | Show callers |
| `xrefs-from <addr\|name>` | Show callees |
| `struct <name>` | Show Ghidra struct definition |
| `enum <name>` | Show Ghidra enum values |
| `vtable <class>` | Show virtual function table |
| `global <addr\|name>` | Show global variable info |
| `strings <pattern>` | Search strings |
| `containing <addr>` | Find function containing address |
| `decompile-class <class>` | Decompile all class methods |
| `context <addr\|name>` | Export a JSON evidence bundle for a function |
| `pcode <addr\|name>` | Show normalized high P-code JSON |
| `cfg <addr\|name>` | Show control-flow graph JSON |
| `asm <addr\|name>` | Show assembly captured during decompiled export |
| `unimplemented [pattern]` | List unimplemented functions |
| `remaining [class]` | Show remaining stubs |
| `source-struct <name>` | Query struct from source |
| `source-enum <name>` | Query enum from source |
| `dump-asm <addr> <output>` | Dump assembly (requires pyghidra) |
| `info` | Show export statistics |
| `list` | List all functions |

## License

MIT
