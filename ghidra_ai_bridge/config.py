"""Configuration loader with layered priority: CLI args > env vars > YAML > defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from ghidra_ai_bridge.patterns import defaults as pattern_defaults


CONFIG_FILENAMES = [
    "ghidra-bridge.yaml",
    "ghidra-bridge.yml",
]

GLOBAL_CONFIG_DIR = Path.home() / ".config" / "ghidra-bridge"


@dataclass
class Config:
    """Layered configuration for ghidra-ai-bridge."""

    # Ghidra installation
    ghidra_install_dir: str = ""
    ghidra_project_dir: str = ""
    ghidra_project_name: str = ""
    ghidra_program_name: str = ""

    # Paths
    export_dir: str = ""
    address_map_path: str = ""

    # Source code integration (optional)
    source_root: str = ""
    hook_patterns: list[str] = field(default_factory=lambda: list(pattern_defaults.HOOK_PATTERNS))
    stub_patterns: list[str] = field(default_factory=lambda: list(pattern_defaults.STUB_PATTERNS))
    class_macro: str = pattern_defaults.CLASS_MACRO
    validate_size_macro: str = pattern_defaults.VALIDATE_SIZE_MACRO
    validate_offset_macro: str = pattern_defaults.VALIDATE_OFFSET_MACRO
    stub_markers: list[str] = field(default_factory=lambda: list(pattern_defaults.STUB_MARKERS))
    file_extensions: list[str] = field(default_factory=lambda: list(pattern_defaults.FILE_EXTENSIONS))

    # Binary code range (optional, for containing-address lookups)
    code_range_min: Optional[int] = None
    code_range_max: Optional[int] = None

    # Derived paths (computed from above)
    @property
    def index_file(self) -> str:
        return os.path.join(self.export_dir, "_index.json")

    @property
    def structs_file(self) -> str:
        return os.path.join(self.export_dir, "_structs.json")

    @property
    def enums_file(self) -> str:
        return os.path.join(self.export_dir, "_enums.json")

    @property
    def vtables_file(self) -> str:
        return os.path.join(self.export_dir, "_vtables.json")

    @property
    def globals_file(self) -> str:
        return os.path.join(self.export_dir, "_globals.json")

    @property
    def strings_file(self) -> str:
        return os.path.join(self.export_dir, "_strings.json")

    @property
    def strings_index_file(self) -> str:
        return os.path.join(self.export_dir, "_strings_index.json")

    @property
    def string_refs_by_function_file(self) -> str:
        return os.path.join(self.export_dir, "_string_refs_by_function.json")

    @property
    def global_refs_by_function_file(self) -> str:
        return os.path.join(self.export_dir, "_global_refs_by_function.json")

    @property
    def source_structs_file(self) -> str:
        return os.path.join(self.export_dir, "_source_structs.json")

    @property
    def source_enums_file(self) -> str:
        return os.path.join(self.export_dir, "_source_enums.json")

    @property
    def remaining_stubs_file(self) -> str:
        return os.path.join(self.export_dir, "_remaining_stubs.json")

    @property
    def has_source(self) -> bool:
        return bool(self.source_root) and os.path.isdir(self.source_root)

    @property
    def has_code_range(self) -> bool:
        return self.code_range_min is not None and self.code_range_max is not None


def _expand(path: str) -> str:
    """Expand ~ and env vars in a path string."""
    if not path:
        return path
    return os.path.expandvars(os.path.expanduser(path))


def _parse_hex_or_int(value) -> Optional[int]:
    """Parse a hex string (0x...) or int."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    s = str(value).strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s)


def _find_config_file(start_dir: Optional[str] = None) -> Optional[Path]:
    """Search for config file in current dir, then global config dir."""
    search_dir = Path(start_dir) if start_dir else Path.cwd()

    # Check local directory
    for name in CONFIG_FILENAMES:
        candidate = search_dir / name
        if candidate.is_file():
            return candidate

    # Check global config directory
    for name in CONFIG_FILENAMES:
        candidate = GLOBAL_CONFIG_DIR / name
        if candidate.is_file():
            return candidate

    return None


def load_config(
    config_path: Optional[str] = None,
    cli_overrides: Optional[dict] = None,
) -> Config:
    """Load configuration with priority: CLI args > env vars > YAML > defaults.

    Args:
        config_path: Explicit path to config file. If None, searches automatically.
        cli_overrides: Dict of CLI-provided overrides (e.g. {"export_dir": "/path"}).

    Returns:
        Fully resolved Config instance.
    """
    cfg = Config()

    # --- Layer 1: YAML file ---
    yaml_path = Path(config_path) if config_path else _find_config_file()
    if yaml_path and yaml_path.is_file():
        with open(yaml_path, "r") as f:
            data = yaml.safe_load(f) or {}
        _apply_yaml(cfg, data)

    # --- Layer 2: Environment variables ---
    _apply_env(cfg)

    # --- Layer 3: CLI overrides ---
    if cli_overrides:
        _apply_cli(cfg, cli_overrides)

    # --- Expand all paths ---
    cfg.ghidra_install_dir = _expand(cfg.ghidra_install_dir)
    cfg.ghidra_project_dir = _expand(cfg.ghidra_project_dir)
    cfg.export_dir = _expand(cfg.export_dir)
    cfg.address_map_path = _expand(cfg.address_map_path)
    cfg.source_root = _expand(cfg.source_root)

    # --- Derive defaults if not set ---
    if not cfg.export_dir:
        cfg.export_dir = os.path.expanduser("~/.ghidra-exports")
    if not cfg.address_map_path:
        cfg.address_map_path = os.path.join(cfg.export_dir, "address_map.json")

    return cfg


def _apply_yaml(cfg: Config, data: dict) -> None:
    """Apply YAML config data to Config."""
    ghidra = data.get("ghidra", {})
    if ghidra:
        cfg.ghidra_install_dir = ghidra.get("install_dir", cfg.ghidra_install_dir)
        cfg.ghidra_project_dir = ghidra.get("project_dir", cfg.ghidra_project_dir)
        cfg.ghidra_project_name = ghidra.get("project_name", cfg.ghidra_project_name)
        cfg.ghidra_program_name = ghidra.get("program_name", cfg.ghidra_program_name)

    paths = data.get("paths", {})
    if paths:
        cfg.export_dir = paths.get("export_dir", cfg.export_dir)
        cfg.address_map_path = paths.get("address_map", cfg.address_map_path)

    source = data.get("source", {})
    if source:
        cfg.source_root = source.get("root", cfg.source_root)
        if "hook_patterns" in source:
            cfg.hook_patterns = source["hook_patterns"]
        if "stub_patterns" in source:
            cfg.stub_patterns = source["stub_patterns"]
        if "class_macro" in source:
            cfg.class_macro = source["class_macro"]
        if "validate_size_macro" in source:
            cfg.validate_size_macro = source["validate_size_macro"]
        if "validate_offset_macro" in source:
            cfg.validate_offset_macro = source["validate_offset_macro"]
        if "stub_markers" in source:
            cfg.stub_markers = source["stub_markers"]
        if "file_extensions" in source:
            cfg.file_extensions = source["file_extensions"]

    binary = data.get("binary", {})
    if binary:
        if "code_range_min" in binary:
            cfg.code_range_min = _parse_hex_or_int(binary["code_range_min"])
        if "code_range_max" in binary:
            cfg.code_range_max = _parse_hex_or_int(binary["code_range_max"])


def _apply_env(cfg: Config) -> None:
    """Apply environment variable overrides."""
    env_map = {
        "GHIDRA_INSTALL_DIR": "ghidra_install_dir",
        "GHIDRA_PROJECT_DIR": "ghidra_project_dir",
        "GHIDRA_PROJECT_NAME": "ghidra_project_name",
        "GHIDRA_PROGRAM_NAME": "ghidra_program_name",
        "GHIDRA_EXPORT_DIR": "export_dir",
    }
    for env_key, attr in env_map.items():
        val = os.environ.get(env_key)
        if val:
            setattr(cfg, attr, val)


def _apply_cli(cfg: Config, overrides: dict) -> None:
    """Apply CLI argument overrides."""
    mapping = {
        "config": None,  # handled separately
        "export_dir": "export_dir",
        "source_root": "source_root",
        "ghidra_install_dir": "ghidra_install_dir",
        "ghidra_project_dir": "ghidra_project_dir",
        "ghidra_project_name": "ghidra_project_name",
        "ghidra_program_name": "ghidra_program_name",
    }
    for key, attr in mapping.items():
        if attr and key in overrides and overrides[key]:
            setattr(cfg, attr, overrides[key])
