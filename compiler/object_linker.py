"""
Native Object Linker & Symbol Relocation Engine
Combines relocatable object modules from separate repositories into unified native executables
and shared libraries (DLL / SO) by resolving cross-module symbols and applying relocations.
Supports:
- IMAGE_REL_AMD64_REL32 / R_X86_64_PC32 (32-bit relative displacement for calls)
- IMAGE_REL_AMD64_ADDR64 / R_X86_64_64 (64-bit absolute virtual addresses)
"""

import struct
from typing import Dict, List, Tuple, Any, Optional
from compiler.binary_emitter import StandaloneBinaryEmitter


class SymbolDef:
    __slots__ = ("name", "section", "offset", "size", "is_exported", "source_repo")

    def __init__(
        self,
        name: str,
        section: str = ".text",
        offset: int = 0,
        size: int = 0,
        is_exported: bool = True,
        source_repo: str = ""
    ):
        self.name = name
        self.section = section
        self.offset = offset
        self.size = size
        self.is_exported = is_exported
        self.source_repo = source_repo

    def __repr__(self) -> str:
        return f"SymbolDef({self.name}@{self.section}+{self.offset}, repo={self.source_repo})"


class RelocationEntry:
    __slots__ = ("section", "offset", "symbol_name", "reloc_type", "addend")

    def __init__(
        self,
        section: str,
        offset: int,
        symbol_name: str,
        reloc_type: str = "REL32",  # "REL32" or "ADDR64"
        addend: int = 0
    ):
        self.section = section
        self.offset = offset
        self.symbol_name = symbol_name
        self.reloc_type = reloc_type
        self.addend = addend

    def __repr__(self) -> str:
        return f"Reloc({self.reloc_type} -> {self.symbol_name} at {self.section}+{self.offset})"


class ObjectModule:
    """Represents a compiled relocatable object from a single repository."""

    def __init__(self, repo_name: str):
        self.repo_name = repo_name
        self.text_bytes = bytearray()
        self.data_bytes = bytearray()
        self.symbols: Dict[str, SymbolDef] = {}
        self.relocations: List[RelocationEntry] = []

    def add_symbol(self, name: str, code: bytes, is_exported: bool = True) -> SymbolDef:
        offset = len(self.text_bytes)
        self.text_bytes.extend(code)
        sym = SymbolDef(
            name=name,
            section=".text",
            offset=offset,
            size=len(code),
            is_exported=is_exported,
            source_repo=self.repo_name
        )
        self.symbols[name] = sym
        return sym

    def add_call_relocation(self, offset_in_text: int, target_symbol: str):
        """Records a 32-bit relative call relocation slot (e.g. at E8 <disp32>)."""
        self.relocations.append(RelocationEntry(
            section=".text",
            offset=offset_in_text,
            symbol_name=target_symbol,
            reloc_type="REL32"
        ))


class NativeObjectLinker:
    """
    Combines and resolves multiple ObjectModules into a fully linked binary artifact.
    """

    def __init__(self):
        self.modules: List[ObjectModule] = []
        self.emitter = StandaloneBinaryEmitter()

    def add_module(self, module: ObjectModule):
        self.modules.append(module)

    def link(self, entry_symbol: Optional[str] = None) -> Dict[str, Any]:
        """
        Executes static linking pass across all modules:
        1. Layout sections contiguously in memory.
        2. Build global symbol address map.
        3. Patch all relocation slots with final displacements.
        """
        combined_text = bytearray()
        module_text_offsets: Dict[str, int] = {}
        global_symbol_table: Dict[str, int] = {}  # symbol_name -> global_text_offset

        # 1. Section Aggregation & Global Symbol Placement
        for mod in self.modules:
            mod_offset = len(combined_text)
            module_text_offsets[mod.repo_name] = mod_offset
            combined_text.extend(mod.text_bytes)

            for sym_name, sym in mod.symbols.items():
                if sym.section == ".text":
                    global_offset = mod_offset + sym.offset
                    global_symbol_table[sym_name] = global_offset

        # 2. Relocation Resolution
        unresolved_symbols = []
        applied_relocs = 0

        for mod in self.modules:
            mod_offset = module_text_offsets[mod.repo_name]
            for reloc in mod.relocations:
                target_sym = reloc.symbol_name
                if target_sym not in global_symbol_table:
                    unresolved_symbols.append((mod.repo_name, target_sym))
                    continue

                target_offset = global_symbol_table[target_sym]
                patch_offset = mod_offset + reloc.offset

                if reloc.reloc_type == "REL32":
                    # E8 <disp32>: next instruction is at patch_offset + 4
                    # disp32 = target_offset - (patch_offset + 4)
                    disp32 = target_offset - (patch_offset + 4)
                    struct.pack_into("<i", combined_text, patch_offset, disp32)
                    applied_relocs += 1

                elif reloc.reloc_type == "ADDR64":
                    struct.pack_into("<Q", combined_text, patch_offset, target_offset)
                    applied_relocs += 1

        if unresolved_symbols:
            raise LinkerError(f"Unresolved external symbols during link: {unresolved_symbols}")

        return {
            "success": True,
            "total_modules": len(self.modules),
            "total_text_size": len(combined_text),
            "global_symbols": global_symbol_table,
            "relocations_applied": applied_relocs,
            "combined_code": bytes(combined_text)
        }

    def emit_linked_shared_library(
        self,
        output_path: str,
        export_name: str,
        target_format: str = "auto"
    ) -> str:
        """Links modules and emits a dynamic shared library (.dll/.so)."""
        link_res = self.link()
        code = link_res["combined_code"]
        return self.emitter.emit_shared_library(
            output_path=output_path,
            func_code=code,
            export_name=export_name,
            target_format=target_format
        )

    def emit_linked_executable(
        self,
        output_path: str,
        entry_symbol: Optional[str] = None,
        target_format: str = "auto"
    ) -> str:
        """Links modules and emits a standalone executable."""
        link_res = self.link()
        code = link_res["combined_code"]
        global_syms = link_res["global_symbols"]
        entry_offset = global_syms.get(entry_symbol) if entry_symbol else 0

        return self.emitter.emit_standalone_binary(
            output_path=output_path,
            custom_code=code,
            entry_offset=entry_offset,
            target_format=target_format
        )


class LinkerError(Exception):
    pass
