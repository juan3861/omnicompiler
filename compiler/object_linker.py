"""
Native Object Linker, COFF/ELF Object Ingestion & Sub-Millisecond Hot-Patch Engine
Combines relocatable object modules (OmniCompiler `ObjectModule`, Microsoft COFF `.obj`
from LLVM/MSVC, and System V ELF64 `.o` from LLVM/GCC) into unified native executables
and multi-export shared libraries (`.dll`, `.so`, `.dylib`), plus live W^X Jump-Thunk
Hot-Patching (`HotPatchLinkerSession`, <0.1 ms symbol replacement).

Supported Relocations:
- REL32 (`IMAGE_REL_AMD64_REL32` / `R_X86_64_PC32` / `R_X86_64_PLT32`)
- ADDR64 (`IMAGE_REL_AMD64_ADDR64` / `R_X86_64_64`)
- ARM64_CALL26 (`IMAGE_REL_ARM64_BRANCH26` / `R_AARCH64_CALL26`)
"""

import ctypes
import io
import struct
import time
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
        reloc_type: str = "REL32",  # "REL32", "ADDR64", or "ARM64_CALL26"
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
    """Represents a compiled relocatable object from a single repository or `.obj`/`.o` file."""

    def __init__(self, repo_name: str):
        self.repo_name = repo_name
        self.text_bytes = bytearray()
        self.rodata_bytes = bytearray()
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

    def add_call_relocation(self, offset_in_text: int, target_symbol: str, reloc_type: str = "REL32", addend: int = 0):
        """Records a relative call relocation slot (`REL32` for x86-64 `E8`, `ARM64_CALL26` for AArch64 `BL`)."""
        self.relocations.append(RelocationEntry(
            section=".text",
            offset=offset_in_text,
            symbol_name=target_symbol,
            reloc_type=reloc_type,
            addend=addend,
        ))


# ==============================================================================
# Native COFF (.obj) & ELF64 (.o) Relocatable Object Parsers
# ==============================================================================

def load_coff_object(obj_bytes: bytes, repo_name: str = "coff_object") -> ObjectModule:
    """
    Parses a real Microsoft PE/COFF `.obj` relocatable object file (e.g. emitted by
    `LLVMBackend.emit_object()` or MSVC `cl.exe`) into an `ObjectModule`.
    """
    if len(obj_bytes) < 20:
        raise LinkerError("Truncated COFF object header (< 20 bytes)")

    machine, num_sections, _ts, symtab_ptr, num_symbols, opt_hdr_sz, _chars = struct.unpack_from(
        "<HHIIIHH", obj_bytes, 0
    )
    if machine not in (0x8664, 0xAA64):
        raise LinkerError(f"Unsupported COFF machine type: 0x{machine:04X}")

    # Parse String Table (immediately follows Symbol Table)
    strtab_offset = symtab_ptr + num_symbols * 18
    strtab_bytes = b""
    if symtab_ptr > 0 and strtab_offset + 4 <= len(obj_bytes):
        strtab_size = struct.unpack_from("<I", obj_bytes, strtab_offset)[0]
        strtab_bytes = obj_bytes[strtab_offset:strtab_offset + strtab_size]

    def decode_coff_name(raw8: bytes) -> str:
        if raw8[:4] == b"\x00\x00\x00\x00":
            soff = struct.unpack_from("<I", raw8, 4)[0]
            if soff < len(strtab_bytes):
                end = strtab_bytes.find(b"\x00", soff)
                chunk = strtab_bytes[soff:] if end == -1 else strtab_bytes[soff:end]
                return chunk.decode("utf-8", errors="replace")
        return raw8.split(b"\x00", 1)[0].decode("utf-8", errors="replace")

    # Parse Section Headers
    sec_hdr_base = 20 + opt_hdr_sz
    sections: List[Dict[str, Any]] = []
    text_sec_idx: Optional[int] = None

    for s_idx in range(num_sections):
        off = sec_hdr_base + s_idx * 40
        if off + 40 > len(obj_bytes):
            raise LinkerError("Truncated COFF section header table")
        (
            raw_sname, vsize, vaddr, raw_sz, raw_ptr,
            reloc_ptr, _line_ptr, num_relocs, _num_lines, s_chars
        ) = struct.unpack_from("<8sIIIIIIHHI", obj_bytes, off)
        sname = decode_coff_name(raw_sname)
        sec_info = {
            "index_1based": s_idx + 1,
            "name": sname,
            "raw_size": raw_sz,
            "raw_ptr": raw_ptr,
            "reloc_ptr": reloc_ptr,
            "num_relocs": num_relocs,
            "characteristics": s_chars,
        }
        sections.append(sec_info)
        if sname == ".text" and text_sec_idx is None:
            text_sec_idx = s_idx

    if text_sec_idx is None:
        raise LinkerError("COFF object contains no .text section")

    text_sec = sections[text_sec_idx]
    mod = ObjectModule(repo_name=repo_name)
    mod.text_bytes.extend(obj_bytes[text_sec["raw_ptr"]:text_sec["raw_ptr"] + text_sec["raw_size"]])

    # Parse COFF Symbol Table (18 bytes per entry, skipping auxiliary records)
    sym_by_idx: Dict[int, Tuple[str, int, int, int]] = {}
    idx = 0
    while idx < num_symbols:
        soff = symtab_ptr + idx * 18
        if soff + 18 > len(obj_bytes):
            break
        raw_name, val, sec_num, _stype, storage_cls, num_aux = struct.unpack_from("<8sIhHBB", obj_bytes, soff)
        sname = decode_coff_name(raw_name)
        sym_by_idx[idx] = (sname, val, sec_num, storage_cls)
        if sec_num == text_sec["index_1based"] and sname and not sname.startswith("."):
            is_exp = (storage_cls == 2)  # IMAGE_SYM_CLASS_EXTERNAL
            mod.symbols[sname] = SymbolDef(
                name=sname,
                section=".text",
                offset=val,
                size=max(1, len(mod.text_bytes) - val),
                is_exported=is_exp,
                source_repo=repo_name,
            )
        idx += 1 + num_aux

    # Parse .text Relocations (10 bytes each: VirtualAddress, SymbolTableIndex, Type)
    reloc_base = text_sec["reloc_ptr"]
    for r_i in range(text_sec["num_relocs"]):
        roff = reloc_base + r_i * 10
        if roff + 10 > len(obj_bytes):
            break
        vaddr_off, sym_idx, rtype = struct.unpack_from("<IIH", obj_bytes, roff)
        target_name = sym_by_idx.get(sym_idx, ("", 0, 0, 0))[0]
        if not target_name:
            continue
        if rtype == 0x0004:  # IMAGE_REL_AMD64_REL32
            init_disp = struct.unpack_from("<i", mod.text_bytes, vaddr_off)[0] if vaddr_off + 4 <= len(mod.text_bytes) else 0
            mod.relocations.append(RelocationEntry(".text", vaddr_off, target_name, "REL32", addend=init_disp))
        elif rtype == 0x0001:  # IMAGE_REL_AMD64_ADDR64
            mod.relocations.append(RelocationEntry(".text", vaddr_off, target_name, "ADDR64", addend=0))
        elif rtype == 0x0003:  # IMAGE_REL_ARM64_BRANCH26
            mod.relocations.append(RelocationEntry(".text", vaddr_off, target_name, "ARM64_CALL26", addend=0))

    return mod


def load_elf_object(obj_bytes: bytes, repo_name: str = "elf_object") -> ObjectModule:
    """
    Parses a System V ELF64 relocatable object file (`.o`, `ET_REL`) into an `ObjectModule`.
    """
    from elftools.elf.elffile import ELFFile

    elf = ELFFile(io.BytesIO(obj_bytes))
    text_sec = elf.get_section_by_name(".text")
    if text_sec is None:
        raise LinkerError("ELF object contains no .text section")

    mod = ObjectModule(repo_name=repo_name)
    mod.text_bytes.extend(text_sec.data())
    text_shndx = None
    for i, s in enumerate(elf.iter_sections()):
        if s.name == ".text":
            text_shndx = i
            break

    symtab = elf.get_section_by_name(".symtab")
    if symtab is not None:
        for sym in symtab.iter_symbols():
            if sym.name and sym["st_shndx"] == text_shndx and sym["st_info"]["type"] in ("STT_FUNC", "STT_NOTYPE"):
                is_exp = sym["st_info"]["bind"] == "STB_GLOBAL"
                mod.symbols[sym.name] = SymbolDef(
                    name=sym.name,
                    section=".text",
                    offset=int(sym["st_value"]),
                    size=max(1, int(sym["st_size"]) or (len(mod.text_bytes) - int(sym["st_value"]))),
                    is_exported=is_exp,
                    source_repo=repo_name,
                )

    rela_text = elf.get_section_by_name(".rela.text")
    if rela_text is not None and symtab is not None:
        for rel in rela_text.iter_relocations():
            sym = symtab.get_symbol(rel["r_info_sym"])
            if not sym or not sym.name:
                continue
            rtype = rel["r_info_type"]
            r_off = int(rel["r_offset"])
            r_addend = int(rel["r_addend"]) if rel.is_RELA() else 0
            # x86-64: R_X86_64_PC32=2, R_X86_64_PLT32=4 (addend typically -4, which cancels +4 in E8 disp32!)
            if rtype in (2, 4):
                mod.relocations.append(RelocationEntry(".text", r_off, sym.name, "REL32", addend=r_addend + 4))
            elif rtype == 1:  # R_X86_64_64
                mod.relocations.append(RelocationEntry(".text", r_off, sym.name, "ADDR64", addend=r_addend))
            elif rtype in (282, 283):  # R_AARCH64_JUMP26 / R_AARCH64_CALL26
                mod.relocations.append(RelocationEntry(".text", r_off, sym.name, "ARM64_CALL26", addend=r_addend))

    return mod


# ==============================================================================
# Static Multi-Module Linker
# ==============================================================================

class NativeObjectLinker:
    """
    Combines and resolves multiple `ObjectModule`s into fully linked native executables
    and multi-symbol shared libraries (`.dll` / `.so` / `.dylib`).
    """

    def __init__(self):
        self.modules: List[ObjectModule] = []
        self.emitter = StandaloneBinaryEmitter()

    def add_module(self, module: ObjectModule):
        self.modules.append(module)

    def add_coff_object(self, obj_bytes: bytes, repo_name: str = "coff_object") -> ObjectModule:
        mod = load_coff_object(obj_bytes, repo_name=repo_name)
        self.add_module(mod)
        return mod

    def add_elf_object(self, obj_bytes: bytes, repo_name: str = "elf_object") -> ObjectModule:
        mod = load_elf_object(obj_bytes, repo_name=repo_name)
        self.add_module(mod)
        return mod

    def link(self, entry_symbol: Optional[str] = None) -> Dict[str, Any]:
        """
        Executes static linking pass across all modules:
        1. Layout sections contiguously in memory.
        2. Build global symbol address map & exported symbol map.
        3. Patch all x86-64 (`REL32`, `ADDR64`) and ARM64 (`ARM64_CALL26`) relocation slots.
        """
        # Auto-synthesize runtime collection symbol thunks if any module requires them
        try:
            from runtime.native_heap import NATIVE_COLLECTION_SYMBOLS
        except ImportError:
            NATIVE_COLLECTION_SYMBOLS = {}

        defined_syms = set()
        for mod in self.modules:
            for s in mod.symbols:
                defined_syms.add(s)

        needed_runtime_syms = set()
        for mod in self.modules:
            for reloc in mod.relocations:
                if reloc.symbol_name not in defined_syms and reloc.symbol_name in NATIVE_COLLECTION_SYMBOLS:
                    needed_runtime_syms.add(reloc.symbol_name)

        if needed_runtime_syms:
            if not hasattr(self, "_active_callbacks"):
                self._active_callbacks = []
            runtime_mod = ObjectModule("__omni_runtime_thunks__")
            for sym in sorted(needed_runtime_syms):
                fn_meta = NATIVE_COLLECTION_SYMBOLS[sym]
                fn_obj, arg_types, res_type = fn_meta
                c_fn = ctypes.CFUNCTYPE(res_type, *arg_types)(fn_obj)
                self._active_callbacks.append(c_fn)
                addr = ctypes.cast(c_fn, ctypes.c_void_p).value
                # x86-64: mov r11, <addr>; jmp r11; ret
                thunk_bytes = b"\x49\xbb" + struct.pack("<Q", addr) + b"\x41\xff\xe3\xc3"
                runtime_mod.add_symbol(sym, thunk_bytes, is_exported=True)
            self.modules.append(runtime_mod)

        combined_text = bytearray()
        module_text_offsets: Dict[int, int] = {}
        global_symbol_table: Dict[str, int] = {}
        exported_symbols: Dict[str, int] = {}

        # 1. Section Aggregation & Global Symbol Placement
        for idx, mod in enumerate(self.modules):
            mod_offset = len(combined_text)
            module_text_offsets[idx] = mod_offset
            combined_text.extend(mod.text_bytes)

            for sym_name, sym in mod.symbols.items():
                if sym.section == ".text":
                    global_offset = mod_offset + sym.offset
                    global_symbol_table[sym_name] = global_offset
                    if sym.is_exported:
                        exported_symbols[sym_name] = global_offset

        # 2. Relocation Resolution
        unresolved_symbols = []
        applied_relocs = 0

        for idx, mod in enumerate(self.modules):
            mod_offset = module_text_offsets[idx]
            for reloc in mod.relocations:
                target_sym = reloc.symbol_name
                if target_sym not in global_symbol_table:
                    unresolved_symbols.append((mod.repo_name, target_sym))
                    continue

                target_offset = global_symbol_table[target_sym]
                if reloc.offset < 0:
                    raise RelocationOutOfBoundsError(
                        f"Negative relocation offset {reloc.offset} in module {mod.repo_name}"
                    )

                patch_offset = mod_offset + reloc.offset
                reloc_size = 8 if reloc.reloc_type == "ADDR64" else 4
                if patch_offset + reloc_size > len(combined_text):
                    raise RelocationOutOfBoundsError(
                        f"Relocation slot [{patch_offset}..{patch_offset + reloc_size}] exceeds combined .text bounds ({len(combined_text)}) in module {mod.repo_name}"
                    )

                if target_offset < 0 or target_offset >= len(combined_text):
                    raise RelocationOutOfBoundsError(
                        f"Relocation target symbol '{target_sym}' at offset {target_offset} is outside valid .text bounds [0..{len(combined_text)})"
                    )

                if reloc.reloc_type == "REL32":
                    disp32 = (target_offset + reloc.addend) - (patch_offset + 4)
                    if not (-0x80000000 <= disp32 <= 0x7FFFFFFF):
                        raise RelocationOutOfBoundsError(f"REL32 displacement {disp32} overflows signed 32-bit range")
                    struct.pack_into("<i", combined_text, patch_offset, disp32)
                    applied_relocs += 1

                elif reloc.reloc_type == "ADDR64":
                    struct.pack_into("<Q", combined_text, patch_offset, target_offset + reloc.addend)
                    applied_relocs += 1

                elif reloc.reloc_type == "ARM64_CALL26":
                    byte_diff = (target_offset + reloc.addend) - patch_offset
                    if byte_diff % 4 != 0:
                        raise RelocationOutOfBoundsError(f"Misaligned ARM64_CALL26 displacement {byte_diff}")
                    imm26 = byte_diff // 4
                    if not (-(1 << 25) <= imm26 < (1 << 25)):
                        raise RelocationOutOfBoundsError(f"ARM64_CALL26 displacement {imm26} overflows 26-bit range")
                    orig_inst = struct.unpack_from("<I", combined_text, patch_offset)[0]
                    patched_inst = (orig_inst & 0xFC000000) | (imm26 & 0x03FFFFFF)
                    struct.pack_into("<I", combined_text, patch_offset, patched_inst)
                    applied_relocs += 1

        if unresolved_symbols:
            raise LinkerError(f"Unresolved external symbols during link: {unresolved_symbols}")

        return {
            "success": True,
            "total_modules": len(self.modules),
            "total_text_size": len(combined_text),
            "global_symbols": global_symbol_table,
            "exported_symbols": exported_symbols,
            "relocations_applied": applied_relocs,
            "combined_code": bytes(combined_text)
        }

    def emit_linked_shared_library(
        self,
        output_path: str,
        export_name: str,
        target_format: str = "auto",
        pdata_xdata: Optional[Tuple[bytes, bytes]] = None,
    ) -> str:
        """Links modules and emits a dynamic shared library exporting ALL exported module symbols."""
        link_res = self.link()
        code = link_res["combined_code"]
        exports = dict(link_res["exported_symbols"])
        if export_name in link_res["global_symbols"]:
            exports[export_name] = link_res["global_symbols"][export_name]
        else:
            exports.setdefault(export_name, 0)

        return self.emitter.emit_shared_library(
            output_path=output_path,
            func_code=code,
            export_name=export_name,
            target_format=target_format,
            extra_exports=exports,
            pdata_xdata=pdata_xdata,
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


# ==============================================================================
# Sub-Millisecond Incremental Jump-Thunk Hot-Patch Linker (GAP-04 / Mold & Roc Style)
# ==============================================================================

class HotPatchLinkerSession:
    """
    Live Incremental Native Linker using an indirect 16-byte Jump-Thunk Dispatch Table
    in W^X memory. Allows replacing any function's native machine code in <0.1 ms while
    preserving existing ctypes function pointers and already-linked cross-module callers.
    """

    THUNK_STRIDE = 16
    MAX_THUNKS = 256
    THUNK_TABLE_BYTES = THUNK_STRIDE * MAX_THUNKS  # 4096 bytes

    def __init__(self, arena_bytes: int = 65536):
        from compiler.native_jit import NativeJitMemory
        self.arena_size = max(16384, arena_bytes)
        self.mem = NativeJitMemory(size=self.arena_size)
        self._image = bytearray(b"\xcc" * self.arena_size)
        self._code_cursor = self.THUNK_TABLE_BYTES
        self._thunk_index: Dict[str, int] = {}
        self._symbol_code_offset: Dict[str, int] = {}
        self._patch_generation: Dict[str, int] = {}

    def _ensure_thunk(self, symbol_name: str) -> int:
        if symbol_name in self._thunk_index:
            return self._thunk_index[symbol_name]
        if len(self._thunk_index) >= self.MAX_THUNKS:
            raise LinkerError("HotPatchLinkerSession thunk table capacity exceeded")
        idx = len(self._thunk_index)
        self._thunk_index[symbol_name] = idx
        return idx

    def thunk_offset(self, symbol_name: str) -> int:
        return self._ensure_thunk(symbol_name) * self.THUNK_STRIDE

    def register_or_patch_symbol(
        self,
        symbol_name: str,
        code_bytes: bytes,
        relocations: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        """
        Appends `code_bytes` to the W^X code arena, resolves any outgoing `REL32` calls
        through the target symbol's Jump-Thunk slot, and atomically updates `symbol_name`'s
        Jump-Thunk (`E9 <disp32>`) to point to the new code body.
        """
        t0 = time.perf_counter()
        aligned_cursor = ((self._code_cursor + 15) // 16) * 16
        if aligned_cursor + len(code_bytes) > self.arena_size:
            raise LinkerError("HotPatchLinkerSession code arena exhausted")

        patched_body = bytearray(code_bytes)
        for rel in (relocations or []):
            rel_sym = rel.symbol_name
            rel_off = rel.offset
            callee_thunk_off = self.thunk_offset(rel_sym)
            patch_abs = aligned_cursor + rel_off
            disp32 = callee_thunk_off - (patch_abs + 4)
            struct.pack_into("<i", patched_body, rel_off, disp32)

        # Write function body into shadow image
        self._image[aligned_cursor:aligned_cursor + len(patched_body)] = patched_body
        self._code_cursor = aligned_cursor + len(patched_body)
        self._symbol_code_offset[symbol_name] = aligned_cursor

        # Update 5-byte JMP rel32 inside symbol's 16-byte thunk slot
        t_off = self.thunk_offset(symbol_name)
        jmp_disp32 = aligned_cursor - (t_off + 5)
        self._image[t_off] = 0xE9
        struct.pack_into("<i", self._image, t_off + 1, jmp_disp32)

        # Commit to physical RAM with W^X RW -> RX + FlushInstructionCache
        self.mem.write_code(bytes(self._image[:self._code_cursor]))
        gen = self._patch_generation.get(symbol_name, 0) + 1
        self._patch_generation[symbol_name] = gen
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "symbol": symbol_name,
            "generation": gen,
            "thunk_address": int(self.mem.ptr) + t_off,  # type: ignore[arg-type]
            "body_address": int(self.mem.ptr) + aligned_cursor,  # type: ignore[arg-type]
            "latency_ms": elapsed_ms,
            "wx_protection": self.mem.protection_mode,
        }

    def get_callable(self, symbol_name: str, arity: int = 1):
        """Returns a persistent ctypes callable bound to `symbol_name`'s stable Jump-Thunk address."""
        if symbol_name not in self._thunk_index:
            raise LinkerError(f"Symbol '{symbol_name}' is not registered in HotPatchLinkerSession")
        addr = int(self.mem.ptr) + self.thunk_offset(symbol_name)  # type: ignore[arg-type]
        arg_types = [ctypes.c_int64] * arity
        fn = ctypes.CFUNCTYPE(ctypes.c_int64, *arg_types)(addr)
        fn._session = self
        return fn

    def close(self):
        self.mem.free()


class LinkerError(Exception):
    pass


class RelocationOutOfBoundsError(LinkerError):
    """Raised when a relocation offset, slot, or target falls outside valid section boundaries."""
    pass
