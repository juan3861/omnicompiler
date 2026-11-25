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
import hashlib
import io
import struct
import sys
import time
from typing import Dict, List, Tuple, Any, Optional, Sequence

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
        self.bss_size: int = 0
        self.tdata_bytes = bytearray()
        self.tbss_size: int = 0
        self.init_array_bytes = bytearray()
        self.fini_array_bytes = bytearray()
        self.eh_frame_bytes = bytearray()
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

def _arm64_ldst_shift(inst_word: int) -> int:
    """Returns the log2 byte scale shift for an AArch64 ADD (0) or LDR/STR unsigned-immediate instruction."""
    if ((inst_word >> 24) & 0x1F) == 0x11:
        return 0
    if ((inst_word >> 27) & 0x7) == 0x7:
        size = (inst_word >> 30) & 0x3
        v_bit = (inst_word >> 26) & 0x1
        opc1 = (inst_word >> 23) & 0x1
        if v_bit == 1 and size == 0 and opc1 == 1:
            return 4
        return size
    return 0


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
        if sname == ".text":
            text_sec_idx = s_idx
        elif text_sec_idx is None and sname.startswith(".text$") and (s_chars & 0x20000020):
            text_sec_idx = s_idx

    if text_sec_idx is None:
        raise LinkerError("COFF object contains no .text section")

    text_sec = sections[text_sec_idx]
    mod = ObjectModule(repo_name=repo_name)
    mod.text_bytes.extend(obj_bytes[text_sec["raw_ptr"]:text_sec["raw_ptr"] + text_sec["raw_size"]])

    exec_sec_offsets: Dict[int, Tuple[int, int]] = {
        text_sec["index_1based"]: (0, text_sec["raw_size"])
    }
    rodata_sec_offsets: Dict[int, int] = {}
    data_sec_offsets: Dict[int, int] = {}
    bss_sec_offsets: Dict[int, int] = {}
    init_sec_offsets: Dict[int, int] = {}
    tdata_sec_offsets: Dict[int, int] = {}
    for s_info in sections:
        s_idx_1 = s_info["index_1based"]
        if s_idx_1 == text_sec["index_1based"]:
            continue
        chars = s_info["characteristics"]
        sname_l = s_info["name"]
        if sname_l.startswith(".text") and (chars & 0x20000020) and s_info["raw_size"] > 0:
            xpad = (16 - (len(mod.text_bytes) % 16)) % 16
            if xpad:
                mod.text_bytes.extend(b"\x90" * xpad)
            exec_sec_offsets[s_idx_1] = (len(mod.text_bytes), s_info["raw_size"])
            mod.text_bytes.extend(obj_bytes[s_info["raw_ptr"] : s_info["raw_ptr"] + s_info["raw_size"]])
        elif sname_l.lower().startswith(".crt$xcu") and s_info["raw_size"] > 0:
            ipad = (8 - (len(mod.init_array_bytes) % 8)) % 8
            if ipad:
                mod.init_array_bytes.extend(b"\x00" * ipad)
            init_sec_offsets[s_idx_1] = len(mod.init_array_bytes)
            mod.init_array_bytes.extend(obj_bytes[s_info["raw_ptr"] : s_info["raw_ptr"] + s_info["raw_size"]])
        elif sname_l.startswith(".tls") and not (chars & 0x00000080) and s_info["raw_size"] > 0:
            tpad = (8 - (len(mod.tdata_bytes) % 8)) % 8
            if tpad:
                mod.tdata_bytes.extend(b"\x00" * tpad)
            tdata_sec_offsets[s_idx_1] = len(mod.tdata_bytes)
            mod.tdata_bytes.extend(obj_bytes[s_info["raw_ptr"] : s_info["raw_ptr"] + s_info["raw_size"]])
        elif (chars & 0x00000080) or sname_l.startswith(".bss"):
            bss_align = (16 - (mod.bss_size % 16)) % 16
            mod.bss_size += bss_align
            bss_sec_offsets[s_idx_1] = mod.bss_size
            mod.bss_size += max(0, int(s_info["raw_size"]))
        elif sname_l.startswith(".data") and s_info["raw_size"] > 0:
            dpad = (16 - (len(mod.data_bytes) % 16)) % 16
            if dpad:
                mod.data_bytes.extend(b"\x00" * dpad)
            data_sec_offsets[s_idx_1] = len(mod.data_bytes)
            mod.data_bytes.extend(
                obj_bytes[s_info["raw_ptr"] : s_info["raw_ptr"] + s_info["raw_size"]]
            )
        elif sname_l.startswith((".rdata", ".rodata")) and s_info["raw_size"] > 0:
            pad = (32 - (len(mod.text_bytes) % 32)) % 32
            if pad:
                mod.text_bytes.extend(b"\x00" * pad)
            rodata_sec_offsets[s_idx_1] = len(mod.text_bytes)
            mod.text_bytes.extend(
                obj_bytes[s_info["raw_ptr"] : s_info["raw_ptr"] + s_info["raw_size"]]
            )

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
        if (
            sec_num in exec_sec_offsets
            and sname
            and not sname.startswith(".")
            and not (
                storage_cls == 3
                and (sname in ("$x", "$d", "$a", "$t") or sname.startswith(("$x.", "$d.", "$a.", "$t.")))
            )
        ):
            is_exp = (storage_cls == 2)  # IMAGE_SYM_CLASS_EXTERNAL
            xbase, xlen = exec_sec_offsets[sec_num]
            mod.symbols[sname] = SymbolDef(
                name=sname,
                section=".text",
                offset=xbase + val,
                size=max(1, xlen - val),
                is_exported=is_exp,
                source_repo=repo_name,
            )
        elif sec_num in tdata_sec_offsets:
            coff_sec_sym = f"__coff_sym_{idx}__"
            mod.symbols[coff_sec_sym] = SymbolDef(
                name=coff_sec_sym, section=".tdata", offset=tdata_sec_offsets[sec_num] + val,
                size=8, is_exported=False, source_repo=repo_name,
            )
            if sname and not sname.startswith("."):
                mod.symbols[sname] = SymbolDef(
                    name=sname, section=".tdata", offset=tdata_sec_offsets[sec_num] + val,
                    size=8, is_exported=(storage_cls == 2), source_repo=repo_name,
                )
        elif sec_num in rodata_sec_offsets:
            coff_sec_sym = f"__coff_sym_{idx}__"
            mod.symbols[coff_sec_sym] = SymbolDef(
                name=coff_sec_sym,
                section=".rodata",
                offset=rodata_sec_offsets[sec_num] + val,
                size=8,
                is_exported=False,
                source_repo=repo_name,
            )
            if sname and not sname.startswith("."):
                mod.symbols[sname] = SymbolDef(
                    name=sname,
                    section=".rodata",
                    offset=rodata_sec_offsets[sec_num] + val,
                    size=8,
                    is_exported=(storage_cls == 2),
                    source_repo=repo_name,
                )
        elif sec_num in data_sec_offsets:
            coff_sec_sym = f"__coff_sym_{idx}__"
            mod.symbols[coff_sec_sym] = SymbolDef(
                name=coff_sec_sym,
                section=".data",
                offset=data_sec_offsets[sec_num] + val,
                size=8,
                is_exported=False,
                source_repo=repo_name,
            )
            if sname and not sname.startswith("."):
                mod.symbols[sname] = SymbolDef(
                    name=sname,
                    section=".data",
                    offset=data_sec_offsets[sec_num] + val,
                    size=8,
                    is_exported=(storage_cls == 2),
                    source_repo=repo_name,
                )
        elif sec_num in bss_sec_offsets:
            coff_sec_sym = f"__coff_sym_{idx}__"
            mod.symbols[coff_sec_sym] = SymbolDef(
                name=coff_sec_sym,
                section=".bss",
                offset=bss_sec_offsets[sec_num] + val,
                size=8,
                is_exported=False,
                source_repo=repo_name,
            )
            if sname and not sname.startswith("."):
                mod.symbols[sname] = SymbolDef(
                    name=sname,
                    section=".bss",
                    offset=bss_sec_offsets[sec_num] + val,
                    size=8,
                    is_exported=(storage_cls == 2),
                    source_repo=repo_name,
                )
        idx += 1 + num_aux

    # Parse .text and .data/.rdata Relocations (10 bytes each: VirtualAddress, SymbolTableIndex, Type)
    is_arm64_coff = (machine == 0xAA64)
    reloc_sources: List[Tuple[str, int, Dict[str, Any], bytearray]] = []
    for s_info in sections:
        s_idx_1 = s_info["index_1based"]
        if s_info["num_relocs"] > 0:
            if s_idx_1 in exec_sec_offsets:
                reloc_sources.append((".text", exec_sec_offsets[s_idx_1][0], s_info, mod.text_bytes))
            elif s_idx_1 in init_sec_offsets:
                reloc_sources.append((".init_array", init_sec_offsets[s_idx_1], s_info, mod.init_array_bytes))
            elif s_idx_1 in data_sec_offsets:
                reloc_sources.append((".data", data_sec_offsets[s_idx_1], s_info, mod.data_bytes))
            elif s_idx_1 in rodata_sec_offsets:
                reloc_sources.append((".text", rodata_sec_offsets[s_idx_1], s_info, mod.text_bytes))

    for reloc_sec_name, sec_base_off, s_info, sec_buf in reloc_sources:
        reloc_base = s_info["reloc_ptr"]
        for r_i in range(s_info["num_relocs"]):
            roff = reloc_base + r_i * 10
            if roff + 10 > len(obj_bytes):
                break
            vaddr_off, sym_idx, rtype = struct.unpack_from("<IIH", obj_bytes, roff)
            patch_off = sec_base_off + vaddr_off
            sname, _sval, s_sec_num, _scls = sym_by_idx.get(sym_idx, ("", 0, 0, 0))
            if (
                s_sec_num in rodata_sec_offsets
                or s_sec_num in data_sec_offsets
                or s_sec_num in bss_sec_offsets
                or s_sec_num in tdata_sec_offsets
            ) and f"__coff_sym_{sym_idx}__" in mod.symbols:
                target_name = f"__coff_sym_{sym_idx}__"
            else:
                target_name = sname
            if not target_name:
                continue
            if not is_arm64_coff:
                if rtype == 0x0004:  # IMAGE_REL_AMD64_REL32
                    init_disp = struct.unpack_from("<i", sec_buf, patch_off)[0] if patch_off + 4 <= len(sec_buf) else 0
                    mod.relocations.append(RelocationEntry(reloc_sec_name, patch_off, target_name, "REL32", addend=init_disp))
                elif rtype == 0x0001:  # IMAGE_REL_AMD64_ADDR64
                    init_abs = struct.unpack_from("<q", sec_buf, patch_off)[0] if patch_off + 8 <= len(sec_buf) else 0
                    mod.relocations.append(RelocationEntry(reloc_sec_name, patch_off, target_name, "ADDR64", addend=init_abs))
                elif rtype == 0x000B:  # IMAGE_REL_AMD64_SECREL (TLS offset)
                    init_sec_off = struct.unpack_from("<i", sec_buf, patch_off)[0] if patch_off + 4 <= len(sec_buf) else 0
                    mod.relocations.append(RelocationEntry(reloc_sec_name, patch_off, target_name, "COFF_SECREL32", addend=init_sec_off))
            else:
                if rtype == 0x0003:  # IMAGE_REL_ARM64_BRANCH26
                    mod.relocations.append(RelocationEntry(reloc_sec_name, patch_off, target_name, "ARM64_CALL26", addend=0))
                elif rtype == 0x000E:  # IMAGE_REL_ARM64_ADDR64
                    init_abs = struct.unpack_from("<q", sec_buf, patch_off)[0] if patch_off + 8 <= len(sec_buf) else 0
                    mod.relocations.append(RelocationEntry(reloc_sec_name, patch_off, target_name, "ADDR64", addend=init_abs))
                elif rtype == 0x0004 and patch_off + 4 <= len(sec_buf):  # IMAGE_REL_ARM64_PAGEBASE_REL21
                    inst_w = struct.unpack_from("<I", sec_buf, patch_off)[0]
                    raw21 = ((inst_w >> 29) & 0x3) | (((inst_w >> 5) & 0x7FFFF) << 2)
                    if raw21 & (1 << 20):
                        raw21 -= (1 << 21)
                    mod.relocations.append(RelocationEntry(reloc_sec_name, patch_off, target_name, "ARM64_PAGE21", addend=raw21))
                elif rtype == 0x0006 and patch_off + 4 <= len(sec_buf):  # IMAGE_REL_ARM64_PAGEOFFSET_12A
                    inst_w = struct.unpack_from("<I", sec_buf, patch_off)[0]
                    imm12 = (inst_w >> 10) & 0xFFF
                    mod.relocations.append(RelocationEntry(reloc_sec_name, patch_off, target_name, "ARM64_LO12", addend=imm12))
                elif rtype == 0x0007 and patch_off + 4 <= len(sec_buf):  # IMAGE_REL_ARM64_PAGEOFFSET_12L
                    inst_w = struct.unpack_from("<I", sec_buf, patch_off)[0]
                    shift = _arm64_ldst_shift(inst_w)
                    imm12 = ((inst_w >> 10) & 0xFFF) << shift
                    mod.relocations.append(RelocationEntry(reloc_sec_name, patch_off, target_name, "ARM64_LO12", addend=imm12))

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
    text_raw_len = len(text_sec.data())
    mod.text_bytes.extend(text_sec.data())
    text_shndx = None
    exec_sec_offsets: Dict[int, Tuple[int, int]] = {}
    rodata_sec_offsets: Dict[int, int] = {}
    data_sec_offsets: Dict[int, int] = {}
    bss_sec_offsets: Dict[int, int] = {}
    tdata_sec_offsets: Dict[int, int] = {}
    tbss_sec_offsets: Dict[int, int] = {}
    init_sec_offsets: Dict[int, int] = {}
    fini_sec_offsets: Dict[int, int] = {}
    eh_sec_offsets: Dict[int, int] = {}
    for i, s in enumerate(elf.iter_sections()):
        sh_type = s.header["sh_type"]
        sh_flags = int(s.header["sh_flags"])
        if s.name == ".eh_frame" and s.data_size > 0:
            eh_sec_offsets[i] = len(mod.eh_frame_bytes)
            mod.eh_frame_bytes.extend(s.data())
        elif s.name == ".text":
            text_shndx = i
            exec_sec_offsets[i] = (0, text_raw_len)
            sec_sym = f"__elf_sec_{i}__"
            mod.symbols[sec_sym] = SymbolDef(
                name=sec_sym, section=".text", offset=0,
                size=max(1, text_raw_len), is_exported=False, source_repo=repo_name,
            )
        elif sh_type == "SHT_PROGBITS" and (sh_flags & 0x6) == 0x6 and s.data_size > 0:
            xpad = (16 - (len(mod.text_bytes) % 16)) % 16
            if xpad:
                mod.text_bytes.extend(b"\x90" * xpad)
            xoff = len(mod.text_bytes)
            xdata = s.data()
            mod.text_bytes.extend(xdata)
            exec_sec_offsets[i] = (xoff, len(xdata))
            sec_sym = f"__elf_sec_{i}__"
            mod.symbols[sec_sym] = SymbolDef(
                name=sec_sym, section=".text", offset=xoff,
                size=max(1, len(xdata)), is_exported=False, source_repo=repo_name,
            )
        elif (sh_flags & 0x400):  # SHF_TLS (.tdata / .tbss)
            if sh_type == "SHT_NOBITS" and int(s.header["sh_size"]) > 0:
                al = max(8, int(s.header["sh_addralign"]) or 8)
                pad_b = (al - (mod.tbss_size % al)) % al
                mod.tbss_size += pad_b
                tbss_sec_offsets[i] = mod.tbss_size
                mod.tbss_size += int(s.header["sh_size"])
                sec_sym = f"__elf_sec_{i}__"
                mod.symbols[sec_sym] = SymbolDef(
                    name=sec_sym, section=".tbss", offset=tbss_sec_offsets[i],
                    size=int(s.header["sh_size"]), is_exported=False, source_repo=repo_name,
                )
            elif s.data_size > 0:
                tpad = (8 - (len(mod.tdata_bytes) % 8)) % 8
                if tpad:
                    mod.tdata_bytes.extend(b"\x00" * tpad)
                tdata_sec_offsets[i] = len(mod.tdata_bytes)
                t_data = s.data()
                mod.tdata_bytes.extend(t_data)
                sec_sym = f"__elf_sec_{i}__"
                mod.symbols[sec_sym] = SymbolDef(
                    name=sec_sym, section=".tdata", offset=tdata_sec_offsets[i],
                    size=max(1, len(t_data)), is_exported=False, source_repo=repo_name,
                )
        elif (sh_type == "SHT_INIT_ARRAY" or s.name.startswith(".init_array")) and s.data_size > 0:
            ipad = (8 - (len(mod.init_array_bytes) % 8)) % 8
            if ipad:
                mod.init_array_bytes.extend(b"\x00" * ipad)
            init_sec_offsets[i] = len(mod.init_array_bytes)
            mod.init_array_bytes.extend(s.data())
        elif (sh_type == "SHT_FINI_ARRAY" or s.name.startswith(".fini_array")) and s.data_size > 0:
            fpad = (8 - (len(mod.fini_array_bytes) % 8)) % 8
            if fpad:
                mod.fini_array_bytes.extend(b"\x00" * fpad)
            fini_sec_offsets[i] = len(mod.fini_array_bytes)
            mod.fini_array_bytes.extend(s.data())
        elif sh_type == "SHT_NOBITS" and (sh_flags & 0x2) and int(s.header["sh_size"]) > 0:
            al = max(16, int(s.header["sh_addralign"]) or 16)
            pad_b = (al - (mod.bss_size % al)) % al
            mod.bss_size += pad_b
            bss_sec_offsets[i] = mod.bss_size
            mod.bss_size += int(s.header["sh_size"])
            sec_sym = f"__elf_sec_{i}__"
            mod.symbols[sec_sym] = SymbolDef(
                name=sec_sym, section=".bss", offset=bss_sec_offsets[i],
                size=int(s.header["sh_size"]), is_exported=False, source_repo=repo_name,
            )
        elif (s.name.startswith((".data", ".sdata")) or (sh_type == "SHT_PROGBITS" and (sh_flags & 0x3) == 0x3 and not s.name.startswith(".debug"))) and s.data_size > 0:
            dpad = (16 - (len(mod.data_bytes) % 16)) % 16
            if dpad:
                mod.data_bytes.extend(b"\x00" * dpad)
            data_sec_offsets[i] = len(mod.data_bytes)
            d_data = s.data()
            mod.data_bytes.extend(d_data)
            sec_sym = f"__elf_sec_{i}__"
            mod.symbols[sec_sym] = SymbolDef(
                name=sec_sym, section=".data", offset=data_sec_offsets[i],
                size=max(1, len(d_data)), is_exported=False, source_repo=repo_name,
            )
        elif (s.name.startswith((".rodata", ".rdata", ".gcc_except_table")) or (sh_type == "SHT_PROGBITS" and (sh_flags & 0x2) and not (sh_flags & 0x5) and not s.name.startswith((".debug", ".note", ".comment", ".eh_frame")))) and s.data_size > 0:
            pad = (32 - (len(mod.text_bytes) % 32)) % 32
            if pad:
                mod.text_bytes.extend(b"\x00" * pad)
            rodata_sec_offsets[i] = len(mod.text_bytes)
            s_data = s.data()
            mod.text_bytes.extend(s_data)
            sec_sym = f"__elf_sec_{i}__"
            mod.symbols[sec_sym] = SymbolDef(
                name=sec_sym,
                section=".rodata",
                offset=rodata_sec_offsets[i],
                size=max(1, len(s_data)),
                is_exported=False,
                source_repo=repo_name,
            )

    symtab = elf.get_section_by_name(".symtab")
    if symtab is not None:
        for sym in symtab.iter_symbols():
            shndx = sym["st_shndx"]
            bind = sym["st_info"]["bind"]
            is_exp = bind in ("STB_GLOBAL", "STB_WEAK")
            if (
                sym.name
                and shndx in exec_sec_offsets
                and sym["st_info"]["type"] in ("STT_FUNC", "STT_NOTYPE")
                and not (
                    bind == "STB_LOCAL"
                    and (
                        sym.name in ("$x", "$d", "$a", "$t")
                        or sym.name.startswith(("$x.", "$d.", "$a.", "$t."))
                    )
                )
            ):
                sec_base_x, sec_len_x = exec_sec_offsets[shndx]
                mod.symbols[sym.name] = SymbolDef(
                    name=sym.name,
                    section=".text",
                    offset=sec_base_x + int(sym["st_value"]),
                    size=max(1, int(sym["st_size"]) or max(1, sec_len_x - int(sym["st_value"]))),
                    is_exported=is_exp,
                    source_repo=repo_name,
                )
            elif sym.name and shndx in rodata_sec_offsets:
                mod.symbols[sym.name] = SymbolDef(
                    name=sym.name,
                    section=".rodata",
                    offset=rodata_sec_offsets[shndx] + int(sym["st_value"]),
                    size=max(1, int(sym["st_size"]) or 8),
                    is_exported=is_exp,
                    source_repo=repo_name,
                )
            elif sym.name and shndx in data_sec_offsets:
                mod.symbols[sym.name] = SymbolDef(
                    name=sym.name,
                    section=".data",
                    offset=data_sec_offsets[shndx] + int(sym["st_value"]),
                    size=max(1, int(sym["st_size"]) or 8),
                    is_exported=is_exp,
                    source_repo=repo_name,
                )
            elif sym.name and shndx in bss_sec_offsets:
                mod.symbols[sym.name] = SymbolDef(
                    name=sym.name,
                    section=".bss",
                    offset=bss_sec_offsets[shndx] + int(sym["st_value"]),
                    size=max(1, int(sym["st_size"]) or 8),
                    is_exported=is_exp,
                    source_repo=repo_name,
                )
            elif sym.name and shndx in tdata_sec_offsets:
                mod.symbols[sym.name] = SymbolDef(
                    name=sym.name,
                    section=".tdata",
                    offset=tdata_sec_offsets[shndx] + int(sym["st_value"]),
                    size=max(1, int(sym["st_size"]) or 8),
                    is_exported=is_exp,
                    source_repo=repo_name,
                )
            elif sym.name and shndx in tbss_sec_offsets:
                mod.symbols[sym.name] = SymbolDef(
                    name=sym.name,
                    section=".tbss",
                    offset=tbss_sec_offsets[shndx] + int(sym["st_value"]),
                    size=max(1, int(sym["st_size"]) or 8),
                    is_exported=is_exp,
                    source_repo=repo_name,
                )
            elif sym.name and shndx == "SHN_COMMON":
                al = max(8, int(sym["st_value"]) or 8)
                pad_b = (al - (mod.bss_size % al)) % al
                mod.bss_size += pad_b
                csz = max(8, int(sym["st_size"]) or 8)
                mod.symbols[sym.name] = SymbolDef(
                    name=sym.name,
                    section=".bss",
                    offset=mod.bss_size,
                    size=csz,
                    is_exported=is_exp,
                    source_repo=repo_name,
                )
                mod.bss_size += csz

    if symtab is not None:
        for sec in elf.iter_sections():
            if sec.header["sh_type"] not in ("SHT_RELA", "SHT_REL"):
                continue
            target_shndx = int(sec.header["sh_info"])
            if target_shndx in exec_sec_offsets:
                reloc_sec_name, sec_base_off = ".text", exec_sec_offsets[target_shndx][0]
            elif target_shndx in data_sec_offsets:
                reloc_sec_name, sec_base_off = ".data", data_sec_offsets[target_shndx]
            elif target_shndx in init_sec_offsets:
                reloc_sec_name, sec_base_off = ".init_array", init_sec_offsets[target_shndx]
            elif target_shndx in fini_sec_offsets:
                reloc_sec_name, sec_base_off = ".fini_array", fini_sec_offsets[target_shndx]
            elif target_shndx in eh_sec_offsets:
                reloc_sec_name, sec_base_off = ".eh_frame", eh_sec_offsets[target_shndx]
            elif target_shndx in rodata_sec_offsets:
                reloc_sec_name, sec_base_off = ".text", rodata_sec_offsets[target_shndx]
            else:
                continue

            for rel in sec.iter_relocations():
                sym = symtab.get_symbol(rel["r_info_sym"])
                if not sym:
                    continue
                target_sym_name = sym.name
                shndx_t = sym["st_shndx"]
                if not target_sym_name and (
                    shndx_t in exec_sec_offsets
                    or shndx_t in rodata_sec_offsets
                    or shndx_t in data_sec_offsets
                    or shndx_t in bss_sec_offsets
                    or shndx_t in tdata_sec_offsets
                    or shndx_t in tbss_sec_offsets
                ):
                    target_sym_name = f"__elf_sec_{shndx_t}__"
                if not target_sym_name:
                    continue
                rtype = rel["r_info_type"]
                r_off = sec_base_off + int(rel["r_offset"])
                r_addend = int(rel["r_addend"]) if rel.is_RELA() else 0
                if rtype in (2, 4):  # R_X86_64_PC32, R_X86_64_PLT32
                    mod.relocations.append(RelocationEntry(reloc_sec_name, r_off, target_sym_name, "REL32", addend=r_addend + 4))
                elif rtype in (9, 41, 42):  # R_X86_64_GOTPCREL / GOTPCRELX / REX_GOTPCRELX
                    mod.relocations.append(RelocationEntry(reloc_sec_name, r_off, target_sym_name, "GOT_REL32", addend=r_addend + 4))
                elif rtype == 23:  # R_X86_64_TPOFF32
                    mod.relocations.append(RelocationEntry(reloc_sec_name, r_off, target_sym_name, "TLS_TPOFF32", addend=r_addend))
                elif rtype == 22:  # R_X86_64_GOTTPOFF
                    mod.relocations.append(RelocationEntry(reloc_sec_name, r_off, target_sym_name, "TLS_GOTTPOFF", addend=r_addend + 4))
                elif rtype in (1, 257):  # R_X86_64_64, R_AARCH64_ABS64
                    mod.relocations.append(RelocationEntry(reloc_sec_name, r_off, target_sym_name, "ADDR64", addend=r_addend))
                elif rtype == 24:  # R_X86_64_PC64
                    mod.relocations.append(RelocationEntry(reloc_sec_name, r_off, target_sym_name, "REL64", addend=r_addend))
                elif rtype in (282, 283):  # R_AARCH64_JUMP26 / R_AARCH64_CALL26
                    mod.relocations.append(RelocationEntry(reloc_sec_name, r_off, target_sym_name, "ARM64_CALL26", addend=r_addend))
                elif rtype in (275, 311):  # R_AARCH64_ADR_PREL_PG_HI21 / R_AARCH64_ADR_GOT_PAGE
                    rk = "ARM64_GOT_PAGE21" if rtype == 311 else "ARM64_PAGE21"
                    mod.relocations.append(RelocationEntry(reloc_sec_name, r_off, target_sym_name, rk, addend=r_addend))
                elif rtype in (277, 278, 284, 285, 286, 299, 312):  # ABS_LO12 / GOT_LO12
                    rk = "ARM64_GOT_LO12" if rtype == 312 else "ARM64_LO12"
                    mod.relocations.append(RelocationEntry(reloc_sec_name, r_off, target_sym_name, rk, addend=r_addend))

    return mod


def load_macho_object(obj_bytes: bytes, repo_name: str = "macho_object") -> ObjectModule:
    """
    Parses a 64-bit Mach-O relocatable object file (`.o`, `MH_OBJECT`) for x86-64
    or ARM64 into an `ObjectModule` for unified static linking.
    """
    if len(obj_bytes) < 32:
        raise LinkerError("Truncated Mach-O object header")
    magic, cputype, _cpusub, filetype, ncmds, _szcmds, _flags, _res = struct.unpack_from("<IIIIIIII", obj_bytes, 0)
    if magic != 0xFEEDFACF:
        raise LinkerError(f"Invalid Mach-O 64 magic: 0x{magic:08x}")
    if filetype != 1:
        raise LinkerError(f"Expected MH_OBJECT (filetype=1), got {filetype}")

    mod = ObjectModule(repo_name=repo_name)
    sections_meta: List[Tuple[str, str, int, int, int, int, int]] = []
    sym_cmd: Optional[Tuple[int, int, int, int]] = None

    off = 32
    for _ in range(ncmds):
        if off + 8 > len(obj_bytes):
            break
        cmd, cmdsize = struct.unpack_from("<II", obj_bytes, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            nsects = struct.unpack_from("<I", obj_bytes, off + 64)[0]
            soff = off + 72
            for _ in range(nsects):
                sname = obj_bytes[soff : soff + 16].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                segname = obj_bytes[soff + 16 : soff + 32].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                vmaddr, sz, foff, _align, reloff, nreloc, _sflags = struct.unpack_from("<QQIIIII", obj_bytes, soff + 32)
                sections_meta.append((segname, sname, vmaddr, sz, foff, reloff, nreloc))
                soff += 80
        elif cmd == 0x02:  # LC_SYMTAB
            sym_cmd = struct.unpack_from("<IIII", obj_bytes, off + 8)
        off += cmdsize

    text_idx_1based: Optional[int] = None
    text_vmaddr = 0
    text_sz = 0
    text_reloff = 0
    text_nreloc = 0
    rodata_sec_bases: Dict[int, Tuple[int, int]] = {}
    data_sec_bases: Dict[int, Tuple[int, int, int, int]] = {}
    bss_sec_bases: Dict[int, Tuple[int, int]] = {}

    for idx_1, (segname, sname, vmaddr, sz, foff, reloff, nreloc) in enumerate(sections_meta, start=1):
        if segname == "__TEXT" and sname == "__text":
            text_idx_1based = idx_1
            text_vmaddr = vmaddr
            text_sz = sz
            text_reloff = reloff
            text_nreloc = nreloc
            mod.text_bytes.extend(obj_bytes[foff : foff + sz])
        elif segname == "__DATA" and sname in ("__bss", "__common") and sz > 0:
            bpad = (16 - (mod.bss_size % 16)) % 16
            mod.bss_size += bpad
            bss_base = mod.bss_size
            mod.bss_size += sz
            bss_sec_bases[idx_1] = (bss_base, vmaddr)
            sec_sym = f"__macho_sec_{idx_1}__"
            mod.symbols[sec_sym] = SymbolDef(
                name=sec_sym, section=".bss", offset=bss_base, size=max(1, sz), is_exported=False, source_repo=repo_name,
            )
        elif segname == "__DATA" and sname == "__data" and sz > 0:
            dpad = (16 - (len(mod.data_bytes) % 16)) % 16
            if dpad:
                mod.data_bytes.extend(b"\x00" * dpad)
            d_base = len(mod.data_bytes)
            mod.data_bytes.extend(obj_bytes[foff : foff + sz])
            data_sec_bases[idx_1] = (d_base, vmaddr, reloff, nreloc)
            sec_sym = f"__macho_sec_{idx_1}__"
            mod.symbols[sec_sym] = SymbolDef(
                name=sec_sym, section=".data", offset=d_base, size=max(1, sz), is_exported=False, source_repo=repo_name,
            )
        elif (
            (segname == "__TEXT" and (sname in ("__cstring", "__const") or sname.startswith("__literal")))
            or (segname == "__DATA" and sname == "__const")
        ) and sz > 0:
            pad = (32 - (len(mod.text_bytes) % 32)) % 32
            if pad:
                mod.text_bytes.extend(b"\x00" * pad)
            sec_base = len(mod.text_bytes)
            mod.text_bytes.extend(obj_bytes[foff : foff + sz])
            rodata_sec_bases[idx_1] = (sec_base, vmaddr)
            sec_sym = f"__macho_sec_{idx_1}__"
            mod.symbols[sec_sym] = SymbolDef(
                name=sec_sym,
                section=".rodata",
                offset=sec_base,
                size=max(1, sz),
                is_exported=False,
                source_repo=repo_name,
            )

    if text_idx_1based is None:
        raise LinkerError("Mach-O object contains no __TEXT,__text section")

    sym_clean_names: Dict[int, str] = {}
    if sym_cmd is not None:
        symoff, nsyms, stroff, _strsize = sym_cmd
        for i in range(nsyms):
            entry_off = symoff + i * 16
            if entry_off + 16 > len(obj_bytes):
                break
            strx, n_type, n_sect, _n_desc, n_val = struct.unpack_from("<IBBHQ", obj_bytes, entry_off)
            end_z = obj_bytes.find(b"\x00", stroff + strx)
            raw_name = obj_bytes[stroff + strx : (end_z if end_z != -1 else len(obj_bytes))].decode("utf-8", errors="replace")
            clean_name = raw_name[1:] if raw_name.startswith("_") else raw_name
            sym_clean_names[i] = clean_name
            is_ext = bool(n_type & 0x01)
            is_sect = (n_type & 0x0E) == 0x0E
            if is_sect and n_sect == text_idx_1based and is_ext and clean_name:
                rel_off = int(n_val - text_vmaddr)
                mod.symbols[clean_name] = SymbolDef(
                    name=clean_name,
                    section=".text",
                    offset=rel_off,
                    size=max(1, text_sz - rel_off),
                    is_exported=True,
                    source_repo=repo_name,
                )
            elif is_sect and n_sect in rodata_sec_bases and clean_name and not raw_name.startswith("ltmp"):
                sec_base, sec_vm = rodata_sec_bases[n_sect]
                mod.symbols[clean_name] = SymbolDef(
                    name=clean_name,
                    section=".rodata",
                    offset=sec_base + int(n_val - sec_vm),
                    size=8,
                    is_exported=is_ext,
                    source_repo=repo_name,
                )
            elif is_sect and n_sect in data_sec_bases and clean_name and not raw_name.startswith("ltmp"):
                d_base, d_vm, _r, _nr = data_sec_bases[n_sect]
                mod.symbols[clean_name] = SymbolDef(
                    name=clean_name,
                    section=".data",
                    offset=d_base + int(n_val - d_vm),
                    size=8,
                    is_exported=is_ext,
                    source_repo=repo_name,
                )
            elif is_sect and n_sect in bss_sec_bases and clean_name and not raw_name.startswith("ltmp"):
                b_base, b_vm = bss_sec_bases[n_sect]
                mod.symbols[clean_name] = SymbolDef(
                    name=clean_name,
                    section=".bss",
                    offset=b_base + int(n_val - b_vm),
                    size=8,
                    is_exported=is_ext,
                    source_repo=repo_name,
                )
            elif is_ext and (n_type & 0x0E) == 0 and n_val > 0 and clean_name:
                # Mach-O tentative/common symbol (`N_UNDF | N_EXT` with n_value = size)
                bpad = (16 - (mod.bss_size % 16)) % 16
                mod.bss_size += bpad
                mod.symbols[clean_name] = SymbolDef(
                    name=clean_name,
                    section=".bss",
                    offset=mod.bss_size,
                    size=int(n_val),
                    is_exported=True,
                    source_repo=repo_name,
                )
                mod.bss_size += int(n_val)

    is_arm64 = (cputype == 0x0100000C)
    macho_reloc_lists: List[Tuple[str, int, int, int, bytearray]] = [(".text", 0, text_reloff, text_nreloc, mod.text_bytes)]
    for d_base, _d_vm, d_roff, d_nrel in data_sec_bases.values():
        if d_nrel > 0:
            macho_reloc_lists.append((".data", d_base, d_roff, d_nrel, mod.data_bytes))

    for sec_lbl, sec_base_off, cur_reloff, cur_nreloc, sec_buf in macho_reloc_lists:
        pending_addend = 0
        for r_i in range(cur_nreloc):
            ro = cur_reloff + r_i * 8
            if ro + 8 > len(obj_bytes):
                break
            r_addr, r_val = struct.unpack_from("<iI", obj_bytes, ro)
            if r_addr < 0:
                continue
            r_sym = r_val & 0x00FFFFFF
            r_len = (r_val >> 25) & 3
            r_ext = (r_val >> 27) & 1
            r_type = (r_val >> 28) & 0xF
            if is_arm64 and r_type == 10:  # ARM64_RELOC_ADDEND
                add24 = r_sym
                if add24 & (1 << 23):
                    add24 -= (1 << 24)
                pending_addend = add24
                continue
            cur_addend = pending_addend
            pending_addend = 0
            patch_off = sec_base_off + r_addr
            if r_ext == 1:
                target_sym = sym_clean_names.get(r_sym, "")
                if not target_sym:
                    continue
                if is_arm64:
                    if r_type == 2:
                        mod.relocations.append(RelocationEntry(sec_lbl, patch_off, target_sym, "ARM64_CALL26", addend=cur_addend))
                    elif r_type == 3:
                        mod.relocations.append(RelocationEntry(sec_lbl, patch_off, target_sym, "ARM64_PAGE21", addend=cur_addend))
                    elif r_type == 4:
                        mod.relocations.append(RelocationEntry(sec_lbl, patch_off, target_sym, "ARM64_LO12", addend=cur_addend))
                    elif r_type == 0 and r_len == 3:
                        mod.relocations.append(RelocationEntry(sec_lbl, patch_off, target_sym, "ADDR64", addend=cur_addend))
                else:
                    if r_type in (1, 2, 3) and r_len == 2:
                        mod.relocations.append(RelocationEntry(sec_lbl, patch_off, target_sym, "REL32", addend=0))
                    elif r_type == 0 and r_len == 3:
                        mod.relocations.append(RelocationEntry(sec_lbl, patch_off, target_sym, "ADDR64", addend=0))
            else:
                if r_sym in rodata_sec_bases or r_sym in data_sec_bases or r_sym in bss_sec_bases:
                    sec_vm = (
                        rodata_sec_bases[r_sym][1]
                        if r_sym in rodata_sec_bases
                        else (data_sec_bases[r_sym][1] if r_sym in data_sec_bases else bss_sec_bases[r_sym][1])
                    )
                    if not is_arm64 and r_type == 1 and r_len == 2:
                        init_disp = struct.unpack_from("<i", sec_buf, patch_off)[0] if patch_off + 4 <= len(sec_buf) else 0
                        inner_addend = (r_addr + 4 + init_disp) - sec_vm
                        mod.relocations.append(RelocationEntry(sec_lbl, patch_off, f"__macho_sec_{r_sym}__", "REL32", addend=inner_addend))
                    elif is_arm64 and r_type in (3, 4):
                        rel_kind = "ARM64_PAGE21" if r_type == 3 else "ARM64_LO12"
                        mod.relocations.append(RelocationEntry(sec_lbl, patch_off, f"__macho_sec_{r_sym}__", rel_kind, addend=cur_addend))

    return mod


def load_static_archive(archive_bytes: bytes, repo_name: str = "static_archive") -> List[ObjectModule]:
    """
    Parses a standard UNIX `ar` (`!<arch>\\n`) static library `.a` (and COFF `.lib` archives)
    supporting GNU longnames (`//`) and BSD `#1/<len>` names, returning parsed `ObjectModule` members.
    """
    if not archive_bytes.startswith(b"!<arch>\n"):
        raise LinkerError("Invalid static archive header (expected '!<arch>\\n')")

    modules: List[ObjectModule] = []
    gnu_longnames = b""
    pos = 8
    total_len = len(archive_bytes)
    member_idx = 0

    while pos + 60 <= total_len:
        hdr = archive_bytes[pos : pos + 60]
        if hdr[58:60] != b"`\n":
            break
        raw_name = hdr[0:16].decode("ascii", errors="replace").rstrip(" ")
        size_str = hdr[48:58].decode("ascii", errors="replace").strip()
        try:
            member_size = int(size_str)
        except ValueError:
            break
        data_start = pos + 60
        data_end = min(total_len, data_start + member_size)
        member_data = archive_bytes[data_start:data_end]
        pos = data_end + (1 if (member_size % 2) == 1 else 0)

        if raw_name in ("/", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED", "__.SYMDEF_64", "__.SYMDEF_64 SORTED"):
            continue
        if raw_name == "//":
            gnu_longnames = member_data
            continue

        member_name = raw_name.rstrip("/")
        if raw_name.startswith("#1/"):
            try:
                nlen = int(raw_name[3:])
                member_name = member_data[:nlen].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                member_data = member_data[nlen:]
            except ValueError:
                pass
        elif raw_name.startswith("/") and raw_name[1:].isdigit() and gnu_longnames:
            noff = int(raw_name[1:])
            if noff < len(gnu_longnames):
                end_n = gnu_longnames.find(b"\n", noff)
                chunk = gnu_longnames[noff:] if end_n == -1 else gnu_longnames[noff:end_n]
                member_name = chunk.decode("utf-8", errors="replace").rstrip("/\r")

        if member_name.startswith("__.SYMDEF"):
            continue

        m_label = f"{repo_name}:{member_name or member_idx}"
        member_idx += 1
        try:
            if member_data[:4] == b"\x7fELF":
                modules.append(load_elf_object(member_data, repo_name=m_label))
            elif member_data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
                modules.append(load_macho_object(member_data, repo_name=m_label))
            elif len(member_data) >= 20 and struct.unpack_from("<H", member_data, 0)[0] in (0x8664, 0xAA64):
                modules.append(load_coff_object(member_data, repo_name=m_label))
        except Exception:
            continue

    return modules


# ==============================================================================
# Static Multi-Module Linker
# ==============================================================================

# Freestanding native x86-64 machine code kernels for runtime collection operations
# Enables freestanding standalone binaries (.exe / ELF / Mach-O) to execute without host Python runtime.
NATIVE_FREESTANDING_KERNELS_X64: Dict[str, bytes] = {
    "omni_list_len": bytes.fromhex("4885c97405488b4108c331c0c3"),
    "omni_list_get": bytes.fromhex("4885c97406488b44d110c331c0c3"),
    "omni_list_set": bytes.fromhex("4885c974174c8944d110483b51087208488d4201488941084889c8c331c0c3"),
    "omni_item_len": bytes.fromhex("4885c97405488b4108c331c0c3"),
    "omni_item_get": bytes.fromhex("4885c97406488b44d110c331c0c3"),
    "omni_item_set": bytes.fromhex("4885c974174c8944d110483b51087208488d4201488941084889c8c331c0c3"),
    "omni_str_len": bytes.fromhex("4885c974100fb601a880750483e07fc3488b4108c331c0c3"),
    "omni_list_sum": bytes.fromhex("4885c9741c488b51084885d2741331c04531c04a0344c11049ffc04939d07cf3c331c0c3"),
}

NATIVE_FREESTANDING_KERNELS_X64_SYSV: Dict[str, bytes] = {
    "omni_list_len": bytes.fromhex("4885ff7405488b4708c331c0c3"),
    "omni_list_get": bytes.fromhex("4885ff7406488b44f710c331c0c3"),
    "omni_list_set": bytes.fromhex("4885ff7417488954f710483b77087208488d4601488947084889f8c331c0c3"),
    "omni_item_len": bytes.fromhex("4885ff7405488b4708c331c0c3"),
    "omni_item_get": bytes.fromhex("4885ff7406488b44f710c331c0c3"),
    "omni_item_set": bytes.fromhex("4885ff7417488954f710483b77087208488d4601488947084889f8c331c0c3"),
    "omni_str_len": bytes.fromhex("4885ff74100fb607a880750483e07fc3488b4708c331c0c3"),
    "omni_list_sum": bytes.fromhex("4885ff741c488b57084885d2741331c04531c04a0344c71049ffc04939d07cf3c331c0c3"),
}

OS_C_ABI_IMPORT_TABLE: Dict[str, Tuple[str, str]] = {
    "ExitProcess": ("KERNEL32.dll", "libc.so.6"),
    "GetCommandLineA": ("KERNEL32.dll", "libc.so.6"),
    "Sleep": ("KERNEL32.dll", "libc.so.6"),
    "abs": ("MSVCRT.dll", "libc.so.6"),
    "labs": ("MSVCRT.dll", "libc.so.6"),
    "atoi": ("MSVCRT.dll", "libc.so.6"),
    "atol": ("MSVCRT.dll", "libc.so.6"),
    "puts": ("MSVCRT.dll", "libc.so.6"),
    "putchar": ("MSVCRT.dll", "libc.so.6"),
    "strlen": ("MSVCRT.dll", "libc.so.6"),
    "strcmp": ("MSVCRT.dll", "libc.so.6"),
    "printf": ("MSVCRT.dll", "libc.so.6"),
    "malloc": ("MSVCRT.dll", "libc.so.6"),
    "calloc": ("MSVCRT.dll", "libc.so.6"),
    "realloc": ("MSVCRT.dll", "libc.so.6"),
    "free": ("MSVCRT.dll", "libc.so.6"),
    "memcpy": ("MSVCRT.dll", "libc.so.6"),
    "memset": ("MSVCRT.dll", "libc.so.6"),
    "memmove": ("MSVCRT.dll", "libc.so.6"),
    "exit": ("MSVCRT.dll", "libc.so.6"),
    "sin": ("MSVCRT.dll", "libm.so.6"),
    "cos": ("MSVCRT.dll", "libm.so.6"),
    "tan": ("MSVCRT.dll", "libm.so.6"),
    "sqrt": ("MSVCRT.dll", "libm.so.6"),
    "pow": ("MSVCRT.dll", "libm.so.6"),
    "floor": ("MSVCRT.dll", "libm.so.6"),
    "ceil": ("MSVCRT.dll", "libm.so.6"),
    "fabs": ("MSVCRT.dll", "libm.so.6"),
    "exp": ("MSVCRT.dll", "libm.so.6"),
    "expf": ("MSVCRT.dll", "libm.so.6"),
    "exp2": ("MSVCRT.dll", "libm.so.6"),
    "log": ("MSVCRT.dll", "libm.so.6"),
    "logf": ("MSVCRT.dll", "libm.so.6"),
    "log2": ("MSVCRT.dll", "libm.so.6"),
    "log10": ("MSVCRT.dll", "libm.so.6"),
    "asin": ("MSVCRT.dll", "libm.so.6"),
    "acos": ("MSVCRT.dll", "libm.so.6"),
    "atan": ("MSVCRT.dll", "libm.so.6"),
    "atan2": ("MSVCRT.dll", "libm.so.6"),
    "sinh": ("MSVCRT.dll", "libm.so.6"),
    "cosh": ("MSVCRT.dll", "libm.so.6"),
    "tanh": ("MSVCRT.dll", "libm.so.6"),
    "cbrt": ("MSVCRT.dll", "libm.so.6"),
    "hypot": ("MSVCRT.dll", "libm.so.6"),
    "fmod": ("MSVCRT.dll", "libm.so.6"),
    "round": ("MSVCRT.dll", "libm.so.6"),
    "trunc": ("MSVCRT.dll", "libm.so.6"),
    "qsort": ("MSVCRT.dll", "libc.so.6"),
    "bsearch": ("MSVCRT.dll", "libc.so.6"),
    "strtol": ("MSVCRT.dll", "libc.so.6"),
    "strtoul": ("MSVCRT.dll", "libc.so.6"),
    "strtod": ("MSVCRT.dll", "libc.so.6"),
    "strncmp": ("MSVCRT.dll", "libc.so.6"),
    "strcpy": ("MSVCRT.dll", "libc.so.6"),
    "strncpy": ("MSVCRT.dll", "libc.so.6"),
    "strcat": ("MSVCRT.dll", "libc.so.6"),
    "strchr": ("MSVCRT.dll", "libc.so.6"),
    "strstr": ("MSVCRT.dll", "libc.so.6"),
    "memcmp": ("MSVCRT.dll", "libc.so.6"),
    "memchr": ("MSVCRT.dll", "libc.so.6"),
    "sprintf": ("MSVCRT.dll", "libc.so.6"),
    "snprintf": ("MSVCRT.dll", "libc.so.6"),
    "vsnprintf": ("MSVCRT.dll", "libc.so.6"),
    "fprintf": ("MSVCRT.dll", "libc.so.6"),
    "fwrite": ("MSVCRT.dll", "libc.so.6"),
    "fread": ("MSVCRT.dll", "libc.so.6"),
    "fopen": ("MSVCRT.dll", "libc.so.6"),
    "fclose": ("MSVCRT.dll", "libc.so.6"),
    "fflush": ("MSVCRT.dll", "libc.so.6"),
    "abort": ("MSVCRT.dll", "libc.so.6"),
    "raise": ("MSVCRT.dll", "libc.so.6"),
    "getenv": ("MSVCRT.dll", "libc.so.6"),
    "time": ("MSVCRT.dll", "libc.so.6"),
    "rand": ("MSVCRT.dll", "libc.so.6"),
    "srand": ("MSVCRT.dll", "libc.so.6"),
    "clock_gettime": ("KERNEL32.dll", "libc.so.6"),
    "gettimeofday": ("KERNEL32.dll", "libc.so.6"),
    "usleep": ("KERNEL32.dll", "libc.so.6"),
    "nanosleep": ("KERNEL32.dll", "libc.so.6"),
    "pthread_create": ("KERNEL32.dll", "libpthread.so.0"),
    "pthread_join": ("KERNEL32.dll", "libpthread.so.0"),
    "pthread_mutex_init": ("KERNEL32.dll", "libpthread.so.0"),
    "pthread_mutex_lock": ("KERNEL32.dll", "libpthread.so.0"),
    "pthread_mutex_unlock": ("KERNEL32.dll", "libpthread.so.0"),
    "pthread_mutex_destroy": ("KERNEL32.dll", "libpthread.so.0"),
    "dlopen": ("KERNEL32.dll", "libdl.so.2"),
    "dlsym": ("KERNEL32.dll", "libdl.so.2"),
    "dlclose": ("KERNEL32.dll", "libdl.so.2"),
    "GetTickCount64": ("KERNEL32.dll", "libc.so.6"),
    "QueryPerformanceCounter": ("KERNEL32.dll", "libc.so.6"),
    "VirtualAlloc": ("KERNEL32.dll", "libc.so.6"),
    "VirtualFree": ("KERNEL32.dll", "libc.so.6"),
    "VirtualProtect": ("KERNEL32.dll", "libc.so.6"),
    "GetCurrentThreadId": ("KERNEL32.dll", "libc.so.6"),
    "GetCurrentProcessId": ("KERNEL32.dll", "libc.so.6"),
}


_LIBM_SYMBOLS = frozenset({
    "sin", "sinf", "cos", "cosf", "tan", "tanf", "asin", "acos", "atan", "atan2",
    "sinh", "cosh", "tanh", "exp", "expf", "exp2", "log", "logf", "log2", "log10",
    "sqrt", "sqrtf", "cbrt", "hypot", "pow", "powf", "floor", "ceil", "round", "trunc",
    "fabs", "fabsf", "fmod", "fma",
})


def _is_cpp_abi_runtime_symbol(sym_name: str) -> bool:
    return sym_name == "__gxx_personality_v0" or sym_name.startswith(
        ("_Unwind_", "__cxa_", "_Z", "__dynamic_cast")
    )


def _infer_dynamic_lib_pair(sym_name: str, lib_hints: Optional[Dict[str, Tuple[str, str]]] = None) -> Tuple[str, str]:
    if lib_hints and sym_name in lib_hints:
        return lib_hints[sym_name]
    if sym_name in OS_C_ABI_IMPORT_TABLE:
        return OS_C_ABI_IMPORT_TABLE[sym_name]
    if sym_name.startswith("_Unwind_"):
        return ("KERNEL32.dll", "libgcc_s.so.1")
    if sym_name == "__gxx_personality_v0" or sym_name.startswith(("__cxa_", "_Z", "__dynamic_cast")):
        return ("VCRUNTIME140.dll", "libstdc++.so.6")
    if sym_name.startswith("pthread_"):
        return ("KERNEL32.dll", "libpthread.so.0")
    if sym_name in _LIBM_SYMBOLS:
        return ("MSVCRT.dll", "libm.so.6")
    if sym_name in ("dlopen", "dlsym", "dlclose", "dlerror"):
        return ("KERNEL32.dll", "libdl.so.2")
    if sym_name[:1].isupper() and any(sym_name.endswith(sfx) for sfx in ("A", "W", "64", "Ex", "File", "Alloc", "Free")):
        return ("KERNEL32.dll", "libc.so.6")
    return ("MSVCRT.dll", "libc.so.6")


class NativeObjectLinker:
    """
    Combines and resolves multiple `ObjectModule`s into fully linked native executables
    and multi-symbol shared libraries (`.dll` / `.so` / `.dylib`).
    """

    def __init__(
        self,
        target_os: Optional[str] = None,
        allow_open_dynamic_imports: bool = False,
        external_lib_hints: Optional[Dict[str, Tuple[str, str]]] = None,
        gc_sections: bool = False,
        icf_folding: bool = False,
    ):
        self.modules: List[ObjectModule] = []
        self.archives: List[List[ObjectModule]] = []
        self.emitter = StandaloneBinaryEmitter()
        self.target_os: Optional[str] = target_os
        self.allow_open_dynamic_imports: bool = bool(allow_open_dynamic_imports)
        self.external_lib_hints: Dict[str, Tuple[str, str]] = dict(external_lib_hints or {})
        self.hot_weights: Dict[str, int] = {}
        self.gc_sections: bool = bool(gc_sections)
        self.icf_folding: bool = bool(icf_folding)

    def add_module(self, module: ObjectModule):
        self.modules.append(module)

    def add_static_archive(self, archive_bytes: bytes, repo_name: str = "static_archive") -> List[ObjectModule]:
        members = load_static_archive(archive_bytes, repo_name=repo_name)
        if members:
            self.archives.append(members)
        return members

    def add_coff_object(self, obj_bytes: bytes, repo_name: str = "coff_object") -> ObjectModule:
        mod = load_coff_object(obj_bytes, repo_name=repo_name)
        self.add_module(mod)
        return mod

    def add_elf_object(self, obj_bytes: bytes, repo_name: str = "elf_object") -> ObjectModule:
        mod = load_elf_object(obj_bytes, repo_name=repo_name)
        self.add_module(mod)
        return mod

    def add_macho_object(self, obj_bytes: bytes, repo_name: str = "macho_object") -> ObjectModule:
        mod = load_macho_object(obj_bytes, repo_name=repo_name)
        self.add_module(mod)
        return mod

    def link(
        self,
        entry_symbol: Optional[str] = None,
        target_os: Optional[str] = None,
        data_vaddr_delta: Optional[int] = None,
        text_vaddr_base: int = 0,
        image_base: int = 0,
        hot_weights: Optional[Dict[str, int]] = None,
        gc_sections: Optional[bool] = None,
        icf_folding: Optional[bool] = None,
        gc_roots: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """
        Executes static linking pass across all modules + static archives (`.a`/`.lib`):
        1. Resolves archive members on-demand for unresolved external symbols.
        2. Separates executable `.text`/`.rodata` from writable `.data` + zero-fill `.bss`.
        3. Allocates internal PIC GOT slots for `GOT_REL32` / `ARM64_GOT_*` references.
        4. Patches cross-section x86-64/ARM64/RV64GC relocations across `.text`, `.rodata`, `.data`, `.bss`.
        """
        eff_target_os = (target_os or self.target_os or ("windows" if sys.platform == "win32" else "linux")).lower()
        is_win_abi = eff_target_os in ("win", "win32", "windows")

        try:
            from runtime.native_heap import NATIVE_COLLECTION_SYMBOLS
        except ImportError:
            NATIVE_COLLECTION_SYMBOLS = {}
        try:
            from runtime.native_atomics import NATIVE_ATOMIC_SYMBOL_NAMES, get_atomic_kernels
        except ImportError:
            NATIVE_ATOMIC_SYMBOL_NAMES = frozenset()
            get_atomic_kernels = None
        try:
            from runtime.native_sanitizer import NATIVE_SANITIZER_SYMBOL_NAMES, get_sanitizer_kernels
        except ImportError:
            NATIVE_SANITIZER_SYMBOL_NAMES = frozenset()
            get_sanitizer_kernels = None

        work_modules: List[ObjectModule] = list(self.modules)

        # 0. Demand-driven Static Archive (.a / .lib) member extraction (fixed-point worklist)
        if self.archives:
            defined_pre: set = {s for mod in work_modules for s in mod.symbols}
            archive_index: Dict[str, Tuple[int, int, ObjectModule]] = {}
            for p_idx, pool in enumerate(self.archives):
                for m_idx, member in enumerate(pool):
                    for sname, sdef in member.symbols.items():
                        if sdef.is_exported and sname not in archive_index:
                            archive_index[sname] = (p_idx, m_idx, member)
            pulled_members: set = set()
            changed_arch = True
            while changed_arch:
                changed_arch = False
                for mod in list(work_modules):
                    for reloc in mod.relocations:
                        sym_n = reloc.symbol_name
                        if sym_n not in defined_pre and sym_n in archive_index:
                            p_i, m_i, cand = archive_index[sym_n]
                            if (p_i, m_i) not in pulled_members:
                                pulled_members.add((p_i, m_i))
                                work_modules.append(cand)
                                defined_pre.update(cand.symbols.keys())
                                changed_arch = True

        # 0b. Reachable --gc-sections Dead-Module Elimination (BFS from entry/exported/init roots)
        use_gc = self.gc_sections if gc_sections is None else bool(gc_sections)
        gc_eliminated_modules = 0
        gc_bytes_reclaimed = 0
        if use_gc and len(work_modules) > 1:
            sym_to_mod_idxs: Dict[str, List[int]] = {}
            for m_i, mod in enumerate(work_modules):
                for sname in mod.symbols:
                    sym_to_mod_idxs.setdefault(sname, []).append(m_i)
            alive_idxs: set = set()
            if gc_roots is not None:
                root_syms = set(gc_roots)
                for rs in root_syms:
                    alive_idxs.update(sym_to_mod_idxs.get(rs, ()))
            else:
                if entry_symbol and entry_symbol in sym_to_mod_idxs:
                    alive_idxs.update(sym_to_mod_idxs[entry_symbol])
                for m_i, mod in enumerate(work_modules):
                    if mod.init_array_bytes or mod.fini_array_bytes:
                        alive_idxs.add(m_i)
                        continue
                    if any(
                        sd.is_exported and not sname.startswith(("__elf_sec_", "__coff_sec_", "__macho_sec_"))
                        for sname, sd in mod.symbols.items()
                    ):
                        alive_idxs.add(m_i)
                if not alive_idxs:
                    alive_idxs.add(0)
            bfs_q = list(sorted(alive_idxs))
            while bfs_q:
                cur_i = bfs_q.pop(0)
                for rel in work_modules[cur_i].relocations:
                    for dep_i in sym_to_mod_idxs.get(rel.symbol_name, ()):
                        if dep_i not in alive_idxs:
                            alive_idxs.add(dep_i)
                            bfs_q.append(dep_i)
            kept_modules: List[ObjectModule] = []
            for m_i, mod in enumerate(work_modules):
                if m_i in alive_idxs:
                    kept_modules.append(mod)
                else:
                    gc_eliminated_modules += 1
                    gc_bytes_reclaimed += len(mod.text_bytes) + len(mod.data_bytes)
            work_modules = kept_modules

        defined_syms: set = {s for mod in work_modules for s in mod.symbols}

        needed_runtime_syms = set()
        needed_atomic_syms = set()
        needed_sanitizer_syms = set()
        needed_os_syms = set()
        needed_got_syms = set()
        needed_tls_got_syms = set()
        for mod in work_modules:
            for reloc in mod.relocations:
                if reloc.symbol_name == "_GLOBAL_OFFSET_TABLE_":
                    continue
                if reloc.reloc_type in ("GOT_REL32", "ARM64_GOT_PAGE21", "ARM64_GOT_LO12"):
                    needed_got_syms.add(reloc.symbol_name)
                elif reloc.reloc_type == "TLS_GOTTPOFF":
                    needed_tls_got_syms.add(reloc.symbol_name)
                if reloc.symbol_name not in defined_syms:
                    if reloc.symbol_name in NATIVE_SANITIZER_SYMBOL_NAMES:
                        needed_sanitizer_syms.add(reloc.symbol_name)
                    elif reloc.symbol_name in NATIVE_ATOMIC_SYMBOL_NAMES:
                        needed_atomic_syms.add(reloc.symbol_name)
                    elif reloc.symbol_name in NATIVE_COLLECTION_SYMBOLS:
                        needed_runtime_syms.add(reloc.symbol_name)
                    elif reloc.symbol_name in OS_C_ABI_IMPORT_TABLE or _is_cpp_abi_runtime_symbol(reloc.symbol_name):
                        needed_os_syms.add(reloc.symbol_name)
                    elif (
                        self.allow_open_dynamic_imports
                        and not reloc.symbol_name.startswith(("__omni_", "__elf_sec_", "__coff_sec_", "__macho_sec_"))
                    ):
                        needed_os_syms.add(reloc.symbol_name)

        if needed_sanitizer_syms and get_sanitizer_kernels is not None:
            is_arm64_link = any(
                r.reloc_type == "ARM64_CALL26"
                for m in work_modules
                for r in m.relocations
            )
            host_os = "windows" if is_win_abi else "linux"
            san_map = get_sanitizer_kernels(target_os=host_os, arch="arm64" if is_arm64_link else "x86_64")
            san_mod = ObjectModule("__omni_sanitizer_thunks__")
            for sym in sorted(needed_sanitizer_syms):
                if sym in san_map:
                    san_mod.add_symbol(sym, san_map[sym], is_exported=False)
            work_modules.append(san_mod)

        if needed_atomic_syms and get_atomic_kernels is not None:
            is_arm64_link = any(
                r.reloc_type == "ARM64_CALL26"
                for m in work_modules
                for r in m.relocations
            )
            host_os = "windows" if is_win_abi else "linux"
            atomic_map = get_atomic_kernels(target_os=host_os, arch="arm64" if is_arm64_link else "x86_64")
            atomic_mod = ObjectModule("__omni_atomic_kernels__")
            for sym in sorted(needed_atomic_syms):
                if sym in atomic_map:
                    atomic_mod.add_symbol(sym, atomic_map[sym], is_exported=True)
            work_modules.append(atomic_mod)

        if needed_runtime_syms:
            if not hasattr(self, "_active_callbacks"):
                self._active_callbacks = []
            runtime_mod = ObjectModule("__omni_runtime_thunks__")
            kernels_map = NATIVE_FREESTANDING_KERNELS_X64 if is_win_abi else NATIVE_FREESTANDING_KERNELS_X64_SYSV
            for sym in sorted(needed_runtime_syms):
                if sym in kernels_map:
                    runtime_mod.add_symbol(sym, kernels_map[sym], is_exported=True)
                else:
                    fn_meta = NATIVE_COLLECTION_SYMBOLS[sym]
                    fn_obj, arg_types, res_type = fn_meta
                    c_fn = ctypes.CFUNCTYPE(res_type, *arg_types)(fn_obj)
                    self._active_callbacks.append(c_fn)
                    addr = ctypes.cast(c_fn, ctypes.c_void_p).value
                    thunk_bytes = b"\x49\xbb" + struct.pack("<Q", addr) + b"\x41\xff\xe3\xc3"
                    runtime_mod.add_symbol(sym, thunk_bytes, is_exported=True)
            work_modules.append(runtime_mod)

        if needed_os_syms:
            is_arm64_link = any(
                r.reloc_type == "ARM64_CALL26"
                for m in work_modules
                for r in m.relocations
            )
            os_mod = ObjectModule("__omni_os_imports__")
            for sym in sorted(needed_os_syms):
                if is_arm64_link:
                    if sym in ("malloc", "calloc", "realloc"):
                        stub = struct.pack("<III", 0xD2930000, 0xF2A04000, 0xD65F03C0)
                    else:
                        stub = struct.pack("<III", 0x52800000, 0xD65F03C0, 0xD503201F)
                else:
                    if sym in ("malloc", "calloc", "realloc"):
                        stub = b"\xb8" + struct.pack("<I", 0x2009800) + b"\xc3"
                    else:
                        stub = b"\x31\xc0\xc3\x90\x90\x90"
                os_mod.add_symbol(sym, stub, is_exported=False)
            work_modules.append(os_mod)

        # 1. Section Aggregation (.text/.rodata vs RW .data/.init_array/.fini_array/.bss + TLS .tdata/.tbss)
        eff_hot_weights = dict(self.hot_weights)
        if hot_weights:
            eff_hot_weights.update({str(k): int(v) for k, v in hot_weights.items()})
        if eff_hot_weights:
            work_modules = [
                m for _, m in sorted(
                    enumerate(work_modules),
                    key=lambda item: (
                        -max((eff_hot_weights.get(s, 0) for s in item[1].symbols), default=0),
                        item[0],
                    ),
                )
            ]

        combined_text = bytearray()
        combined_data = bytearray()
        combined_tdata = bytearray()
        total_bss_size = 0
        total_tbss_size = 0
        module_text_offsets: Dict[int, int] = {}
        module_data_offsets: Dict[int, int] = {}
        module_bss_offsets: Dict[int, int] = {}
        module_tdata_offsets: Dict[int, int] = {}
        module_tbss_offsets: Dict[int, int] = {}
        module_init_offsets: Dict[int, int] = {}
        module_fini_offsets: Dict[int, int] = {}

        use_icf = self.icf_folding if icf_folding is None else bool(icf_folding)
        icf_seen_canon: Dict[Tuple[bytes, Tuple[Any, ...]], int] = {}
        icf_folded_indices: set = set()
        icf_folded_modules = 0
        icf_bytes_saved = 0
        icf_folded_symbols: List[str] = []

        for idx, mod in enumerate(work_modules):
            can_icf = (
                use_icf
                and not mod.repo_name.startswith("__omni_")
                and len(mod.text_bytes) >= 4
                and not mod.data_bytes
                and mod.bss_size == 0
                and not mod.tdata_bytes
                and mod.tbss_size == 0
                and not mod.init_array_bytes
                and not mod.fini_array_bytes
                and not getattr(mod, "eh_frame_bytes", b"")
                and all(sd.section == ".text" for sd in mod.symbols.values())
                and all(r.section == ".text" for r in mod.relocations)
            )
            folded_into_off: Optional[int] = None
            if can_icf:
                reloc_sig = tuple(
                    (
                        r.offset,
                        ("LOCAL", mod.symbols[r.symbol_name].offset) if r.symbol_name in mod.symbols else ("EXT", r.symbol_name),
                        r.reloc_type,
                        r.addend,
                    )
                    for r in sorted(mod.relocations, key=lambda x: (x.offset, x.symbol_name, x.reloc_type, x.addend))
                )
                icf_key = (bytes(mod.text_bytes), reloc_sig)
                if icf_key in icf_seen_canon:
                    folded_into_off = icf_seen_canon[icf_key]
            if folded_into_off is not None:
                module_text_offsets[idx] = folded_into_off
                icf_folded_indices.add(idx)
                icf_folded_modules += 1
                icf_bytes_saved += len(mod.text_bytes)
                icf_folded_symbols.extend(sorted(s for s in mod.symbols if not s.startswith("__")))
            else:
                pad = (32 - (len(combined_text) % 32)) % 32
                if pad:
                    combined_text.extend(b"\x90" * pad)
                module_text_offsets[idx] = len(combined_text)
                if can_icf:
                    icf_seen_canon[icf_key] = module_text_offsets[idx]  # type: ignore[possibly-undefined]
                combined_text.extend(mod.text_bytes)

            if mod.data_bytes:
                dpad = (16 - (len(combined_data) % 16)) % 16
                if dpad:
                    combined_data.extend(b"\x00" * dpad)
                module_data_offsets[idx] = len(combined_data)
                combined_data.extend(mod.data_bytes)
            else:
                module_data_offsets[idx] = len(combined_data)

            if mod.bss_size > 0:
                bpad = (16 - (total_bss_size % 16)) % 16
                total_bss_size += bpad
                module_bss_offsets[idx] = total_bss_size
                total_bss_size += mod.bss_size
            else:
                module_bss_offsets[idx] = total_bss_size

            if mod.tdata_bytes:
                tpad = (8 - (len(combined_tdata) % 8)) % 8
                if tpad:
                    combined_tdata.extend(b"\x00" * tpad)
                module_tdata_offsets[idx] = len(combined_tdata)
                combined_tdata.extend(mod.tdata_bytes)
            else:
                module_tdata_offsets[idx] = len(combined_tdata)

            if mod.tbss_size > 0:
                tbpad = (8 - (total_tbss_size % 8)) % 8
                total_tbss_size += tbpad
                module_tbss_offsets[idx] = total_tbss_size
                total_tbss_size += mod.tbss_size
            else:
                module_tbss_offsets[idx] = total_tbss_size

        # Append combined DWARF .eh_frame tables after .text/.rodata in RX segment
        module_eh_offsets: Dict[int, int] = {}
        eh_frame_offset_in_code = 0
        eh_frame_size = 0
        if any(getattr(mod, "eh_frame_bytes", b"") for mod in work_modules):
            eh_pad = (8 - (len(combined_text) % 8)) % 8
            if eh_pad:
                combined_text.extend(b"\x90" * eh_pad)
            eh_frame_offset_in_code = len(combined_text)
            for idx, mod in enumerate(work_modules):
                eh_raw = bytes(getattr(mod, "eh_frame_bytes", b""))
                if not eh_raw:
                    continue
                if len(eh_raw) >= 4 and eh_raw.endswith(b"\x00\x00\x00\x00"):
                    eh_raw = eh_raw[:-4]
                if not eh_raw:
                    continue
                sub_eh_pad = (8 - (len(combined_text) % 8)) % 8
                if sub_eh_pad:
                    combined_text.extend(b"\x00" * sub_eh_pad)
                module_eh_offsets[idx] = len(combined_text)
                combined_text.extend(eh_raw)
            if len(combined_text) > eh_frame_offset_in_code:
                combined_text.extend(b"\x00\x00\x00\x00")
                eh_frame_size = len(combined_text) - eh_frame_offset_in_code
            else:
                eh_frame_offset_in_code = 0

        # Reserve internal GOT slots & TLS GOTTPOFF slots inside writable .data
        got_slot_data_offsets: Dict[str, int] = {}
        if needed_got_syms:
            gpad = (8 - (len(combined_data) % 8)) % 8
            if gpad:
                combined_data.extend(b"\x00" * gpad)
            for gsym in sorted(needed_got_syms):
                got_slot_data_offsets[gsym] = len(combined_data)
                combined_data.extend(b"\x00" * 8)

        tls_got_slot_offsets: Dict[str, int] = {}
        if needed_tls_got_syms:
            gpad2 = (8 - (len(combined_data) % 8)) % 8
            if gpad2:
                combined_data.extend(b"\x00" * gpad2)
            for tsym in sorted(needed_tls_got_syms):
                tls_got_slot_offsets[tsym] = len(combined_data)
                combined_data.extend(b"\x00" * 8)

        # Append .init_array and .fini_array constructor/destructor pointer tables inside RW .data
        init_array_offset_in_data = 0
        init_array_size = 0
        if any(mod.init_array_bytes for mod in work_modules):
            ipad = (8 - (len(combined_data) % 8)) % 8
            if ipad:
                combined_data.extend(b"\x00" * ipad)
            init_array_offset_in_data = len(combined_data)
            for idx, mod in enumerate(work_modules):
                if mod.init_array_bytes:
                    subpad = (8 - (len(combined_data) % 8)) % 8
                    if subpad:
                        combined_data.extend(b"\x00" * subpad)
                    module_init_offsets[idx] = len(combined_data)
                    combined_data.extend(mod.init_array_bytes)
            init_array_size = len(combined_data) - init_array_offset_in_data

        fini_array_offset_in_data = 0
        fini_array_size = 0
        if any(mod.fini_array_bytes for mod in work_modules):
            fpad = (8 - (len(combined_data) % 8)) % 8
            if fpad:
                combined_data.extend(b"\x00" * fpad)
            fini_array_offset_in_data = len(combined_data)
            for idx, mod in enumerate(work_modules):
                if mod.fini_array_bytes:
                    subpad = (8 - (len(combined_data) % 8)) % 8
                    if subpad:
                        combined_data.extend(b"\x00" * subpad)
                    module_fini_offsets[idx] = len(combined_data)
                    combined_data.extend(mod.fini_array_bytes)
            fini_array_size = len(combined_data) - fini_array_offset_in_data

        total_tdata_size = len(combined_tdata)
        tls_total_memsz = ((total_tdata_size + total_tbss_size + 15) // 16) * 16 if (total_tdata_size or total_tbss_size) else 0
        has_rw_section = bool(combined_data) or (total_bss_size > 0) or (tls_total_memsz > 0)
        eff_data_delta = (
            data_vaddr_delta
            if data_vaddr_delta is not None
            else (((len(combined_text) + 0xFFF) // 0x1000) * 0x1000 if has_rw_section else 0)
        )
        # BSS follows aligned data_bytes in the RW section
        bss_start_in_data = ((len(combined_data) + 15) // 16) * 16

        global_symbol_table: Dict[str, int] = {}
        exported_symbols: Dict[str, int] = {}
        external_os_imports: Dict[str, int] = {}
        local_symbol_offsets: Dict[Tuple[int, str], int] = {}
        tls_symbol_offsets: Dict[Tuple[int, str], int] = {}
        global_tls_offsets: Dict[str, int] = {}

        for idx, mod in enumerate(work_modules):
            t_off = module_text_offsets[idx]
            d_off = module_data_offsets[idx]
            b_off = module_bss_offsets[idx]
            td_off = module_tdata_offsets[idx]
            tb_off = module_tbss_offsets[idx]
            for sym_name, sym in mod.symbols.items():
                if sym.section in (".tdata", ".tbss"):
                    tls_off = (td_off + sym.offset) if sym.section == ".tdata" else (total_tdata_size + tb_off + sym.offset)
                    tls_symbol_offsets[(idx, sym_name)] = tls_off
                    global_tls_offsets[sym_name] = tls_off
                    global_offset = tls_off
                elif sym.section in (".text", ".rodata"):
                    global_offset = t_off + sym.offset
                elif sym.section == ".data":
                    global_offset = eff_data_delta + d_off + sym.offset
                else:  # .bss
                    global_offset = eff_data_delta + bss_start_in_data + b_off + sym.offset
                local_symbol_offsets[(idx, sym_name)] = global_offset
                global_symbol_table[sym_name] = global_offset
                if mod.repo_name == "__omni_os_imports__":
                    external_os_imports[sym_name] = global_offset
                if sym.section == ".text" and sym.is_exported:
                    exported_symbols[sym_name] = global_offset

        # 2. Cross-Section Relocation Resolution
        unresolved_symbols = []
        applied_relocs = 0
        abs64_reloc_rvas: List[int] = []
        external_dyn_relocs: List[Tuple[int, str, int, int]] = []
        is_arm64_link = any(
            r.reloc_type.startswith("ARM64_")
            for m in work_modules
            for r in m.relocations
        )

        # Populate internal GOT slots (or emit R_X86_64_GLOB_DAT for external shared library symbols)
        for gsym, g_data_off in got_slot_data_offsets.items():
            if gsym in external_os_imports:
                struct.pack_into("<Q", combined_data, g_data_off, 0)
                external_dyn_relocs.append((
                    text_vaddr_base + eff_data_delta + g_data_off,
                    gsym,
                    1025 if is_arm64_link else 6,
                    0,
                ))
            elif gsym in global_symbol_table:
                target_va = image_base + text_vaddr_base + global_symbol_table[gsym]
                struct.pack_into("<Q", combined_data, g_data_off, target_va)
                abs64_reloc_rvas.append(text_vaddr_base + eff_data_delta + g_data_off)

        for tsym, tg_off in tls_got_slot_offsets.items():
            if tsym in global_tls_offsets and tls_total_memsz > 0:
                tpoff_i64 = global_tls_offsets[tsym] - tls_total_memsz
                struct.pack_into("<q", combined_data, tg_off, tpoff_i64)

        for idx, mod in enumerate(work_modules):
            if idx in icf_folded_indices:
                continue
            t_base = module_text_offsets[idx]
            d_base = module_data_offsets[idx]
            i_base = module_init_offsets.get(idx, 0)
            f_base = module_fini_offsets.get(idx, 0)
            eh_base = module_eh_offsets.get(idx, eh_frame_offset_in_code)
            for reloc in mod.relocations:
                target_sym = reloc.symbol_name
                if target_sym == "_GLOBAL_OFFSET_TABLE_":
                    target_offset = eff_data_delta if has_rw_section else len(combined_text)
                elif (idx, target_sym) in local_symbol_offsets:
                    target_offset = local_symbol_offsets[(idx, target_sym)]
                elif target_sym in global_symbol_table:
                    target_offset = global_symbol_table[target_sym]
                else:
                    unresolved_symbols.append((mod.repo_name, target_sym))
                    continue

                if reloc.offset < 0:
                    raise RelocationOutOfBoundsError(
                        f"Negative relocation offset {reloc.offset} in module {mod.repo_name}"
                    )

                if reloc.section == ".data":
                    target_buf = combined_data
                    buf_patch_off = d_base + reloc.offset
                    reloc_v_pos = eff_data_delta + buf_patch_off
                elif reloc.section == ".init_array":
                    target_buf = combined_data
                    buf_patch_off = i_base + reloc.offset
                    reloc_v_pos = eff_data_delta + buf_patch_off
                elif reloc.section == ".fini_array":
                    target_buf = combined_data
                    buf_patch_off = f_base + reloc.offset
                    reloc_v_pos = eff_data_delta + buf_patch_off
                elif reloc.section == ".eh_frame":
                    target_buf = combined_text
                    buf_patch_off = eh_base + reloc.offset
                    reloc_v_pos = buf_patch_off
                else:
                    target_buf = combined_text
                    buf_patch_off = t_base + reloc.offset
                    reloc_v_pos = buf_patch_off

                reloc_size = 8 if reloc.reloc_type in ("ADDR64", "REL64") else 4
                if buf_patch_off + reloc_size > len(target_buf):
                    raise RelocationOutOfBoundsError(
                        f"Relocation slot [{buf_patch_off}..{buf_patch_off + reloc_size}] exceeds {reloc.section} bounds ({len(target_buf)}) in module {mod.repo_name}"
                    )

                is_tls_reloc = reloc.reloc_type in ("TLS_TPOFF32", "TLS_GOTTPOFF", "COFF_SECREL32")
                if not is_tls_reloc and target_sym != "_GLOBAL_OFFSET_TABLE_":
                    max_valid_off = (eff_data_delta + bss_start_in_data + total_bss_size) if has_rw_section else len(combined_text)
                    if target_offset < 0 or target_offset >= max(len(combined_text), max_valid_off):
                        raise RelocationOutOfBoundsError(
                            f"Relocation target symbol '{target_sym}' at offset {target_offset} is outside linked section bounds"
                        )

                if reloc.reloc_type == "REL32":
                    disp32 = (target_offset + reloc.addend) - (reloc_v_pos + 4)
                    if not (-0x80000000 <= disp32 <= 0x7FFFFFFF):
                        raise RelocationOutOfBoundsError(f"REL32 displacement {disp32} overflows signed 32-bit range")
                    struct.pack_into("<i", target_buf, buf_patch_off, disp32)
                    applied_relocs += 1

                elif reloc.reloc_type == "REL64":
                    disp64 = (target_offset + reloc.addend) - reloc_v_pos
                    struct.pack_into("<q", target_buf, buf_patch_off, disp64)
                    applied_relocs += 1

                elif reloc.reloc_type == "COFF_SECREL32":
                    tls_off = tls_symbol_offsets.get((idx, target_sym), global_tls_offsets.get(target_sym, target_offset))
                    struct.pack_into("<I", target_buf, buf_patch_off, (tls_off + reloc.addend) & 0xFFFFFFFF)
                    applied_relocs += 1

                elif reloc.reloc_type == "TLS_TPOFF32":
                    tls_off = tls_symbol_offsets.get((idx, target_sym), global_tls_offsets.get(target_sym, target_offset))
                    tpoff32 = (tls_off - tls_total_memsz) + reloc.addend
                    if not (-0x80000000 <= tpoff32 <= 0x7FFFFFFF):
                        raise RelocationOutOfBoundsError(f"TLS_TPOFF32 displacement {tpoff32} overflows signed 32-bit range")
                    struct.pack_into("<i", target_buf, buf_patch_off, tpoff32)
                    applied_relocs += 1

                elif reloc.reloc_type == "TLS_GOTTPOFF":
                    slot_rel_off = eff_data_delta + tls_got_slot_offsets[target_sym]
                    disp32 = (slot_rel_off + reloc.addend) - (reloc_v_pos + 4)
                    if not (-0x80000000 <= disp32 <= 0x7FFFFFFF):
                        raise RelocationOutOfBoundsError(f"TLS_GOTTPOFF displacement {disp32} overflows signed 32-bit range")
                    struct.pack_into("<i", target_buf, buf_patch_off, disp32)
                    applied_relocs += 1

                elif reloc.reloc_type == "GOT_REL32":
                    slot_rel_off = eff_data_delta + got_slot_data_offsets[target_sym]
                    disp32 = (slot_rel_off + reloc.addend) - (reloc_v_pos + 4)
                    if not (-0x80000000 <= disp32 <= 0x7FFFFFFF):
                        raise RelocationOutOfBoundsError(f"GOT_REL32 displacement {disp32} overflows signed 32-bit range")
                    struct.pack_into("<i", target_buf, buf_patch_off, disp32)
                    applied_relocs += 1

                elif reloc.reloc_type == "ADDR64":
                    if target_sym in external_os_imports:
                        struct.pack_into("<Q", target_buf, buf_patch_off, 0)
                        external_dyn_relocs.append((
                            text_vaddr_base + reloc_v_pos,
                            target_sym,
                            257 if is_arm64_link else 1,
                            reloc.addend,
                        ))
                    else:
                        target_va = image_base + text_vaddr_base + target_offset + reloc.addend
                        struct.pack_into("<Q", target_buf, buf_patch_off, target_va)
                        abs64_reloc_rvas.append(text_vaddr_base + reloc_v_pos)
                    applied_relocs += 1

                elif reloc.reloc_type in ("ARM64_CALL26",):
                    byte_diff = (target_offset + reloc.addend) - reloc_v_pos
                    if byte_diff % 4 != 0:
                        raise RelocationOutOfBoundsError(f"Misaligned ARM64_CALL26 displacement {byte_diff}")
                    imm26 = byte_diff // 4
                    if not (-(1 << 25) <= imm26 < (1 << 25)):
                        raise RelocationOutOfBoundsError(f"ARM64_CALL26 displacement {imm26} overflows 26-bit range")
                    orig_inst = struct.unpack_from("<I", target_buf, buf_patch_off)[0]
                    patched_inst = (orig_inst & 0xFC000000) | (imm26 & 0x03FFFFFF)
                    struct.pack_into("<I", target_buf, buf_patch_off, patched_inst)
                    applied_relocs += 1

                elif reloc.reloc_type in ("ARM64_PAGE21", "ARM64_GOT_PAGE21"):
                    eff_t = (eff_data_delta + got_slot_data_offsets[target_sym]) if reloc.reloc_type == "ARM64_GOT_PAGE21" else target_offset
                    eff_target = image_base + text_vaddr_base + eff_t + reloc.addend
                    eff_pc = image_base + text_vaddr_base + reloc_v_pos
                    page_delta = (eff_target >> 12) - (eff_pc >> 12)
                    if not (-(1 << 20) <= page_delta < (1 << 20)):
                        raise RelocationOutOfBoundsError(f"ARM64_PAGE21 page delta {page_delta} overflows 21-bit range")
                    immlo = page_delta & 0x3
                    immhi = (page_delta >> 2) & 0x7FFFF
                    orig_inst = struct.unpack_from("<I", target_buf, buf_patch_off)[0]
                    patched_inst = (orig_inst & 0x9F00001F) | (immlo << 29) | (immhi << 5)
                    struct.pack_into("<I", target_buf, buf_patch_off, patched_inst)
                    applied_relocs += 1

                elif reloc.reloc_type in ("ARM64_LO12", "ARM64_GOT_LO12"):
                    eff_t = (eff_data_delta + got_slot_data_offsets[target_sym]) if reloc.reloc_type == "ARM64_GOT_LO12" else target_offset
                    eff_target = image_base + text_vaddr_base + eff_t + reloc.addend
                    lo12 = eff_target & 0xFFF
                    orig_inst = struct.unpack_from("<I", target_buf, buf_patch_off)[0]
                    shift = _arm64_ldst_shift(orig_inst)
                    scaled_imm12 = (lo12 >> shift) & 0xFFF
                    patched_inst = (orig_inst & 0xFFC003FF) | (scaled_imm12 << 10)
                    struct.pack_into("<I", target_buf, buf_patch_off, patched_inst)
                    applied_relocs += 1

                elif reloc.reloc_type == "RISCV_CALL_PLT":
                    byte_diff = (target_offset + reloc.addend) - reloc_v_pos
                    if (byte_diff % 2) != 0 or not (-(1 << 20) <= byte_diff < (1 << 20)):
                        raise RelocationOutOfBoundsError(f"RISCV_CALL_PLT displacement {byte_diff} out of range")
                    imm = byte_diff & 0x1FFFFF
                    b20 = (imm >> 20) & 1
                    b10_1 = (imm >> 1) & 0x3FF
                    b11 = (imm >> 11) & 1
                    b19_12 = (imm >> 12) & 0xFF
                    orig_inst = struct.unpack_from("<I", target_buf, buf_patch_off)[0]
                    rd_bits = orig_inst & 0xF80
                    patched_inst = (b20 << 31) | (b10_1 << 21) | (b11 << 20) | (b19_12 << 12) | rd_bits | 0x6F
                    struct.pack_into("<I", target_buf, buf_patch_off, patched_inst)
                    applied_relocs += 1

        if unresolved_symbols:
            raise LinkerError(f"Unresolved external symbols during link: {unresolved_symbols}")

        resolved_os_import_table = dict(OS_C_ABI_IMPORT_TABLE)
        for ext_s in external_os_imports:
            if ext_s not in resolved_os_import_table:
                resolved_os_import_table[ext_s] = _infer_dynamic_lib_pair(ext_s, self.external_lib_hints)

        return {
            "success": True,
            "total_modules": len(work_modules),
            "total_text_size": len(combined_text),
            "total_data_size": len(combined_data),
            "total_bss_size": total_bss_size,
            "global_symbols": global_symbol_table,
            "exported_symbols": exported_symbols,
            "layout_order": sorted(
                (s for s in exported_symbols if not s.startswith(("__elf_sec_", "__coff_sec_", "__macho_sec_"))),
                key=lambda s: global_symbol_table[s],
            ),
            "hot_first_applied": bool(eff_hot_weights),
            "gc_sections_applied": use_gc,
            "gc_eliminated_modules": gc_eliminated_modules,
            "gc_bytes_reclaimed": gc_bytes_reclaimed,
            "icf_folding_applied": use_icf,
            "icf_folded_modules": icf_folded_modules,
            "icf_bytes_saved": icf_bytes_saved,
            "icf_folded_symbols": sorted(set(icf_folded_symbols)),
            "external_os_imports": external_os_imports,
            "os_import_table": resolved_os_import_table,
            "relocations_applied": applied_relocs,
            "abs64_reloc_rvas": sorted(set(abs64_reloc_rvas)),
            "external_dyn_relocs": external_dyn_relocs,
            "eh_frame_offset_in_code": eh_frame_offset_in_code,
            "eh_frame_size": eh_frame_size,
            "combined_code": bytes(combined_text),
            "combined_data": bytes(combined_data),
            "bss_start_in_data": bss_start_in_data,
            "init_array_offset_in_data": init_array_offset_in_data,
            "init_array_size": init_array_size,
            "fini_array_offset_in_data": fini_array_offset_in_data,
            "fini_array_size": fini_array_size,
            "combined_tdata": bytes(combined_tdata),
            "total_tbss_size": total_tbss_size,
        }

    def emit_linked_shared_library(
        self,
        output_path: str,
        export_name: str,
        target_format: str = "auto",
        pdata_xdata: Optional[Tuple[bytes, bytes]] = None,
        dwarf_sections: Optional[Dict[str, bytes]] = None,
    ) -> str:
        """Links modules and emits a dynamic shared library exporting ALL exported module symbols."""
        link_res = self.link(entry_symbol=export_name)
        has_rw = (
            bool(link_res["combined_data"])
            or (link_res["total_bss_size"] > 0)
            or bool(link_res["abs64_reloc_rvas"])
            or bool(link_res["external_dyn_relocs"])
            or bool(link_res["combined_tdata"])
            or (link_res["total_tbss_size"] > 0)
        )
        eff_imp_table = link_res.get("os_import_table") or OS_C_ABI_IMPORT_TABLE
        if has_rw:
            combined_data_len = len(link_res["combined_data"])
            bss_pad = max(0, link_res["bss_start_in_data"] - combined_data_len)
            full_bss = bss_pad + link_res["total_bss_size"]
            exports_probe = dict(link_res["exported_symbols"])
            if export_name in link_res["global_symbols"]:
                exports_probe[export_name] = link_res["global_symbols"][export_name]
            else:
                exports_probe.setdefault(export_name, 0)
            image_base, text_va, data_va = self.emitter.compute_shared_lib_layout(
                output_path=output_path,
                func_code=link_res["combined_code"],
                export_name=export_name,
                target_format=target_format,
                extra_exports=exports_probe,
                pdata_xdata=pdata_xdata,
                dwarf_sections=dwarf_sections,
                os_import_stubs=link_res.get("external_os_imports") or None,
                os_import_table=eff_imp_table,
                data_bytes=link_res["combined_data"],
                bss_size=full_bss,
                abs64_reloc_rvas=link_res["abs64_reloc_rvas"],
                has_init_array=link_res.get("init_array_size", 0) > 0,
                has_fini_array=link_res.get("fini_array_size", 0) > 0,
                eh_frame_offset_in_code=link_res.get("eh_frame_offset_in_code", 0),
                eh_frame_size=link_res.get("eh_frame_size", 0),
                external_dyn_relocs=link_res.get("external_dyn_relocs") or None,
            )
            link_res = self.link(
                entry_symbol=export_name,
                data_vaddr_delta=(data_va - text_va),
                text_vaddr_base=text_va,
                image_base=image_base,
            )
            eff_imp_table = link_res.get("os_import_table") or eff_imp_table

        code = link_res["combined_code"]
        exports = dict(link_res["exported_symbols"])
        if export_name in link_res["global_symbols"]:
            exports[export_name] = link_res["global_symbols"][export_name]
        else:
            exports.setdefault(export_name, 0)

        data_bytes = link_res["combined_data"]
        bss_pad = max(0, link_res["bss_start_in_data"] - len(data_bytes))
        total_bss = (bss_pad + link_res["total_bss_size"]) if (data_bytes or link_res["total_bss_size"]) else 0

        return self.emitter.emit_shared_library(
            output_path=output_path,
            func_code=code,
            export_name=export_name,
            target_format=target_format,
            extra_exports=exports,
            pdata_xdata=pdata_xdata,
            dwarf_sections=dwarf_sections,
            os_import_stubs=link_res.get("external_os_imports") or None,
            os_import_table=eff_imp_table,
            data_bytes=data_bytes or None,
            bss_size=total_bss,
            abs64_reloc_rvas=link_res["abs64_reloc_rvas"] or None,
            init_array_offset_in_data=link_res.get("init_array_offset_in_data", 0),
            init_array_size=link_res.get("init_array_size", 0),
            fini_array_offset_in_data=link_res.get("fini_array_offset_in_data", 0),
            fini_array_size=link_res.get("fini_array_size", 0),
            tdata_bytes=link_res.get("combined_tdata") or None,
            tbss_size=link_res.get("total_tbss_size", 0),
            eh_frame_offset_in_code=link_res.get("eh_frame_offset_in_code", 0),
            eh_frame_size=link_res.get("eh_frame_size", 0),
            external_dyn_relocs=link_res.get("external_dyn_relocs") or None,
        )

    def emit_linked_executable(
        self,
        output_path: str,
        entry_symbol: Optional[str] = None,
        target_format: str = "auto"
    ) -> str:
        """Links modules and emits a standalone executable (routing OS dynamic imports when present)."""
        link_res = self.link()
        code = link_res["combined_code"]
        global_syms = link_res["global_symbols"]
        entry_offset = global_syms.get(entry_symbol, 0) if entry_symbol else 0
        os_imports = link_res.get("external_os_imports") or {}
        exports = dict(link_res.get("exported_symbols") or {})
        if entry_symbol and entry_symbol in global_syms:
            exports.setdefault(entry_symbol, entry_offset)

        resolved_fmt = ("pe64" if sys.platform == "win32" else "elf64") if target_format == "auto" else target_format
        if os_imports and resolved_fmt in ("pe64", "elf64", "arm64_elf", "macho64", "macho_x86_64", "arm64_macho", "macho_arm64"):
            return self.emitter.emit_dynamic_linked_executable(
                output_path=output_path,
                linked_code=code,
                entry_offset=entry_offset,
                os_import_stubs=os_imports,
                os_import_table=OS_C_ABI_IMPORT_TABLE,
                target_format=resolved_fmt,
                exported_symbols=exports,
            )

        return self.emitter.emit_standalone_binary(
            output_path=output_path,
            custom_code=code,
            entry_offset=entry_offset,
            target_format=target_format,
            exported_symbols=exports,
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
