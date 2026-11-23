"""
OmniCompiler Native Debug Info & Stack-Unwind Emitter (`debug_info_emitter.py`).
Closes GAP-02 with spec-compliant binary debug & exception-unwind tables:
1. DWARF v5 `.debug_line` & `.debug_info` binary encoder (ULEB128 / SLEB128 + Line Number Program)
   and deterministic state-machine decoder (`decode_dwarf_line_table`) for round-trip verification.
2. Windows x64 PE32+ `.pdata` (`RUNTIME_FUNCTION`) & `.xdata` (`UNWIND_INFO` v1) unwind emitter
   and decoder (`decode_win64_pdata`) for OS stack walking and structured exception handling.
"""

import os
import struct
from typing import List, Tuple, Dict, Any, Optional


# ==============================================================================
# ULEB128 / SLEB128 Variable-Length Integer Encoding & Decoding
# ==============================================================================

def encode_uleb128(value: int) -> bytes:
    if value < 0:
        raise ValueError("ULEB128 requires non-negative integer")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80
        out.append(byte)
        if value == 0:
            break
    return bytes(out)


def decode_uleb128(data: bytes, offset: int = 0) -> Tuple[int, int]:
    result = 0
    shift = 0
    pos = offset
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return result, pos


def encode_sleb128(value: int) -> bytes:
    out = bytearray()
    more = True
    while more:
        byte = value & 0x7F
        value >>= 7
        sign_bit = (byte & 0x40) != 0
        if (value == 0 and not sign_bit) or (value == -1 and sign_bit):
            more = False
        else:
            byte |= 0x80
        out.append(byte)
    return bytes(out)


def decode_sleb128(data: bytes, offset: int = 0) -> Tuple[int, int]:
    result = 0
    shift = 0
    pos = offset
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if (b & 0x80) == 0:
            if shift < 64 and (b & 0x40) != 0:
                result |= -(1 << shift)
            break
    return result, pos


# ==============================================================================
# DWARF v5 `.debug_line` & `.debug_info` Emitter + State-Machine Verifier
# ==============================================================================

DW_LNS_copy = 1
DW_LNS_advance_pc = 2
DW_LNS_advance_line = 3
DW_LNS_set_file = 4

DW_LNE_end_sequence = 1
DW_LNE_set_address = 2

DW_LNCT_path = 0x01
DW_LNCT_directory_index = 0x02
DW_FORM_string = 0x08
DW_FORM_udata = 0x0F


class DwarfV5Emitter:
    """
    Emits and decodes DWARF v5 `.debug_line` and `.debug_info` sections mapping native
    machine-code instruction addresses back to source filenames and line numbers.
    """

    def emit_debug_line(
        self,
        source_file: str,
        line_entries: List[Tuple[int, int]],
        code_size: int,
        base_address: int = 0x1000,
    ) -> bytes:
        """
        Emits a DWARF v5 `.debug_line` compilation unit table.
        `line_entries`: sorted list of `(code_offset, source_line)`.
        """
        dir_name = os.path.dirname(source_file) or "."
        base_name = os.path.basename(source_file) or "module.py"

        # 1. Build Line Number Program Body
        prog = bytearray()

        # Extended opcode: DW_LNE_set_address(base_address)
        prog.append(0x00)
        prog.extend(encode_uleb128(1 + 8))
        prog.append(DW_LNE_set_address)
        prog.extend(struct.pack("<Q", base_address))

        cur_pc = 0
        cur_line = 1

        normalized = sorted(set((max(0, int(off)), max(1, int(ln))) for off, ln in line_entries))
        if not normalized:
            normalized = [(0, 1)]

        for off, ln in normalized:
            delta_pc = off - cur_pc
            delta_ln = ln - cur_line
            if delta_pc > 0:
                prog.append(DW_LNS_advance_pc)
                prog.extend(encode_uleb128(delta_pc))
                cur_pc = off
            if delta_ln != 0:
                prog.append(DW_LNS_advance_line)
                prog.extend(encode_sleb128(delta_ln))
                cur_line = ln
            prog.append(DW_LNS_copy)

        # Advance PC to end of function and emit DW_LNE_end_sequence
        end_delta = max(0, code_size - cur_pc)
        if end_delta > 0:
            prog.append(DW_LNS_advance_pc)
            prog.extend(encode_uleb128(end_delta))
        prog.append(0x00)
        prog.extend(encode_uleb128(1))
        prog.append(DW_LNE_end_sequence)

        # 2. Build DWARF v5 Line Table Prologue Header
        prologue = bytearray()
        prologue.append(1)                      # minimum_instruction_length = 1
        prologue.append(1)                      # maximum_operations_per_instruction = 1
        prologue.append(1)                      # default_is_stmt = 1
        prologue.extend(struct.pack("<b", -5))  # line_base = -5
        prologue.append(14)                     # line_range = 14
        prologue.append(13)                     # opcode_base = 13
        # standard_opcode_lengths for opcodes 1..12
        prologue.extend(bytes([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]))

        # Directory table (1 format: DW_LNCT_path / DW_FORM_string, 1 entry)
        prologue.append(1)  # directory_entry_format_count
        prologue.extend(encode_uleb128(DW_LNCT_path))
        prologue.extend(encode_uleb128(DW_FORM_string))
        prologue.extend(encode_uleb128(1))  # directories_count
        prologue.extend(dir_name.encode("utf-8") + b"\x00")

        # File name table (2 formats: path + dir_index, 1 entry)
        prologue.append(2)  # file_name_entry_format_count
        prologue.extend(encode_uleb128(DW_LNCT_path))
        prologue.extend(encode_uleb128(DW_FORM_string))
        prologue.extend(encode_uleb128(DW_LNCT_directory_index))
        prologue.extend(encode_uleb128(DW_FORM_udata))
        prologue.extend(encode_uleb128(1))  # file_names_count
        prologue.extend(base_name.encode("utf-8") + b"\x00")
        prologue.extend(encode_uleb128(0))  # dir index 0

        # 3. Assemble DWARF v5 Unit Header:
        # unit_length (u32), version (u16=5), address_size (u8=8), segment_selector_size (u8=0),
        # header_length (u32), prologue, program
        header_length = len(prologue)
        unit_body = (
            struct.pack("<HBBI", 5, 8, 0, header_length)
            + bytes(prologue)
            + bytes(prog)
        )
        return struct.pack("<I", len(unit_body)) + unit_body

    def decode_debug_line(self, data: bytes) -> Dict[str, Any]:
        """
        Executes a spec-compliant DWARF v5 Line Number Program state machine over `data`
        and returns the reconstructed address-to-source-line matrix.
        """
        if len(data) < 12:
            raise ValueError("Truncated DWARF .debug_line section")
        unit_length = struct.unpack_from("<I", data, 0)[0]
        version, addr_size, seg_sel, header_length = struct.unpack_from("<HBBI", data, 4)
        if version != 5:
            raise ValueError(f"Unsupported DWARF version {version}; expected 5")

        pos = 12
        prog_start = pos + header_length
        unit_end = 4 + unit_length

        min_inst_len = data[pos]
        _max_ops = data[pos + 1]
        default_is_stmt = bool(data[pos + 2])
        _line_base = struct.unpack_from("<b", data, pos + 3)[0]
        _line_range = data[pos + 4]
        opcode_base = data[pos + 5]
        pos += 6 + (opcode_base - 1)

        # Parse directories
        dir_fmt_cnt = data[pos]
        pos += 1
        dir_fmts = []
        for _ in range(dir_fmt_cnt):
            ct, pos = decode_uleb128(data, pos)
            fm, pos = decode_uleb128(data, pos)
            dir_fmts.append((ct, fm))
        dirs_cnt, pos = decode_uleb128(data, pos)
        directories: List[str] = []
        for _ in range(dirs_cnt):
            d_path = ""
            for ct, fm in dir_fmts:
                if fm == DW_FORM_string:
                    end_nul = data.index(b"\x00", pos)
                    s = data[pos:end_nul].decode("utf-8", errors="replace")
                    pos = end_nul + 1
                    if ct == DW_LNCT_path:
                        d_path = s
                elif fm == DW_FORM_udata:
                    _, pos = decode_uleb128(data, pos)
            directories.append(d_path)

        # Parse files
        file_fmt_cnt = data[pos]
        pos += 1
        file_fmts = []
        for _ in range(file_fmt_cnt):
            ct, pos = decode_uleb128(data, pos)
            fm, pos = decode_uleb128(data, pos)
            file_fmts.append((ct, fm))
        files_cnt, pos = decode_uleb128(data, pos)
        files: List[Tuple[str, int]] = []
        for _ in range(files_cnt):
            f_path = ""
            d_idx = 0
            for ct, fm in file_fmts:
                if fm == DW_FORM_string:
                    end_nul = data.index(b"\x00", pos)
                    s = data[pos:end_nul].decode("utf-8", errors="replace")
                    pos = end_nul + 1
                    if ct == DW_LNCT_path:
                        f_path = s
                elif fm == DW_FORM_udata:
                    v, pos = decode_uleb128(data, pos)
                    if ct == DW_LNCT_directory_index:
                        d_idx = v
            files.append((f_path, d_idx))

        # Run state machine
        pos = prog_start
        address = 0
        file_idx = 0
        line = 1
        is_stmt = default_is_stmt
        rows: List[Dict[str, Any]] = []

        while pos < unit_end:
            opcode = data[pos]
            pos += 1
            if opcode == 0:
                ext_len, pos = decode_uleb128(data, pos)
                ext_end = pos + ext_len
                sub_op = data[pos]
                pos += 1
                if sub_op == DW_LNE_set_address:
                    address = struct.unpack_from("<Q" if addr_size == 8 else "<I", data, pos)[0]
                elif sub_op == DW_LNE_end_sequence:
                    rows.append({
                        "address": address,
                        "line": line,
                        "file": files[file_idx][0] if files else "",
                        "end_sequence": True,
                    })
                    address = 0
                    line = 1
                pos = ext_end
            elif opcode == DW_LNS_copy:
                rows.append({
                    "address": address,
                    "line": line,
                    "file": files[file_idx][0] if files else "",
                    "is_stmt": is_stmt,
                    "end_sequence": False,
                })
            elif opcode == DW_LNS_advance_pc:
                adv, pos = decode_uleb128(data, pos)
                address += adv * min_inst_len
            elif opcode == DW_LNS_advance_line:
                dl, pos = decode_sleb128(data, pos)
                line += dl
            elif opcode == DW_LNS_set_file:
                file_idx, pos = decode_uleb128(data, pos)

        return {
            "version": version,
            "address_size": addr_size,
            "directories": directories,
            "files": [f[0] for f in files],
            "rows": rows,
        }

    def emit_debug_info_cu(
        self,
        unit_name: str,
        producer: str = "OmniCompiler 1.0",
        low_pc: int = 0x1000,
        high_pc: int = 0x1100,
    ) -> Tuple[bytes, bytes]:
        """
        Emits minimal DWARF v5 `.debug_info` + `.debug_abbrev` pair describing the Compilation Unit.
        """
        # .debug_abbrev: abbrev code 1 -> DW_TAG_compile_unit (0x11), no children (0)
        # Attributes: DW_AT_producer (0x25, DW_FORM_string=0x08),
        #             DW_AT_name (0x03, DW_FORM_string=0x08),
        #             DW_AT_low_pc (0x11, DW_FORM_addr=0x01),
        #             DW_AT_high_pc (0x12, DW_FORM_addr=0x01)
        abbrev = bytes([
            0x01, 0x11, 0x00,
            0x25, 0x08,
            0x03, 0x08,
            0x11, 0x01,
            0x12, 0x01,
            0x00, 0x00,
            0x00,
        ])

        die = bytearray()
        die.append(0x01)  # abbrev code 1
        die.extend(producer.encode("utf-8") + b"\x00")
        die.extend(unit_name.encode("utf-8") + b"\x00")
        die.extend(struct.pack("<QQ", low_pc, high_pc))

        # DWARF v5 CU header: unit_length(u32), version(u16=5), unit_type(u8=DW_UT_compile=0x01),
        # address_size(u8=8), debug_abbrev_offset(u32=0)
        cu_body = struct.pack("<HBBI", 5, 0x01, 8, 0) + bytes(die)
        debug_info = struct.pack("<I", len(cu_body)) + cu_body
        return debug_info, abbrev

    def emit_debug_info_with_subprograms(
        self,
        unit_name: str,
        producer: str = "OmniCompiler 1.0",
        low_pc: int = 0x1000,
        high_pc: int = 0x1100,
        subprograms: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[bytes, bytes]:
        """
        Emits DWARF v5 `.debug_info` + `.debug_abbrev` containing a `DW_TAG_compile_unit`
        and child `DW_TAG_subprogram` (`0x2E`) DIEs for every compiled function.
        """
        subs = subprograms or []
        if not subs:
            return self.emit_debug_info_cu(unit_name, producer=producer, low_pc=low_pc, high_pc=high_pc)

        # abbrev 1: DW_TAG_compile_unit (0x11), DW_CHILDREN_yes (1)
        #   DW_AT_producer (0x25, string=0x08), DW_AT_name (0x03, string=0x08),
        #   DW_AT_low_pc (0x11, addr=0x01), DW_AT_high_pc (0x12, addr=0x01),
        #   DW_AT_stmt_list (0x10, sec_offset=0x17)
        # abbrev 2: DW_TAG_subprogram (0x2E), DW_CHILDREN_no (0):
        #   DW_AT_name (0x03, string=0x08), DW_AT_low_pc (0x11, addr=0x01),
        #   DW_AT_high_pc (0x12, addr=0x01), DW_AT_decl_line (0x3B, data4=0x06)
        abbrev = bytes([
            0x01, 0x11, 0x01,
            0x25, 0x08,
            0x03, 0x08,
            0x11, 0x01,
            0x12, 0x01,
            0x10, 0x17,
            0x00, 0x00,
            0x02, 0x2E, 0x00,
            0x03, 0x08,
            0x11, 0x01,
            0x12, 0x01,
            0x3B, 0x06,
            0x00, 0x00,
            0x00,
        ])

        die = bytearray()
        die.append(0x01)
        die.extend(producer.encode("utf-8") + b"\x00")
        die.extend(unit_name.encode("utf-8") + b"\x00")
        die.extend(struct.pack("<QQI", low_pc, high_pc, 0))
        for sp in subs:
            die.append(0x02)
            die.extend(str(sp["name"]).encode("utf-8") + b"\x00")
            die.extend(struct.pack("<QQI", int(sp["low_pc"]), int(sp["high_pc"]), max(1, int(sp.get("line", 1)))))
        die.append(0x00)  # end of CU children

        cu_body = struct.pack("<HBBI", 5, 0x01, 8, 0) + bytes(die)
        debug_info = struct.pack("<I", len(cu_body)) + cu_body
        return debug_info, abbrev


# ==============================================================================
# Windows x64 `.pdata` & `.xdata` Exception / Stack-Unwind Emitter
# ==============================================================================

UWOP_PUSH_NONVOL = 0
UWOP_ALLOC_LARGE = 1
UWOP_ALLOC_SMALL = 2
UWOP_SET_FPREG = 3

X64_UNWIND_REG_IDS = {
    "rax": 0, "rcx": 1, "rdx": 2, "rbx": 3,
    "rsp": 4, "rbp": 5, "rsi": 6, "rdi": 7,
    "r8": 8,  "r9": 9,  "r10": 10, "r11": 11,
    "r12": 12, "r13": 13, "r14": 14, "r15": 15,
}


def emit_win64_pdata_xdata(
    func_rva: int,
    code_size: int,
    prologue_size: int,
    stack_frame_size: int,
    saved_regs: Optional[List[str]] = None,
    xdata_rva: int = 0x3000,
) -> Tuple[bytes, bytes]:
    """
    Synthesizes Microsoft x64 ABI `.pdata` (`RUNTIME_FUNCTION`) and `.xdata` (`UNWIND_INFO` v1)
    unwind descriptors so Windows `RtlVirtualUnwind`, debuggers, and profilers can walk stack frames.
    """
    saved_regs = saved_regs or []
    # Unwind codes are stored in reverse prologue execution order!
    unwind_codes: List[int] = []

    if stack_frame_size > 0:
        if 8 <= stack_frame_size <= 128 and stack_frame_size % 8 == 0:
            op_info = (stack_frame_size // 8) - 1
            code_word = prologue_size | ((UWOP_ALLOC_SMALL | (op_info << 4)) << 8)
            unwind_codes.append(code_word)
        else:
            # UWOP_ALLOC_LARGE (op_info=0 -> next slot holds size / 8)
            code_word = prologue_size | ((UWOP_ALLOC_LARGE | (0 << 4)) << 8)
            unwind_codes.append(code_word)
            unwind_codes.append((stack_frame_size // 8) & 0xFFFF)

    for reg in reversed(saved_regs):
        reg_id = X64_UNWIND_REG_IDS.get(reg.lower(), 5)
        code_word = min(prologue_size, 1) | ((UWOP_PUSH_NONVOL | (reg_id << 4)) << 8)
        unwind_codes.append(code_word)

    count_of_codes = len(unwind_codes)
    has_rbp = "rbp" in [r.lower() for r in saved_regs]
    frame_reg_byte = 5 if has_rbp else 0  # RBP = 5, offset = 0

    xdata = bytearray()
    # Version=1 (bits 0..2), Flags=0 (bits 3..7) -> 0x01
    xdata.extend(struct.pack("<BBBB", 0x01, prologue_size & 0xFF, count_of_codes & 0xFF, frame_reg_byte))
    for w in unwind_codes:
        xdata.extend(struct.pack("<H", w & 0xFFFF))
    if count_of_codes % 2 == 1:
        xdata.extend(b"\x00\x00")  # 4-byte align UNWIND_INFO

    # RUNTIME_FUNCTION: BeginAddress, EndAddress, UnwindInfoAddress
    pdata = struct.pack("<III", func_rva, func_rva + code_size, xdata_rva)
    return pdata, bytes(xdata)


def emit_win64_multi_pdata_xdata(entries: List[Dict[str, Any]]) -> Tuple[bytes, bytes]:
    """
    Synthesizes sorted multi-function Win64 `.pdata` (`RUNTIME_FUNCTION[]`) and packed
    4-byte-aligned `.xdata` (`UNWIND_INFO` v1) blobs across all functions in a linked binary.
    `UnwindInfoAddress` in `.pdata` stores the relative offset inside `.xdata`.
    """
    sorted_entries = sorted(entries, key=lambda e: int(e["func_rva"]))
    pdata_all = bytearray()
    xdata_all = bytearray()
    for ent in sorted_entries:
        xdata_rel_off = len(xdata_all)
        p_one, x_one = emit_win64_pdata_xdata(
            func_rva=int(ent["func_rva"]),
            code_size=max(1, int(ent["code_size"])),
            prologue_size=int(ent.get("prologue_size", 4)),
            stack_frame_size=int(ent.get("stack_frame_size", 0)),
            saved_regs=ent.get("saved_regs") or [],
            xdata_rva=xdata_rel_off,
        )
        pdata_all.extend(p_one)
        xdata_all.extend(x_one)
        rem4 = (-len(xdata_all)) & 3
        if rem4:
            xdata_all.extend(b"\x00" * rem4)
    return bytes(pdata_all), bytes(xdata_all)


def decode_win64_pdata(pdata: bytes, xdata: bytes) -> List[Dict[str, Any]]:
    """Decodes `.pdata` + `.xdata` unwind entries for structural verification."""
    entries = []
    for off in range(0, len(pdata), 12):
        if off + 12 > len(pdata):
            break
        begin_rva, end_rva, unwind_rva = struct.unpack_from("<III", pdata, off)
        ver_flags, prolog_sz, code_cnt, frame_reg = struct.unpack_from("<BBBB", xdata, 0)
        entries.append({
            "begin_rva": begin_rva,
            "end_rva": end_rva,
            "unwind_rva": unwind_rva,
            "version": ver_flags & 0x7,
            "prologue_size": prolog_sz,
            "unwind_code_count": code_cnt,
            "frame_register": frame_reg & 0xF,
        })
    return entries


# ==============================================================================
# DWARF CFI Zero-Cost Exception Unwinding (`.eh_frame` CIE + FDE) (Alpha-C90)
# ==============================================================================

_X64_DWARF_REG = {
    "rax": 0, "rdx": 1, "rcx": 2, "rbx": 3,
    "rsi": 4, "rdi": 5, "rbp": 6, "rsp": 7,
    "r8": 8, "r9": 9, "r10": 10, "r11": 11,
    "r12": 12, "r13": 13, "r14": 14, "r15": 15,
    "rip": 16,
}

_ARM64_DWARF_REG = {
    **{f"x{i}": i for i in range(31)},
    "sp": 31,
}


class DwarfCFIFrameEmitter:
    """
    Emits System V ELF `.eh_frame` DWARF Call Frame Information (CIE + FDE records)
    describing stack-frame CFA recovery and callee-saved register spills for zero-cost
    exception unwinding on x86-64 and ARM64.
    """

    def emit_eh_frame(
        self,
        functions: List[Dict[str, Any]],
        arch: str = "x86_64",
    ) -> bytes:
        is_arm64 = arch.lower() in ("arm64", "aarch64")
        sp_reg = 31 if is_arm64 else 7
        ra_reg = 30 if is_arm64 else 16
        fp_reg = 29 if is_arm64 else 6
        reg_map = _ARM64_DWARF_REG if is_arm64 else _X64_DWARF_REG

        # CIE (version 1, "zR" augmentation, DW_EH_PE_absptr=0x00, code_align=1, data_align=-8)
        cie_body = bytearray()
        cie_body.extend(struct.pack("<IB", 0, 1))  # CIE_id=0, version=1
        cie_body.extend(b"zR\x00")
        cie_body.extend(encode_uleb128(1))         # code_alignment_factor
        cie_body.extend(encode_sleb128(-8))        # data_alignment_factor
        cie_body.extend(encode_uleb128(ra_reg))    # return_address_register
        cie_body.extend(encode_uleb128(1))         # augmentation data length
        cie_body.append(0x00)                      # DW_EH_PE_absptr (64-bit pointer)
        # Initial CFA: CFA = SP + (0 on arm64 else 8), RA at [CFA - 8] for x64
        if is_arm64:
            cie_body.append(0x0C)  # DW_CFA_def_cfa
            cie_body.extend(encode_uleb128(sp_reg))
            cie_body.extend(encode_uleb128(0))
        else:
            cie_body.append(0x0C)  # DW_CFA_def_cfa(rsp, 8)
            cie_body.extend(encode_uleb128(sp_reg))
            cie_body.extend(encode_uleb128(8))
            cie_body.append(0x80 | ra_reg)  # DW_CFA_offset(rip, 1 * -8 = -8)
            cie_body.extend(encode_uleb128(1))
        while (4 + len(cie_body)) % 8 != 0:
            cie_body.append(0x00)  # DW_CFA_nop
        cie_bytes = struct.pack("<I", len(cie_body)) + bytes(cie_body)

        out = bytearray(cie_bytes)
        for fn_info in functions:
            init_pc = int(fn_info.get("initial_location", fn_info.get("low_pc", 0x1000)))
            code_sz = max(1, int(fn_info.get("address_range", fn_info.get("code_size", 16))))
            frame_sz = max(0, int(fn_info.get("stack_frame_size", 0)))
            prolog_sz = max(1, min(code_sz - 1, int(fn_info.get("prologue_size", 4))))
            saved = list(fn_info.get("saved_regs") or [])

            fde_offset = len(out)
            # CIE_pointer in FDE points backward from the CIE_pointer field (fde_offset + 4) to CIE (0)
            cie_ptr = fde_offset + 4
            fde_body = bytearray()
            fde_body.extend(struct.pack("<IQQB", cie_ptr, init_pc, code_sz, 0))

            # Advance across prologue pushes and frame allocation
            adv = min(63, prolog_sz)
            fde_body.append(0x40 | adv)  # DW_CFA_advance_loc(adv)
            total_cfa = (0 if is_arm64 else 8) + frame_sz
            pushed_words = 0
            for r in saved:
                if r in reg_map:
                    pushed_words += 1
                    rnum = reg_map[r]
                    if not is_arm64 and pushed_words == 1 and r == "rbp":
                        cfa_off = 16
                    else:
                        cfa_off = (0 if is_arm64 else 8) + pushed_words * 8
                    if rnum <= 63:
                        fde_body.append(0x80 | rnum)
                        fde_body.extend(encode_uleb128(1 + pushed_words))
                    else:
                        fde_body.append(0x05)  # DW_CFA_offset_extended
                        fde_body.extend(encode_uleb128(rnum))
                        fde_body.extend(encode_uleb128(1 + pushed_words))
            final_cfa_off = max(total_cfa, (0 if is_arm64 else 8) + pushed_words * 8)
            fde_body.append(0x0E)  # DW_CFA_def_cfa_offset
            fde_body.extend(encode_uleb128(final_cfa_off))
            if not is_arm64 and "rbp" in saved:
                fde_body.append(0x0D)  # DW_CFA_def_cfa_register(rbp)
                fde_body.extend(encode_uleb128(fp_reg))

            while (4 + len(fde_body)) % 8 != 0:
                fde_body.append(0x00)
            out.extend(struct.pack("<I", len(fde_body)) + bytes(fde_body))

        out.extend(b"\x00\x00\x00\x00")  # CIE/FDE ZERO terminator
        return bytes(out)

    @staticmethod
    def decode_eh_frame(data: bytes) -> Dict[str, Any]:
        """Decodes CIE and FDE headers from an ELF `.eh_frame` section."""
        pos = 0
        cies: List[Dict[str, Any]] = []
        fdes: List[Dict[str, Any]] = []
        while pos + 4 <= len(data):
            length = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            if length == 0:
                break
            rec = data[pos:pos + length]
            pos += length
            cie_id = struct.unpack_from("<I", rec, 0)[0]
            if cie_id == 0:
                cies.append({"version": rec[4], "length": length})
            else:
                init_loc, addr_range = struct.unpack_from("<QQ", rec, 4)
                fdes.append({
                    "cie_pointer": cie_id,
                    "initial_location": init_loc,
                    "address_range": addr_range,
                    "length": length,
                })
        return {
            "cie_count": len(cies),
            "fde_count": len(fdes),
            "cies": cies,
            "fdes": fdes,
        }
