"""
OmniCompiler Standalone Native Binary & Shared Library Emitter
Synthesizes fully linked, freestanding 64-bit native executables and dynamic shared libraries directly in machine code.
Zero runtime dependencies: No GCC, Clang, MSVC, or Python interpreter required.

Capabilities:
1. Windows PE32+ (AMD64 & ARM64) Executables (.exe) with CLI arg parsing AND real `WriteFile` stdout I/O.
2. Windows PE32+ (AMD64) Dynamic Link Libraries (.dll) with lexicographically sorted Multi-Symbol `.edata`
   Export Tables + optional `.pdata`/`.xdata` x64 stack-unwind tables.
3. Linux ELF64 (x86-64 & ARM64) Standalone Executables (`sys_write` + `sys_exit`) & Multi-Symbol `.so` (`PT_DYNAMIC`, `.dynsym`, `.dynstr`).
4. macOS Mach-O 64 (x86-64 & Apple Silicon ARM64) Executables & Multi-Symbol `.dylib` (`LC_SYMTAB`, `nlist_64`)
   with XNU-compliant Ad-Hoc `LC_CODE_SIGNATURE` (`CS_SuperBlob` `0xFADE0CC0` + SHA-256 page hashes).
"""

import hashlib
import os
import struct
import sys
from typing import Dict, List, Optional, Tuple, Union


class MiniAssembler:
    """
    Two-pass relocation assembler for deterministic instruction and branch offset emission.
    """
    def __init__(self):
        self.code = bytearray()
        self.labels: Dict[str, int] = {}
        self.fixups: List[Tuple[int, str, int, int]] = []

    def label(self, name: str):
        self.labels[name] = len(self.code)

    def emit(self, b: bytes):
        self.code.extend(b)

    def jmp_rel8(self, op_byte: int, target_label: str):
        pos = len(self.code)
        self.emit(bytes([op_byte, 0]))
        self.fixups.append((pos + 1, target_label, 1, 0))

    def jmp_rel32(self, op_bytes: bytes, target_label: str, target_offset: int = 0):
        pos = len(self.code)
        self.emit(op_bytes + b"\x00\x00\x00\x00")
        self.fixups.append((pos + len(op_bytes), target_label, 4, target_offset))

    def resolve(self) -> bytes:
        for pos, target_label, size, offset in self.fixups:
            if target_label not in self.labels:
                raise ValueError(f"Unresolved assembler label: {target_label}")
            target = self.labels[target_label] + offset
            next_rip = pos + size
            disp = target - next_rip
            if size == 1:
                if not (-128 <= disp <= 127):
                    raise ValueError(f"Relative jump displacement {disp} out of int8 range for label '{target_label}'")
                struct.pack_into("<b", self.code, pos, disp)
            else:
                struct.pack_into("<i", self.code, pos, disp)
        return bytes(self.code)


def build_macho_adhoc_codesign_blob(unsigned_macho: bytes, identifier: str = "com.omnicompiler.native", page_shift: int = 14) -> bytes:
    """
    Builds an XNU-compliant big-endian Ad-Hoc `CS_SuperBlob` (`0xFADE0CC0`) containing a
    `CS_CodeDirectory` (`0xFADE0C02`, SHA-256 page hashes) over `unsigned_macho`.
    """
    page_size = 1 << page_shift
    code_limit = len(unsigned_macho)
    n_code_slots = (code_limit + page_size - 1) // page_size
    ident_bytes = identifier.encode("utf-8") + b"\x00"

    hashes = bytearray()
    for slot in range(n_code_slots):
        start = slot * page_size
        end = min(start + page_size, code_limit)
        hashes.extend(hashlib.sha256(unsigned_macho[start:end]).digest())

    cd_header_len = 44
    ident_offset = cd_header_len
    hash_offset = ident_offset + len(ident_bytes)
    cd_total_len = hash_offset + len(hashes)

    # CS_CodeDirectory v0x00020001 (big-endian)
    code_dir = struct.pack(
        ">IIIIIIIIIBBBBI",
        0xFADE0C02,      # magic: CSMAGIC_CODEDIRECTORY
        cd_total_len,    # length
        0x00020001,      # version
        0x00020002,      # flags: kSecCodeSignatureAdhoc | kSecCodeSignatureLinkerSigned
        hash_offset,     # hashOffset
        ident_offset,    # identOffset
        0,               # nSpecialSlots
        n_code_slots,    # nCodeSlots
        code_limit,      # codeLimit
        32,              # hashSize (SHA-256)
        2,               # hashType (CS_HASHTYPE_SHA256)
        0,               # platform
        page_shift,      # pageSize (log2)
        0,               # spare2
    ) + ident_bytes + bytes(hashes)

    sb_total_len = 12 + 8 + len(code_dir)
    superblob = struct.pack(
        ">IIIII",
        0xFADE0CC0,      # magic: CSMAGIC_EMBEDDED_SIGNATURE
        sb_total_len,    # length
        1,               # count = 1 blob
        0,               # CSSLOT_CODEDIRECTORY
        20,              # offset to CodeDirectory
    ) + code_dir
    return superblob


class StandaloneBinaryEmitter:
    """
    Direct Machine-Code Binary & Shared Library Emitter.
    Transforms raw x86-64 and ARM64 machine code into freestanding binaries.
    """

    FILE_ALIGN = 0x200
    SEC_ALIGN = 0x1000
    IMAGE_BASE_PE = 0x140000000
    IMAGE_BASE_DLL = 0x180000000
    VADDR_ELF = 0x400000
    VADDR_SO = 0x100000

    def __init__(self):
        self.host_os = "windows" if sys.platform == "win32" else "linux"

    @staticmethod
    def _align_up(val: int, align: int) -> int:
        return ((val + align - 1) // align) * align

    # =========================================================================
    # 1. WINDOWS PE32+ (AMD64) EXECUTABLES (CLI ARG PARSER + STDOUT WRITER)
    # =========================================================================

    def build_pe64(
        self,
        custom_code: Optional[bytes] = None,
        exit_code: int = 0,
        entry_offset: Optional[int] = None
    ) -> bytes:
        """Builds a compliant Windows PE32+ (AMD64) console executable calling GetCommandLineA + ExitProcess."""
        file_align = self.FILE_ALIGN
        sec_align = self.SEC_ALIGN
        image_base = self.IMAGE_BASE_PE

        if entry_offset is not None and custom_code:
            # First dry-measure prologue size (164 bytes) so rva_idata scales cleanly if custom_code > 4KB
            est_text = 180 + len(custom_code)
            rva_idata = 0x1000 + self._align_up(max(1, est_text), sec_align)

            asm = MiniAssembler()
            asm.emit(b"\x48\x83\xec\x28")  # sub rsp, 40

            call_getcmd_rip = 0x1000 + len(asm.code) + 6
            asm.emit(b"\xff\x15" + struct.pack("<i", (rva_idata + 0x58) - call_getcmd_rip))

            asm.emit(b"\x48\x89\xc6")                    # mov rsi, rax
            asm.emit(b"\x48\xc7\xc3\x0a\x00\x00\x00")    # mov rbx, 10 (default argument)

            asm.emit(b"\x0f\xb6\x0e")                    # movzx rcx, byte [rsi]
            asm.emit(b"\x80\xf9\x22")                    # cmp cl, '"'
            asm.jmp_rel8(0x75, "skip_no_quote")

            asm.label("skip_quoted")
            asm.emit(b"\x48\xff\xc6")
            asm.emit(b"\x0f\xb6\x0e")
            asm.emit(b"\x84\xc9")
            asm.jmp_rel8(0x74, "use_default")
            asm.emit(b"\x80\xf9\x22")
            asm.jmp_rel8(0x75, "skip_quoted")
            asm.emit(b"\x48\xff\xc6")
            asm.jmp_rel8(0xeb, "find_arg")

            asm.label("skip_no_quote")
            asm.emit(b"\x0f\xb6\x0e")
            asm.emit(b"\x84\xc9")
            asm.jmp_rel8(0x74, "use_default")
            asm.emit(b"\x80\xf9\x20")
            asm.jmp_rel8(0x74, "find_arg")
            asm.emit(b"\x48\xff\xc6")
            asm.jmp_rel8(0xeb, "skip_no_quote")

            asm.label("find_arg")
            asm.emit(b"\x0f\xb6\x0e")
            asm.emit(b"\x84\xc9")
            asm.jmp_rel8(0x74, "use_default")
            asm.emit(b"\x80\xf9\x20")
            asm.jmp_rel8(0x75, "parse_num")
            asm.emit(b"\x48\xff\xc6")
            asm.jmp_rel8(0xeb, "find_arg")

            asm.label("parse_num")
            asm.emit(b"\x80\xf9\x30")
            asm.jmp_rel8(0x72, "use_default")
            asm.emit(b"\x80\xf9\x39")
            asm.jmp_rel8(0x77, "use_default")
            asm.emit(b"\x48\x31\xdb")

            asm.label("num_loop")
            asm.emit(b"\x0f\xb6\x0e")
            asm.emit(b"\x48\xff\xc6")
            asm.emit(b"\x84\xc9")
            asm.jmp_rel8(0x74, "use_default")
            asm.emit(b"\x80\xf9\x30")
            asm.jmp_rel8(0x72, "use_default")
            asm.emit(b"\x80\xf9\x39")
            asm.jmp_rel8(0x77, "use_default")
            asm.emit(b"\x80\xe9\x30")
            asm.emit(b"\x48\x6b\xdb\x0a")
            asm.emit(b"\x48\x0f\xb6\xd1")
            asm.emit(b"\x48\x01\xd3")
            asm.jmp_rel8(0xeb, "num_loop")

            asm.label("use_default")
            asm.emit(b"\x48\x89\xd9")                    # mov rcx, rbx
            asm.jmp_rel32(b"\xe8", "fn_target", entry_offset)
            asm.emit(b"\x89\xc1")                        # mov ecx, eax

            call_exit_rip = 0x1000 + len(asm.code) + 6
            asm.emit(b"\xff\x15" + struct.pack("<i", (rva_idata + 0x50) - call_exit_rip))
            asm.emit(b"\x48\x83\xc4\x28\xc3")

            asm.label("fn_target")
            asm.emit(custom_code)

            text_code = bytearray(asm.resolve())
            raw_text_len = len(text_code)
            aligned_text_len = self._align_up(raw_text_len, file_align)
            text_code = text_code.ljust(aligned_text_len, b"\x90")

            idata = bytearray(file_align)
            struct.pack_into("<IIIII", idata, 0, rva_idata + 0x30, 0, 0, rva_idata + 0x80, rva_idata + 0x50)
            struct.pack_into("<QQQ", idata, 0x30, rva_idata + 0x90, rva_idata + 0xA0, 0)
            struct.pack_into("<QQQ", idata, 0x50, rva_idata + 0x90, rva_idata + 0xA0, 0)
            idata[0x80:0x80 + 13] = b"KERNEL32.DLL\0"
            idata[0x90:0x90 + 14] = b"\x00\x00ExitProcess\0"
            idata[0xA0:0xA0 + 18] = b"\x00\x00GetCommandLineA\0"

            iat_rva = rva_idata + 0x50
            iat_size = 24
            idata_vsize = 0xB8
        elif custom_code:
            est_text = 32 + len(custom_code)
            rva_idata = 0x1000 + self._align_up(max(1, est_text), sec_align)
            text_code = bytearray()
            text_code.extend(b"\x48\x83\xec\x28")
            text_code.extend(custom_code)
            text_code.extend(b"\x89\xc1")
            next_rip = 0x1000 + len(text_code) + 6
            iat_rva = rva_idata + 0x40
            disp32 = iat_rva - next_rip
            text_code.extend(b"\xff\x15" + struct.pack("<i", disp32))
            text_code.extend(b"\x48\x83\xc4\x28\xc3")

            raw_text_len = len(text_code)
            aligned_text_len = self._align_up(raw_text_len, file_align)
            text_code.extend(b"\x90" * (aligned_text_len - raw_text_len))

            idata = bytearray(file_align)
            struct.pack_into("<IIIII", idata, 0, rva_idata + 0x30, 0, 0, rva_idata + 0x50, rva_idata + 0x40)
            struct.pack_into("<Q", idata, 0x30, rva_idata + 0x60)
            struct.pack_into("<Q", idata, 0x40, rva_idata + 0x60)
            idata[0x50:0x50 + 13] = b"KERNEL32.DLL\0"
            idata[0x60:0x60 + 14] = b"\x00\x00ExitProcess\0"

            iat_size = 16
            idata_vsize = 0x74
        else:
            rva_idata = 0x2000
            text_code = bytearray()
            text_code.extend(b"\x48\x83\xec\x28")
            text_code.extend(b"\xb9" + struct.pack("<I", exit_code & 0xFFFFFFFF))
            next_rip = 0x1000 + len(text_code) + 6
            iat_rva = rva_idata + 0x40
            disp32 = iat_rva - next_rip
            text_code.extend(b"\xff\x15" + struct.pack("<i", disp32))
            text_code.extend(b"\x48\x83\xc4\x28\xc3")

            raw_text_len = len(text_code)
            aligned_text_len = self._align_up(raw_text_len, file_align)
            text_code.extend(b"\x90" * (aligned_text_len - raw_text_len))

            idata = bytearray(file_align)
            struct.pack_into("<IIIII", idata, 0, rva_idata + 0x30, 0, 0, rva_idata + 0x50, rva_idata + 0x40)
            struct.pack_into("<Q", idata, 0x30, rva_idata + 0x60)
            struct.pack_into("<Q", idata, 0x40, rva_idata + 0x60)
            idata[0x50:0x50 + 13] = b"KERNEL32.DLL\0"
            idata[0x60:0x60 + 14] = b"\x00\x00ExitProcess\0"

            iat_size = 16
            idata_vsize = 0x74

        size_of_image = rva_idata + self._align_up(len(idata), sec_align)

        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<I", dos_header, 0x3C, 0x80)
        dos_stub = b"This program cannot be run in DOS mode.\r\r\n$\0\0\0\0\0\0\0".ljust(64, b"\0")
        pe_sig = b"PE\0\0"

        coff = struct.pack(
            "<HHIIIHH",
            0x8664, 2, 0, 0, 0, 240, 0x0022
        )

        opt = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            0x020B, 14, 0,
            len(text_code), len(idata), 0,
            0x1000, 0x1000,
            image_base,
            sec_align, file_align,
            6, 0, 0, 0, 6, 0, 0,
            size_of_image, 0x200, 0,
            3, 0x8160,
            0x100000, 0x1000, 0x100000, 0x1000,
            0, 16
        )

        data_dirs = bytearray(16 * 8)
        struct.pack_into("<II", data_dirs, 1 * 8, rva_idata, 40)
        struct.pack_into("<II", data_dirs, 12 * 8, iat_rva, iat_size)

        sec_text = struct.pack(
            "<8sIIIIIIHHI",
            b".text\0\0\0",
            raw_text_len, 0x1000, len(text_code), 0x200,
            0, 0, 0, 0,
            0x60000020
        )

        sec_idata = struct.pack(
            "<8sIIIIIIHHI",
            b".idata\0\0",
            idata_vsize, rva_idata, len(idata), 0x200 + len(text_code),
            0, 0, 0, 0,
            0xC0000040
        )

        headers = (dos_header + dos_stub + pe_sig + coff + opt + data_dirs + sec_text + sec_idata).ljust(file_align, b"\0")
        return bytes(headers + text_code + idata)

    def build_pe64_stdout_exe(self, message: Union[str, bytes], exit_code: int = 0) -> bytes:
        """
        Builds a standalone Windows PE32+ (.exe) console executable that writes `message`
        directly to OS `stdout` via `GetStdHandle(-11)` + `WriteFile` and exits with `exit_code`.
        """
        msg_bytes = message.encode("utf-8") if isinstance(message, str) else bytes(message)
        file_align = self.FILE_ALIGN
        sec_align = self.SEC_ALIGN
        image_base = self.IMAGE_BASE_PE

        # Layout: .text at 0x1000, .idata at 0x2000, .rdata at 0x3000
        rva_idata = 0x2000
        rva_rdata = 0x3000
        # IAT slots inside .idata:
        #   0x2060 -> GetStdHandle
        #   0x2068 -> WriteFile
        #   0x2070 -> ExitProcess
        text = bytearray()
        text.extend(b"\x48\x83\xec\x38")              # sub rsp, 56 (32 shadow + 8 5th-arg + 8 bytesWritten + align)
        # ecx = -11 (STD_OUTPUT_HANDLE = 0xFFFFFFF5)
        text.extend(b"\xb9\xf5\xff\xff\xff")          # mov ecx, 0xFFFFFFF5
        rip_after_getstd = 0x1000 + len(text) + 6
        text.extend(b"\xff\x15" + struct.pack("<i", (rva_idata + 0x60) - rip_after_getstd))
        # WriteFile(hFile=rax->rcx, lpBuffer=rdx, nNumberOfBytesToWrite=r8d, lpNumberOfBytesWritten=r9, lpOverlapped=[rsp+32]=0)
        text.extend(b"\x48\x89\xc1")                  # mov rcx, rax
        rip_after_lea_buf = 0x1000 + len(text) + 7
        text.extend(b"\x48\x8d\x15" + struct.pack("<i", rva_rdata - rip_after_lea_buf))  # lea rdx, [rip + msg]
        text.extend(b"\x41\xb8" + struct.pack("<I", len(msg_bytes)))  # mov r8d, len(msg)
        text.extend(b"\x4c\x8d\x4c\x24\x28")          # lea r9, [rsp + 40] (&bytesWritten)
        text.extend(b"\x48\xc7\x44\x24\x20\x00\x00\x00\x00")  # mov qword [rsp + 32], 0 (lpOverlapped = NULL)
        rip_after_write = 0x1000 + len(text) + 6
        text.extend(b"\xff\x15" + struct.pack("<i", (rva_idata + 0x68) - rip_after_write))
        # ExitProcess(exit_code)
        text.extend(b"\xb9" + struct.pack("<I", exit_code & 0xFFFFFFFF))
        rip_after_exit = 0x1000 + len(text) + 6
        text.extend(b"\xff\x15" + struct.pack("<i", (rva_idata + 0x70) - rip_after_exit))
        text.extend(b"\x48\x83\xc4\x38\xc3")

        raw_text_len = len(text)
        raw_text = bytes(text).ljust(file_align, b"\x90")

        idata = bytearray(file_align)
        # Import Descriptor -> ILT=0x2030, Name=0x2090, IAT=0x2060
        struct.pack_into("<IIIII", idata, 0, rva_idata + 0x30, 0, 0, rva_idata + 0x90, rva_idata + 0x60)
        hints = (rva_idata + 0xA0, rva_idata + 0xB4, rva_idata + 0xC4, 0)
        struct.pack_into("<QQQQ", idata, 0x30, *hints)
        struct.pack_into("<QQQQ", idata, 0x60, *hints)
        idata[0x90:0x90 + 13] = b"KERNEL32.DLL\0"
        idata[0xA0:0xA0 + 15] = b"\x00\x00GetStdHandle\0"
        idata[0xB4:0xB4 + 12] = b"\x00\x00WriteFile\0"
        idata[0xC4:0xC4 + 14] = b"\x00\x00ExitProcess\0"

        rdata_raw_len = max(1, len(msg_bytes))
        raw_rdata = msg_bytes.ljust(self._align_up(rdata_raw_len, file_align), b"\x00")
        size_of_image = rva_rdata + self._align_up(len(raw_rdata), sec_align)

        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<I", dos_header, 0x3C, 0x80)
        dos_stub = b"This program cannot be run in DOS mode.\r\r\n$\0\0\0\0\0\0\0".ljust(64, b"\0")
        pe_sig = b"PE\0\0"

        coff = struct.pack("<HHIIIHH", 0x8664, 3, 0, 0, 0, 240, 0x0022)
        opt = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            0x020B, 14, 0,
            len(raw_text), len(idata) + len(raw_rdata), 0,
            0x1000, 0x1000,
            image_base,
            sec_align, file_align,
            6, 0, 0, 0, 6, 0, 0,
            size_of_image, 0x200, 0,
            3, 0x8160,
            0x100000, 0x1000, 0x100000, 0x1000,
            0, 16
        )
        data_dirs = bytearray(16 * 8)
        struct.pack_into("<II", data_dirs, 1 * 8, rva_idata, 40)
        struct.pack_into("<II", data_dirs, 12 * 8, rva_idata + 0x60, 32)

        sec_text = struct.pack("<8sIIIIIIHHI", b".text\0\0\0", raw_text_len, 0x1000, len(raw_text), 0x200, 0, 0, 0, 0, 0x60000020)
        sec_idata = struct.pack("<8sIIIIIIHHI", b".idata\0\0", 0xD8, rva_idata, len(idata), 0x200 + len(raw_text), 0, 0, 0, 0, 0xC0000040)
        sec_rdata = struct.pack("<8sIIIIIIHHI", b".rdata\0\0", rdata_raw_len, rva_rdata, len(raw_rdata), 0x200 + len(raw_text) + len(idata), 0, 0, 0, 0, 0x40000040)

        headers = (dos_header + dos_stub + pe_sig + coff + opt + data_dirs + sec_text + sec_idata + sec_rdata).ljust(file_align, b"\0")
        return bytes(headers + raw_text + idata + raw_rdata)

    # =========================================================================
    # 2. WINDOWS PE32+ (AMD64) MULTI-EXPORT SHARED LIBRARY (.DLL) + UNWIND
    # =========================================================================

    def build_pe64_dll(
        self,
        func_code: bytes,
        export_name: str = "omni_compute",
        dll_name: str = "omni_titan.dll",
        extra_exports: Optional[Dict[str, int]] = None,
        pdata_xdata: Optional[Tuple[bytes, bytes]] = None,
    ) -> bytes:
        """
        Builds a compliant Windows PE32+ (AMD64) Dynamic Link Library (.dll)
        with DllMain stub, lexicographically sorted Multi-Symbol Export Table (.edata),
        and optional `.pdata`/`.xdata` exception-unwind metadata.
        """
        file_align = self.FILE_ALIGN
        sec_align = self.SEC_ALIGN
        image_base = self.IMAGE_BASE_DLL

        # 1. Text Section at RVA 0x1000
        text_data = bytearray()
        text_data.extend(b"\xb8\x01\x00\x00\x00\xc3")  # DllMain -> TRUE
        text_data.extend(b"\x90" * 10)                  # 16-byte align -> 0x1010

        base_fn_rva = 0x1000 + len(text_data)
        text_data.extend(func_code)

        raw_text_len = len(text_data)
        raw_text = bytes(text_data).ljust(self._align_up(max(1, raw_text_len), file_align), b"\x90")
        text_vspan = self._align_up(max(1, len(raw_text)), sec_align)

        # 2. Multi-Symbol Export Directory (.edata) — sorted by ASCII symbol name for GetProcAddress binary search
        exports_map: Dict[str, int] = dict(extra_exports) if extra_exports else {}
        if export_name and export_name not in exports_map:
            exports_map[export_name] = 0
        if not exports_map:
            exports_map["omni_compute"] = 0

        sorted_exports = sorted(exports_map.items(), key=lambda kv: kv[0].encode("ascii"))
        num_syms = len(sorted_exports)

        rva_edata = 0x1000 + text_vspan
        eat_offset = 40
        npt_offset = eat_offset + 4 * num_syms
        ot_offset = npt_offset + 4 * num_syms
        ot_bytes_len = 2 * num_syms
        pad_after_ot = (4 - (ot_bytes_len % 4)) % 4
        strings_start = ot_offset + ot_bytes_len + pad_after_ot

        dll_name_bytes = dll_name.encode("ascii") + b"\x00"
        dll_name_rva = rva_edata + strings_start

        str_blob = bytearray(dll_name_bytes)
        name_rvas: List[int] = []
        eat_rvas: List[int] = []
        for sym_name, sym_off in sorted_exports:
            name_rvas.append(rva_edata + strings_start + len(str_blob))
            str_blob.extend(sym_name.encode("ascii") + b"\x00")
            eat_rvas.append(base_fn_rva + int(sym_off))

        edata = bytearray()
        edata.extend(struct.pack(
            "<IIHHIIIIIII",
            0, 0, 0, 0,
            dll_name_rva,
            1,          # OrdinalBase
            num_syms,   # AddressTableEntries
            num_syms,   # NumberOfNamePointers
            rva_edata + eat_offset,
            rva_edata + npt_offset,
            rva_edata + ot_offset,
        ))
        for rva in eat_rvas:
            edata.extend(struct.pack("<I", rva))
        for nrva in name_rvas:
            edata.extend(struct.pack("<I", nrva))
        for ord_idx in range(num_syms):
            edata.extend(struct.pack("<H", ord_idx))
        edata.extend(b"\x00" * pad_after_ot)
        edata.extend(str_blob)

        raw_edata_len = len(edata)
        raw_edata = bytes(edata).ljust(self._align_up(max(1, raw_edata_len), file_align), b"\x00")
        edata_vspan = self._align_up(max(1, len(raw_edata)), sec_align)

        # Optional 3rd section: .pdata + .xdata unwind metadata
        has_pdata = pdata_xdata is not None
        rva_pdata = rva_edata + edata_vspan
        raw_pdata = b""
        raw_pdata_len = 0
        pdata_dir_size = 0
        if has_pdata:
            pdata_raw, xdata_raw = pdata_xdata  # type: ignore[misc]
            pdata_dir_size = len(pdata_raw)
            # Re-point RUNTIME_FUNCTION.UnwindInfoAddress to rva_pdata + aligned(len(pdata_raw))
            xdata_off_in_sec = self._align_up(len(pdata_raw), 8)
            patched_pdata = bytearray(pdata_raw)
            for p_off in range(0, len(patched_pdata), 12):
                if p_off + 12 <= len(patched_pdata):
                    b_rva, e_rva, _ = struct.unpack_from("<III", patched_pdata, p_off)
                    # Shift function RVAs by +0x10 (DllMain stub offset) if relative to 0x1000
                    if b_rva == 0x1000:
                        b_rva = base_fn_rva
                        e_rva = base_fn_rva + (e_rva - 0x1000)
                    struct.pack_into("<III", patched_pdata, p_off, b_rva, e_rva, rva_pdata + xdata_off_in_sec)
            combined_unwind = bytes(patched_pdata).ljust(xdata_off_in_sec, b"\x00") + xdata_raw
            raw_pdata_len = len(combined_unwind)
            raw_pdata = combined_unwind.ljust(self._align_up(max(1, raw_pdata_len), file_align), b"\x00")
            size_of_image = rva_pdata + self._align_up(len(raw_pdata), sec_align)
        else:
            size_of_image = rva_edata + edata_vspan

        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<I", dos_header, 0x3C, 0x80)
        dos_stub = b"This program cannot be run in DOS mode.\r\r\n$\0\0\0\0\0\0\0".ljust(64, b"\0")
        pe_sig = b"PE\0\0"

        num_sections = 3 if has_pdata else 2
        coff = struct.pack("<HHIIIHH", 0x8664, num_sections, 0, 0, 0, 240, 0x2022)

        opt = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            0x020B, 14, 0,
            len(raw_text), len(raw_edata) + len(raw_pdata), 0,
            0x1000, 0x1000,
            image_base,
            sec_align, file_align,
            6, 0, 0, 0, 6, 0, 0,
            size_of_image, 0x200, 0,
            3, 0x8160,
            0x100000, 0x1000, 0x100000, 0x1000,
            0, 16
        )

        data_dirs = bytearray(16 * 8)
        struct.pack_into("<II", data_dirs, 0 * 8, rva_edata, raw_edata_len)
        if has_pdata:
            struct.pack_into("<II", data_dirs, 3 * 8, rva_pdata, pdata_dir_size)

        sec1 = struct.pack("<8sIIIIIIHHI", b".text\0\0\0", raw_text_len, 0x1000, len(raw_text), 0x200, 0, 0, 0, 0, 0x60000020)
        sec2 = struct.pack("<8sIIIIIIHHI", b".edata\0\0", raw_edata_len, rva_edata, len(raw_edata), 0x200 + len(raw_text), 0, 0, 0, 0, 0x40000040)

        sec_hdrs = sec1 + sec2
        if has_pdata:
            sec3 = struct.pack(
                "<8sIIIIIIHHI",
                b".pdata\0\0",
                raw_pdata_len, rva_pdata, len(raw_pdata), 0x200 + len(raw_text) + len(raw_edata),
                0, 0, 0, 0, 0x40000040
            )
            sec_hdrs += sec3

        headers = (dos_header + dos_stub + pe_sig + coff + opt + data_dirs + sec_hdrs).ljust(file_align, b"\0")
        return bytes(headers + raw_text + raw_edata + raw_pdata)

    # =========================================================================
    # 3. LINUX ELF64 (x86-64) STANDALONE EXECUTABLE + STDOUT EXECUTABLE
    # =========================================================================

    def build_elf64(
        self,
        custom_code: Optional[bytes] = None,
        exit_code: int = 0,
        entry_offset: Optional[int] = None
    ) -> bytes:
        """Builds a compliant Linux ELF64 (x86-64) standalone executable via sys_exit."""
        vaddr = self.VADDR_ELF
        entry_offset_hdr = 120
        entry_addr = vaddr + entry_offset_hdr

        code = bytearray()
        if entry_offset is not None and custom_code:
            asm = MiniAssembler()
            asm.emit(b"\x48\xc7\xc0\x0a\x00\x00\x00")
            asm.emit(b"\x48\x8b\x34\x24")
            asm.emit(b"\x48\x83\xfe\x02")
            asm.jmp_rel8(0x7c, "use_default")

            asm.emit(b"\x48\x8b\x74\x24\x10")
            asm.emit(b"\x0f\xb6\x0e")
            asm.emit(b"\x80\xf9\x30")
            asm.jmp_rel8(0x72, "use_default")
            asm.emit(b"\x80\xf9\x39")
            asm.jmp_rel8(0x77, "use_default")
            asm.emit(b"\x48\x31\xc0")

            asm.label("parse_loop")
            asm.emit(b"\x0f\xb6\x0e")
            asm.emit(b"\x48\xff\xc6")
            asm.emit(b"\x84\xc9")
            asm.jmp_rel8(0x74, "use_default")
            asm.emit(b"\x80\xf9\x30")
            asm.jmp_rel8(0x72, "use_default")
            asm.emit(b"\x80\xf9\x39")
            asm.jmp_rel8(0x77, "use_default")
            asm.emit(b"\x80\xe9\x30")
            asm.emit(b"\x48\x6b\xc0\x0a")
            asm.emit(b"\x48\x0f\xb6\xd1")
            asm.emit(b"\x48\x01\xd0")
            asm.jmp_rel8(0xeb, "parse_loop")

            asm.label("use_default")
            asm.emit(b"\x48\x89\xc7")
            asm.jmp_rel32(b"\xe8", "fn_target", entry_offset)
            asm.emit(b"\x89\xc7")
            asm.emit(b"\xb8\x3c\x00\x00\x00")
            asm.emit(b"\x0f\x05")

            asm.label("fn_target")
            asm.emit(custom_code)
            code = bytearray(asm.resolve())
        elif custom_code:
            code.extend(custom_code)
            code.extend(b"\x89\xc7")
            code.extend(b"\xb8\x3c\x00\x00\x00")
            code.extend(b"\x0f\x05")
        else:
            code.extend(b"\xbf" + struct.pack("<I", exit_code & 0xFFFFFFFF))
            code.extend(b"\xb8\x3c\x00\x00\x00")
            code.extend(b"\x0f\x05")

        total_size = entry_offset_hdr + len(code)
        elf_ident = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8)
        elf_header = struct.pack(
            "<16sHHIQQQIHHHHHH",
            elf_ident,
            2, 0x3E, 1, entry_addr, 64, 0, 0,
            64, 56, 1, 64, 0, 0
        )
        prog_header = struct.pack(
            "<IIQQQQQQ",
            1, 7, 0, vaddr, vaddr, total_size, total_size, 0x1000
        )
        return bytes(elf_header + prog_header + code)

    def build_elf64_stdout_exe(self, message: Union[str, bytes], exit_code: int = 0) -> bytes:
        """Builds a freestanding Linux ELF64 executable writing `message` to fd 1 via `sys_write`."""
        msg_bytes = message.encode("utf-8") if isinstance(message, str) else bytes(message)
        vaddr = self.VADDR_ELF
        entry_offset_hdr = 120
        entry_addr = vaddr + entry_offset_hdr

        asm = MiniAssembler()
        asm.emit(b"\xb8\x01\x00\x00\x00")                    # mov eax, 1 (sys_write)
        asm.emit(b"\xbf\x01\x00\x00\x00")                    # mov edi, 1 (stdout)
        asm.jmp_rel32(b"\x48\x8d\x35", "msg_data", 0)        # lea rsi, [rip + msg_data]
        asm.emit(b"\xba" + struct.pack("<I", len(msg_bytes)))  # mov edx, len
        asm.emit(b"\x0f\x05")                                # syscall
        asm.emit(b"\xbf" + struct.pack("<I", exit_code & 0xFFFFFFFF))
        asm.emit(b"\xb8\x3c\x00\x00\x00")                    # mov eax, 60 (sys_exit)
        asm.emit(b"\x0f\x05")
        asm.label("msg_data")
        asm.emit(msg_bytes)

        code = asm.resolve()
        total_size = entry_offset_hdr + len(code)
        elf_ident = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8)
        elf_header = struct.pack("<16sHHIQQQIHHHHHH", elf_ident, 2, 0x3E, 1, entry_addr, 64, 0, 0, 64, 56, 1, 64, 0, 0)
        prog_header = struct.pack("<IIQQQQQQ", 1, 7, 0, vaddr, vaddr, total_size, total_size, 0x1000)
        return elf_header + prog_header + code

    # =========================================================================
    # 4. LINUX ELF64 (x86-64) MULTI-SYMBOL SHARED OBJECT (.SO)
    # =========================================================================

    def build_elf64_so(
        self,
        func_code: bytes,
        export_name: str = "omni_compute",
        extra_exports: Optional[Dict[str, int]] = None,
    ) -> bytes:
        """
        Builds a compliant Linux ELF64 Shared Object (ET_DYN) with
        PT_DYNAMIC, multi-symbol `.dynsym`, and `.dynstr` for dynamic runtime linking.
        """
        vaddr = self.VADDR_SO
        code = bytearray(func_code)

        code_offset = 0x200
        code_vaddr = vaddr + code_offset

        exports_map: Dict[str, int] = dict(extra_exports) if extra_exports else {}
        if export_name and export_name not in exports_map:
            exports_map[export_name] = 0
        if not exports_map:
            exports_map["omni_compute"] = 0

        sorted_exports = sorted(exports_map.items(), key=lambda kv: kv[0])

        dynstr = bytearray(b"\x00")
        dynsym = bytearray(b"\x00" * 24)  # STN_UNDEF null symbol

        for idx, (sym_name, sym_off) in enumerate(sorted_exports):
            st_name = len(dynstr)
            dynstr.extend(sym_name.encode("ascii") + b"\x00")
            # Compute symbol size heuristically up to next offset or end of code
            next_offs = [o for _, o in sorted_exports if o > sym_off]
            st_size = (min(next_offs) - sym_off) if next_offs else max(1, len(code) - sym_off)
            dynsym.extend(struct.pack(
                "<IBBHQQ",
                st_name,
                0x12,                   # STB_GLOBAL | STT_FUNC
                0,
                1,
                code_vaddr + int(sym_off),
                max(1, st_size),
            ))

        # Align dynsym to 8 bytes
        dynstr_offset = code_offset + len(code)
        dynsym_offset = self._align_up(dynstr_offset + len(dynstr), 8)

        dyn_table = bytearray()
        dyn_table.extend(struct.pack("<QQ", 5, vaddr + dynstr_offset))   # DT_STRTAB
        dyn_table.extend(struct.pack("<QQ", 6, vaddr + dynsym_offset))   # DT_SYMTAB
        dyn_table.extend(struct.pack("<QQ", 10, len(dynstr)))            # DT_STRSZ
        dyn_table.extend(struct.pack("<QQ", 11, 24))                     # DT_SYMENT
        dyn_table.extend(struct.pack("<QQ", 0, 0))                       # DT_NULL

        dynamic_offset = self._align_up(dynsym_offset + len(dynsym), 8)
        total_size = dynamic_offset + len(dyn_table)

        elf_ident = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8)
        elf_header = struct.pack(
            "<16sHHIQQQIHHHHHH",
            elf_ident,
            3,          # ET_DYN
            0x3E,       # EM_X86_64
            1,
            code_vaddr,
            64, 0, 0,
            64, 56, 2, 64, 0, 0
        )

        ph_load = struct.pack(
            "<IIQQQQQQ",
            1, 7, 0, vaddr, vaddr, total_size, total_size, 0x1000
        )

        ph_dynamic = struct.pack(
            "<IIQQQQQQ",
            2, 6, dynamic_offset,
            vaddr + dynamic_offset, vaddr + dynamic_offset,
            len(dyn_table), len(dyn_table), 8
        )

        file_bytes = bytearray(total_size)
        file_bytes[0:64] = elf_header
        file_bytes[64:120] = ph_load
        file_bytes[120:176] = ph_dynamic
        file_bytes[code_offset:code_offset + len(code)] = code
        file_bytes[dynstr_offset:dynstr_offset + len(dynstr)] = dynstr
        file_bytes[dynsym_offset:dynsym_offset + len(dynsym)] = dynsym
        file_bytes[dynamic_offset:dynamic_offset + len(dyn_table)] = dyn_table

        return bytes(file_bytes)

    # =========================================================================
    # 5. ARM64 (AARCH64) STANDALONE EXECUTABLES (LINUX & WINDOWS)
    # =========================================================================

    def build_arm64_elf(self, exit_code: int = 0, custom_code: Optional[bytes] = None) -> bytes:
        vaddr = self.VADDR_ELF
        entry_offset = 120
        entry_addr = vaddr + entry_offset

        code = bytearray()
        if custom_code:
            # Call custom_code (which ends in RET) via BL #2 instructions (+8 bytes), then SVC #0 sys_exit(X0)!
            # BL +12 (3 words: BL, MOV X8 #93, SVC #0 -> custom_code starts at +12 bytes = +3 words)
            bl_fn = 0x94000003
            mov_x8 = 0xD2800000 | (93 << 5) | 8
            svc_0 = 0xD4000001
            code.extend(struct.pack("<III", bl_fn, mov_x8, svc_0))
            code.extend(custom_code)
        else:
            mov_x0 = 0xD2800000 | ((exit_code & 0xFFFF) << 5) | 0
            mov_x8 = 0xD2800000 | (93 << 5) | 8
            svc_0 = 0xD4000001
            code.extend(struct.pack("<III", mov_x0, mov_x8, svc_0))

        total_size = entry_offset + len(code)
        elf_ident = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8)
        elf_header = struct.pack(
            "<16sHHIQQQIHHHHHH",
            elf_ident,
            2, 183, 1, entry_addr, 64, 0, 0,
            64, 56, 1, 64, 0, 0
        )
        prog_header = struct.pack("<IIQQQQQQ", 1, 7, 0, vaddr, vaddr, total_size, total_size, 0x1000)
        return elf_header + prog_header + bytes(code)

    def build_arm64_pe(self, exit_code: int = 0, custom_code: Optional[bytes] = None) -> bytes:
        file_align = self.FILE_ALIGN
        sec_align = self.SEC_ALIGN
        image_base = self.IMAGE_BASE_PE

        code = bytearray()
        if custom_code:
            code.extend(custom_code)
        else:
            mov_x0 = 0xD2800000 | ((exit_code & 0xFFFF) << 5) | 0
            ret_inst = 0xD65F03C0
            code.extend(struct.pack("<II", mov_x0, ret_inst))

        raw_code = bytes(code).ljust(self._align_up(max(1, len(code)), file_align), b"\x00")
        size_of_image = 0x1000 + self._align_up(len(raw_code), sec_align)

        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<I", dos_header, 0x3C, 0x80)
        dos_stub = b"This program cannot be run in DOS mode.\r\r\n$\0\0\0\0\0\0\0".ljust(64, b"\0")
        pe_sig = b"PE\0\0"

        coff = struct.pack("<HHIIIHH", 0xAA64, 1, 0, 0, 0, 240, 0x0022)
        opt = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            0x020B, 14, 0,
            len(raw_code), 0, 0,
            0x1000, 0x1000,
            image_base,
            sec_align, file_align,
            6, 0, 0, 0, 6, 0, 0,
            size_of_image, 0x200, 0,
            3, 0x8160,
            0x100000, 0x1000, 0x100000, 0x1000,
            0, 16
        )
        data_dirs = bytearray(16 * 8)
        sec1 = struct.pack("<8sIIIIIIHHI", b".text\0\0\0", len(code), 0x1000, len(raw_code), 0x200, 0, 0, 0, 0, 0x60000020)
        headers = (dos_header + dos_stub + pe_sig + coff + opt + data_dirs + sec1).ljust(file_align, b"\0")
        return bytes(headers + raw_code)

    # =========================================================================
    # 6. MACH-O 64-BIT (macOS x86-64 & Apple Silicon ARM64 + AD-HOC CODESIGN)
    # =========================================================================

    def build_macho64(
        self,
        exit_code: int = 0,
        custom_code: Optional[bytes] = None,
        arch: str = "x86_64",
        entry_offset: Optional[int] = None
    ) -> bytes:
        """
        Synthesizes a 64-bit Mach-O standalone executable (`MH_EXECUTE`) for macOS.
        On Apple Silicon (`arm64`), embeds `__LINKEDIT` + XNU `LC_CODE_SIGNATURE` (`0x1D`)
        with SHA-256 page hashes (`CS_SuperBlob` `0xFADE0CC0`).
        """
        is_arm64 = arch.lower() in ("arm64", "aarch64")
        cpu_type = 0x0100000C if is_arm64 else 0x01000007
        cpu_subtype = 0x00000000 if is_arm64 else 0x80000003

        if custom_code is not None:
            raw_code = custom_code
        else:
            if is_arm64:
                val = exit_code & 0xFFFF
                mov_x0 = struct.pack("<I", 0xD2800000 | (val << 5))
                mov_x16 = struct.pack("<I", 0xD2800000 | (1 << 5) | 16)
                svc = struct.pack("<I", 0xD4001001)
                raw_code = mov_x0 + mov_x16 + svc
            else:
                raw_code = struct.pack("<BI", 0xBF, exit_code & 0xFFFFFFFF)
                raw_code += b"\xb8\x01\x00\x00\x02\x0f\x05"

        page_size = 0x4000 if is_arm64 else 0x1000
        code_offset = page_size
        code_vaddr = 0x100000000 + code_offset
        padded_code = raw_code.ljust(self._align_up(max(1, len(raw_code)), 16), b"\x00")
        text_file_end = self._align_up(code_offset + len(padded_code), page_size)
        text_vmsize = text_file_end

        cmd1_size = 72        # __PAGEZERO
        cmd2_size = 72 + 80   # __TEXT + __text
        cmd3_size = 24        # LC_MAIN
        cmd_linkedit_size = 72 if is_arm64 else 0
        cmd_codesig_size = 16 if is_arm64 else 0

        ncmds = 5 if is_arm64 else 3
        sizeofcmds = cmd1_size + cmd2_size + cmd3_size + cmd_linkedit_size + cmd_codesig_size

        # Pre-calculate codesign size for __LINKEDIT if ARM64
        page_shift = 14 if is_arm64 else 12
        dummy_unsigned = b"\x00" * text_file_end
        est_sig = build_macho_adhoc_codesign_blob(dummy_unsigned, page_shift=page_shift) if is_arm64 else b""

        header = struct.pack(
            "<IIIIIIII",
            0xFEEDFACF, cpu_type, cpu_subtype,
            0x2, ncmds, sizeofcmds, 0x00200085, 0
        )

        cmd_pagezero = struct.pack(
            "<II16sQQQQIIII",
            0x19, cmd1_size, b"__PAGEZERO\x00\x00\x00\x00\x00\x00",
            0, 0x100000000, 0, 0, 0, 0, 0, 0
        )

        cmd_text = struct.pack(
            "<II16sQQQQIIII",
            0x19, cmd2_size, b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            0x100000000, text_vmsize, 0, text_file_end, 5, 5, 1, 0
        )

        sec_text = struct.pack(
            "<16s16sQQIIIIIIII",
            b"__text\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            code_vaddr, len(raw_code), code_offset, 2, 0, 0, 0x80000400, 0, 0, 0
        )

        actual_entry = code_offset + (entry_offset if entry_offset is not None else 0)
        cmd_main = struct.pack("<IIQQ", 0x80000028, cmd3_size, actual_entry, 0)

        extra_cmds = b""
        if is_arm64:
            linkedit_vmaddr = 0x100000000 + text_vmsize
            linkedit_vmsize = self._align_up(len(est_sig), page_size)
            cmd_linkedit = struct.pack(
                "<II16sQQQQIIII",
                0x19, 72, b"__LINKEDIT\x00\x00\x00\x00\x00\x00",
                linkedit_vmaddr, linkedit_vmsize,
                text_file_end, len(est_sig),
                1, 1, 0, 0
            )
            cmd_codesig = struct.pack("<IIII", 0x1D, 16, text_file_end, len(est_sig))
            extra_cmds = cmd_linkedit + cmd_codesig

        all_headers = (header + cmd_pagezero + cmd_text + sec_text + cmd_main + extra_cmds).ljust(code_offset, b"\x00")
        unsigned_img = (all_headers + padded_code).ljust(text_file_end, b"\x00")

        if is_arm64:
            real_sig = build_macho_adhoc_codesign_blob(unsigned_img, page_shift=page_shift)
            return unsigned_img + real_sig
        return unsigned_img[:code_offset + len(raw_code)]

    def build_macho64_dylib(
        self,
        func_code: bytes,
        export_name: str = "omni_compute",
        arch: str = "x86_64",
        dylib_name: Optional[str] = None,
        extra_exports: Optional[Dict[str, int]] = None,
    ) -> bytes:
        """
        Synthesizes a 64-bit Mach-O dynamic shared library (`MH_DYLIB`) with:
          - `LC_SYMTAB (0x02)` multi-symbol `nlist_64` export table (`_symbol` ABI convention)
          - `__LINKEDIT` segment
          - On `arm64`: XNU Ad-Hoc `LC_CODE_SIGNATURE (0x1D)` (`CS_SuperBlob` `0xFADE0CC0`).
        """
        is_arm64 = arch.lower() in ("arm64", "aarch64")
        cpu_type = 0x0100000C if is_arm64 else 0x01000007
        cpu_subtype = 0x00000000 if is_arm64 else 0x80000003
        page_size = 0x4000 if is_arm64 else 0x1000
        page_shift = 14 if is_arm64 else 12
        code_offset = page_size
        code_vaddr = code_offset

        exports_map: Dict[str, int] = dict(extra_exports) if extra_exports else {}
        if export_name and export_name not in exports_map:
            exports_map[export_name] = 0
        if not exports_map:
            exports_map["omni_compute"] = 0
        sorted_exports = sorted(exports_map.items(), key=lambda kv: kv[0])

        # Build Mach-O nlist_64 symbol table + string table
        strtab = bytearray(b"\x00")
        symtab = bytearray()
        for sym_name, sym_off in sorted_exports:
            macho_sym = sym_name if sym_name.startswith("_") else f"_{sym_name}"
            n_strx = len(strtab)
            strtab.extend(macho_sym.encode("utf-8") + b"\x00")
            # nlist_64: n_strx(I), n_type(B=0x0F N_EXT|N_SECT), n_sect(B=1), n_desc(H=0), n_value(Q)
            symtab.extend(struct.pack("<IBBHQ", n_strx, 0x0F, 1, 0, code_vaddr + int(sym_off)))
        strtab_padded = bytes(strtab).ljust(self._align_up(len(strtab), 16), b"\x00")

        padded_code = func_code.ljust(self._align_up(max(1, len(func_code)), 16), b"\x00")
        text_file_end = self._align_up(code_offset + len(padded_code), page_size)
        text_vmsize = text_file_end

        symoff = text_file_end
        stroff = symoff + len(symtab)
        after_syms_off = self._align_up(stroff + len(strtab_padded), 16)

        install_name = (dylib_name or f"lib{export_name}.dylib").encode("utf-8") + b"\x00"
        padded_name = install_name.ljust(self._align_up(len(install_name), 8), b"\x00")
        cmd_id_size = 24 + len(padded_name)

        cmd_text_size = 72 + 80
        cmd_linkedit_size = 72
        cmd_symtab_size = 24
        cmd_codesig_size = 16 if is_arm64 else 0

        ncmds = 5 if is_arm64 else 4
        sizeofcmds = cmd_text_size + cmd_linkedit_size + cmd_id_size + cmd_symtab_size + cmd_codesig_size

        est_sig = build_macho_adhoc_codesign_blob(b"\x00" * after_syms_off, page_shift=page_shift) if is_arm64 else b""
        linkedit_filesize = (after_syms_off - text_file_end) + len(est_sig)
        linkedit_vmsize = self._align_up(max(1, linkedit_filesize), page_size)

        header = struct.pack(
            "<IIIIIIII",
            0xFEEDFACF, cpu_type, cpu_subtype,
            0x6, ncmds, sizeofcmds, 0x00200085, 0
        )

        cmd_text = struct.pack(
            "<II16sQQQQIIII",
            0x19, cmd_text_size, b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            0, text_vmsize, 0, text_file_end, 5, 5, 1, 0
        )
        sec_text = struct.pack(
            "<16s16sQQIIIIIIII",
            b"__text\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            code_vaddr, len(func_code), code_offset, 2, 0, 0, 0x80000400, 0, 0, 0
        )
        cmd_linkedit = struct.pack(
            "<II16sQQQQIIII",
            0x19, cmd_linkedit_size, b"__LINKEDIT\x00\x00\x00\x00\x00\x00",
            text_vmsize, linkedit_vmsize,
            text_file_end, linkedit_filesize,
            1, 1, 0, 0
        )
        cmd_id = struct.pack("<IIIIII", 0x0D, cmd_id_size, 24, 1, 0x00010000, 0x00010000) + padded_name
        cmd_symtab = struct.pack("<IIIIII", 0x02, cmd_symtab_size, symoff, len(sorted_exports), stroff, len(strtab_padded))

        extra_cmds = struct.pack("<IIII", 0x1D, 16, after_syms_off, len(est_sig)) if is_arm64 else b""

        all_headers = (header + cmd_text + sec_text + cmd_linkedit + cmd_id + cmd_symtab + extra_cmds).ljust(code_offset, b"\x00")
        text_img = (all_headers + padded_code).ljust(text_file_end, b"\x00")
        unsigned_dylib = (text_img + bytes(symtab) + strtab_padded).ljust(after_syms_off, b"\x00")

        if is_arm64:
            real_sig = build_macho_adhoc_codesign_blob(unsigned_dylib, page_shift=page_shift)
            return unsigned_dylib + real_sig
        return unsigned_dylib

    # =========================================================================
    # HIGH-LEVEL ORCHESTRATION HELPERS
    # =========================================================================

    def emit_standalone_binary(
        self,
        output_path: str,
        target_format: str = "auto",
        custom_code: Optional[bytes] = None,
        exit_code: int = 0,
        entry_offset: Optional[int] = None
    ) -> str:
        if target_format == "auto":
            target_format = "pe64" if sys.platform == "win32" else "elf64"

        if target_format == "pe64":
            if not output_path.endswith(".exe"):
                output_path += ".exe"
            data = self.build_pe64(custom_code=custom_code, exit_code=exit_code, entry_offset=entry_offset)
        elif target_format == "elf64":
            data = self.build_elf64(custom_code=custom_code, exit_code=exit_code, entry_offset=entry_offset)
        elif target_format == "arm64_elf":
            data = self.build_arm64_elf(exit_code=exit_code, custom_code=custom_code)
        elif target_format == "arm64_pe":
            if not output_path.endswith(".exe"):
                output_path += ".exe"
            data = self.build_arm64_pe(exit_code=exit_code, custom_code=custom_code)
        elif target_format in ("macho64", "macho_x86_64"):
            data = self.build_macho64(exit_code=exit_code, custom_code=custom_code, arch="x86_64", entry_offset=entry_offset)
        elif target_format in ("arm64_macho", "macho_arm64"):
            data = self.build_macho64(exit_code=exit_code, custom_code=custom_code, arch="arm64", entry_offset=entry_offset)
        else:
            raise ValueError(f"Unsupported binary target: {target_format}")

        self._write_file(output_path, data)
        return output_path

    def emit_stdout_executable(
        self,
        output_path: str,
        message: Union[str, bytes],
        target_format: str = "auto",
        exit_code: int = 0,
    ) -> str:
        """Emits a standalone native executable writing `message` directly to OS stdout."""
        if target_format == "auto":
            target_format = "pe64" if sys.platform == "win32" else "elf64"
        if target_format == "pe64":
            if not output_path.endswith(".exe"):
                output_path += ".exe"
            data = self.build_pe64_stdout_exe(message=message, exit_code=exit_code)
        elif target_format == "elf64":
            data = self.build_elf64_stdout_exe(message=message, exit_code=exit_code)
        else:
            raise ValueError(f"Unsupported stdout binary format: {target_format}")
        self._write_file(output_path, data)
        return output_path

    def emit_shared_library(
        self,
        output_path: str,
        func_code: bytes,
        export_name: str = "omni_compute",
        target_format: str = "auto",
        extra_exports: Optional[Dict[str, int]] = None,
        pdata_xdata: Optional[Tuple[bytes, bytes]] = None,
    ) -> str:
        if target_format == "auto":
            target_format = "pe_dll" if sys.platform == "win32" else "elf_so"

        if target_format == "pe_dll":
            if not output_path.endswith(".dll"):
                output_path += ".dll"
            data = self.build_pe64_dll(
                func_code=func_code,
                export_name=export_name,
                dll_name=os.path.basename(output_path),
                extra_exports=extra_exports,
                pdata_xdata=pdata_xdata,
            )
        elif target_format == "elf_so":
            if not output_path.endswith(".so"):
                output_path += ".so"
            data = self.build_elf64_so(func_code=func_code, export_name=export_name, extra_exports=extra_exports)
        elif target_format in ("macho_dylib", "dylib"):
            if not output_path.endswith(".dylib"):
                output_path += ".dylib"
            data = self.build_macho64_dylib(
                func_code=func_code,
                export_name=export_name,
                arch="x86_64",
                dylib_name=os.path.basename(output_path),
                extra_exports=extra_exports,
            )
        elif target_format in ("arm64_macho_dylib", "macho_arm64_dylib"):
            if not output_path.endswith(".dylib"):
                output_path += ".dylib"
            data = self.build_macho64_dylib(
                func_code=func_code,
                export_name=export_name,
                arch="arm64",
                dylib_name=os.path.basename(output_path),
                extra_exports=extra_exports,
            )
        else:
            raise ValueError(f"Unsupported shared library target: {target_format}")

        self._write_file(output_path, data)
        return output_path

    def _write_file(self, path: str, data: bytes):
        dir_path = os.path.dirname(path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        if hasattr(os, "chmod") and not path.endswith(".dll") and not path.endswith(".exe"):
            try:
                os.chmod(path, 0o755)
            except Exception:
                pass


def emit_standalone_executable(output_path: str, exit_code: int = 0, custom_code: Optional[bytes] = None) -> str:
    emitter = StandaloneBinaryEmitter()
    return emitter.emit_standalone_binary(output_path=output_path, custom_code=custom_code, exit_code=exit_code)
