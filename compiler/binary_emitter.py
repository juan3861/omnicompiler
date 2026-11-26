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
from typing import Any, Dict, List, Optional, Tuple, Union


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
    VADDR_SO = 0

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
            self._emit_pe64_cli_entry_prefix(asm, 0x1000, rva_idata + 0x58, rva_idata + 0x50, entry_offset)
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

    @staticmethod
    def build_pdb_msf_rsds(
        dll_name: str,
        exports_map: Dict[str, int],
        base_fn_rva: int = 0x1010,
        pdb_guid: Optional[bytes] = None,
        age: int = 1,
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Synthesizes a deterministic Microsoft CodeView RSDS debug record and
        a standards-compliant MSF 7.0 `.pdb` symbol container mapping exported
        functions for Windows debuggers (`WinDbg`, `pefile`, `llvm-pdbutil`).
        """
        if pdb_guid is None:
            sig_seed = f"{dll_name}:{sorted(exports_map.items())}".encode("utf-8")
            pdb_guid = hashlib.sha256(sig_seed).digest()[:16]
        pdb_base = os.path.splitext(os.path.basename(dll_name))[0] + ".pdb"
        rsds_record = b"RSDS" + pdb_guid + struct.pack("<I", age) + pdb_base.encode("utf-8") + b"\x00"

        block_size = 4096
        # Stream 0: old directory (0B)
        # Stream 1: PDB Info stream (Version 20000404 + Signature + Age + GUID + NamedMapSize=0)
        s1_info = struct.pack("<III16sI", 20000404, 0x6F6D6E69, age, pdb_guid, 0)
        # Stream 2: TPI minimal 56-byte header (Version 20040203)
        s2_tpi = struct.pack("<IIIIIIIIIIIIII", 20040203, 56, 0x1000, 0x1000, 0, 0xFFFFFFFF, 0, 0, 0, 0, 0, 0, 0, 0)
        # Stream 3: DBI header (64B) + encoded public export table payload
        sym_recs = bytearray()
        for sym_name, sym_off in sorted(exports_map.items(), key=lambda kv: kv[0]):
            name_b = sym_name.encode("utf-8") + b"\x00"
            rec_len = 14 + len(name_b)
            sym_recs.extend(struct.pack("<HHIIH", rec_len, 0x110E, 2, base_fn_rva + int(sym_off), 1) + name_b)
            while len(sym_recs) % 4:
                sym_recs.append(0)
        s3_dbi = struct.pack("<IiiiHHIiiHIIHHII", 0xFFFFFFFF, 19990903, age, -1, 0, 0, 0, len(sym_recs), 0, 0, 0, 0, 0, 0, 0, 0)[:64]
        s3_full = s3_dbi + bytes(sym_recs)
        s4_ipi = struct.pack("<IIIIIIIIIIIIII", 20040203, 56, 0x1000, 0x1000, 0, 0xFFFFFFFF, 0, 0, 0, 0, 0, 0, 0, 0)

        streams = [b"", s1_info, s2_tpi, s3_full, s4_ipi]
        stream_blocks: List[List[int]] = []
        next_blk = 5  # Blocks: 0=Super, 1=FPM0, 2=FPM1, 3=DirMap, 4=Dir
        for st in streams:
            n_b = (len(st) + block_size - 1) // block_size if st else 0
            blks = list(range(next_blk, next_blk + n_b))
            stream_blocks.append(blks)
            next_blk += n_b

        dir_bytes = bytearray()
        dir_bytes.extend(struct.pack("<I", len(streams)))
        for st in streams:
            dir_bytes.extend(struct.pack("<I", len(st)))
        for blks in stream_blocks:
            for b in blks:
                dir_bytes.extend(struct.pack("<I", b))

        num_dir_blocks = (len(dir_bytes) + block_size - 1) // block_size
        # Reserve block 4..4+num_dir_blocks-1 if needed (stream sizes fit comfortably in 1 block < 4096)
        assert num_dir_blocks == 1, "Stream directory overflowed 1 block"
        num_blocks = next_blk

        msf = bytearray(num_blocks * block_size)
        magic = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00"
        super_blk = struct.pack("<32sIIIIII", magic, block_size, 1, num_blocks, len(dir_bytes), 0, 3)
        msf[0:len(super_blk)] = super_blk

        # Free Page Maps (Block 1 and Block 2)
        fpm = bytearray(b"\xff" * block_size)
        for b_idx in range(num_blocks):
            fpm[b_idx // 8] &= ~(1 << (b_idx % 8))
        msf[1 * block_size:2 * block_size] = fpm
        msf[2 * block_size:3 * block_size] = fpm

        # Block 3: Directory Block Map -> [4]
        msf[3 * block_size:3 * block_size + 4] = struct.pack("<I", 4)
        # Block 4: Stream Directory
        msf[4 * block_size:4 * block_size + len(dir_bytes)] = dir_bytes
        # Blocks 5..: Stream data
        for st, blks in zip(streams, stream_blocks):
            if st and blks:
                msf[blks[0] * block_size:blks[0] * block_size + len(st)] = st

        return rsds_record, bytes(msf), pdb_guid

    def build_pe64_dll(
        self,
        func_code: bytes,
        export_name: str = "omni_compute",
        dll_name: str = "omni_titan.dll",
        extra_exports: Optional[Dict[str, int]] = None,
        pdata_xdata: Optional[Tuple[bytes, bytes]] = None,
        imports: Optional[Dict[str, List[str]]] = None,
        os_import_stubs: Optional[Dict[str, int]] = None,
        data_bytes: Optional[bytes] = None,
        bss_size: int = 0,
        abs64_reloc_rvas: Optional[List[int]] = None,
        init_array_offset_in_data: int = 0,
        init_array_size: int = 0,
        fini_array_offset_in_data: int = 0,
        fini_array_size: int = 0,
        tdata_bytes: Optional[bytes] = None,
        tbss_size: int = 0,
        pdata_prelinked: bool = False,
        emit_pdb_path: Optional[str] = None,
        emit_debug_dir: bool = True,
    ) -> bytes:
        """
        Builds a compliant Windows PE32+ (AMD64) Dynamic Link Library (.dll)
        with DllMain stub, `.edata`, optional `.idata` OS Import Table, optional
        `.pdata`/`.xdata`, optional writable `.data`+`.bss`, and optional `.reloc`.
        """
        file_align = self.FILE_ALIGN
        sec_align = self.SEC_ALIGN
        image_base = self.IMAGE_BASE_DLL

        # 1. Text Section metrics (fixed length even before IAT patching)
        has_init_calls = int(init_array_size) > 0
        text_prefix_len = 64 if has_init_calls else 16
        text_prefix = (b"\x90" * 64) if has_init_calls else (b"\xb8\x01\x00\x00\x00\xc3" + (b"\x90" * 10))
        base_fn_rva = 0x1000 + text_prefix_len
        raw_text_len = text_prefix_len + len(func_code)
        aligned_text_len = self._align_up(max(1, raw_text_len), file_align)
        text_vspan = self._align_up(max(1, aligned_text_len), sec_align)

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

        # Optional .idata section (multi-DLL dynamic OS imports)
        dll_items = [(dll, list(syms)) for dll, syms in (imports or {}).items() if syms]
        has_idata = bool(dll_items)
        rva_idata = rva_edata + edata_vspan
        raw_idata = b""
        raw_idata_len = 0
        idata_vspan = 0
        idata_desc_bytes = 0
        iat_rva = 0
        iat_total_bytes = 0
        patched_func_code = bytearray(func_code)

        if has_idata:
            n_dlls = len(dll_items)
            idata_desc_bytes = (n_dlls + 1) * 20
            ilt_offsets: Dict[str, int] = {}
            cur = idata_desc_bytes
            for dll, syms in dll_items:
                ilt_offsets[dll] = cur
                cur += (len(syms) + 1) * 8

            iat_start_off = cur
            iat_offsets: Dict[str, int] = {}
            for dll, syms in dll_items:
                iat_offsets[dll] = cur
                cur += (len(syms) + 1) * 8
            iat_total_bytes = cur - iat_start_off
            iat_rva = rva_idata + iat_start_off

            dll_name_offs: Dict[str, int] = {}
            imp_str_blob = bytearray()
            for dll, _ in dll_items:
                dll_name_offs[dll] = cur + len(imp_str_blob)
                enc = dll.encode("ascii") + b"\x00"
                if len(enc) % 2:
                    enc += b"\x00"
                imp_str_blob.extend(enc)

            hint_offs: Dict[Tuple[str, str], int] = {}
            for dll, syms in dll_items:
                for sym in syms:
                    hint_offs[(dll, sym)] = cur + len(imp_str_blob)
                    enc = b"\x00\x00" + sym.encode("ascii") + b"\x00"
                    if len(enc) % 2:
                        enc += b"\x00"
                    imp_str_blob.extend(enc)

            raw_idata_len = cur + len(imp_str_blob)
            raw_idata_ba = bytearray(self._align_up(max(1, raw_idata_len), file_align))
            flat_iat_slots: Dict[str, int] = {}
            for d_idx, (dll, syms) in enumerate(dll_items):
                struct.pack_into(
                    "<IIIII",
                    raw_idata_ba,
                    d_idx * 20,
                    rva_idata + ilt_offsets[dll],
                    0, 0,
                    rva_idata + dll_name_offs[dll],
                    rva_idata + iat_offsets[dll],
                )
                for s_idx, sym in enumerate(syms):
                    hint_rva = rva_idata + hint_offs[(dll, sym)]
                    struct.pack_into("<Q", raw_idata_ba, ilt_offsets[dll] + s_idx * 8, hint_rva)
                    struct.pack_into("<Q", raw_idata_ba, iat_offsets[dll] + s_idx * 8, hint_rva)
                    flat_iat_slots[sym] = rva_idata + iat_offsets[dll] + s_idx * 8
            raw_idata_ba[cur:cur + len(imp_str_blob)] = imp_str_blob
            raw_idata = bytes(raw_idata_ba)
            idata_vspan = self._align_up(len(raw_idata), sec_align)

            if os_import_stubs:
                for sym, stub_off in os_import_stubs.items():
                    if sym in flat_iat_slots and stub_off + 6 <= len(patched_func_code):
                        stub_rip = base_fn_rva + stub_off + 6
                        disp = flat_iat_slots[sym] - stub_rip
                        patched_func_code[stub_off:stub_off + 6] = b"\xff\x25" + struct.pack("<i", disp)

        raw_text = (text_prefix + bytes(patched_func_code)).ljust(aligned_text_len, b"\x90")

        # Optional .pdata + .xdata unwind metadata
        has_pdata = pdata_xdata is not None
        rva_pdata = (rva_idata + idata_vspan) if has_idata else (rva_edata + edata_vspan)
        raw_pdata = b""
        raw_pdata_len = 0
        pdata_dir_size = 0
        if has_pdata:
            pdata_raw, xdata_raw = pdata_xdata  # type: ignore[misc]
            pdata_dir_size = len(pdata_raw)
            xdata_off_in_sec = self._align_up(len(pdata_raw), 8)
            patched_pdata = bytearray(pdata_raw)
            if not pdata_prelinked:
                fn_rva_shift = base_fn_rva - 0x1000
                for p_off in range(0, len(patched_pdata), 12):
                    if p_off + 12 <= len(patched_pdata):
                        b_rva, e_rva, u_off = struct.unpack_from("<III", patched_pdata, p_off)
                        if b_rva >= 0x1000:
                            b_rva += fn_rva_shift
                            e_rva += fn_rva_shift
                        rel_xdata_off = u_off if u_off < len(xdata_raw) else 0
                        struct.pack_into("<III", patched_pdata, p_off, b_rva, e_rva, rva_pdata + xdata_off_in_sec + rel_xdata_off)
            combined_unwind = bytes(patched_pdata).ljust(xdata_off_in_sec, b"\x00") + xdata_raw
            raw_pdata_len = len(combined_unwind)
            raw_pdata = combined_unwind.ljust(self._align_up(max(1, raw_pdata_len), file_align), b"\x00")
            pdata_vspan = self._align_up(len(raw_pdata), sec_align)
        else:
            pdata_vspan = 0

        # Optional writable .data (+ .bss) section
        rw_init = bytes(data_bytes or b"")
        has_data_sec = bool(rw_init) or (int(bss_size) > 0)
        rva_data = rva_pdata + pdata_vspan
        if has_init_calls:
            init_rva = rva_data + int(init_array_offset_in_data)
            disp_init = init_rva - 0x1012
            dllmain_stub = (
                b"\x83\xfa\x01"
                b"\x75\x2f"
                b"\x53"
                b"\x56"
                b"\x48\x83\xec\x28"
                + b"\x48\x8d\x1d" + struct.pack("<i", disp_init)
                + b"\x48\x8d\xb3" + struct.pack("<I", int(init_array_size))
                + b"\x48\x39\xf3"
                b"\x73\x10"
                b"\x48\x8b\x03"
                b"\x48\x85\xc0"
                b"\x74\x02"
                b"\xff\xd0"
                b"\x48\x83\xc3\x08"
                b"\xeb\xeb"
                b"\x48\x83\xc4\x28"
                b"\x5e"
                b"\x5b"
                b"\xb8\x01\x00\x00\x00"
                b"\xc3"
                + (b"\x90" * 6)
            )
            raw_text = dllmain_stub + raw_text[64:]
        raw_data_sec = b""
        data_vsize = 0
        data_vspan = 0
        if has_data_sec:
            data_vsize = max(1, len(rw_init) + max(0, int(bss_size)))
            raw_data_sec = rw_init.ljust(self._align_up(max(1, len(rw_init)), file_align), b"\x00")
            data_vspan = self._align_up(data_vsize, sec_align)

        # Optional .tls section (IMAGE_TLS_DIRECTORY64 + TLS template bytes + _tls_index)
        tls_init_pe = bytes(tdata_bytes or b"")
        has_tls_sec = bool(tls_init_pe) or (int(tbss_size) > 0)
        rva_tls = rva_data + data_vspan
        raw_tls_sec = b""
        raw_tls_len = 0
        tls_vspan = 0
        tls_dir_rva = 0
        tls_reloc_rvas: List[int] = []
        if has_tls_sec:
            tls_data_pad_len = max(8, self._align_up(len(tls_init_pe), 8))
            tls_idx_off = tls_data_pad_len
            tls_dir_off = tls_idx_off + 8
            tls_dir_rva = rva_tls + tls_dir_off
            start_va = image_base + rva_tls
            end_va = image_base + rva_tls + len(tls_init_pe)
            idx_va = image_base + rva_tls + tls_idx_off
            tls_dir_bytes = struct.pack(
                "<QQQQII",
                start_va,
                end_va,
                idx_va,
                0,
                max(0, int(tbss_size)),
                0,
            )
            tls_blob = tls_init_pe.ljust(tls_data_pad_len, b"\x00") + (b"\x00" * 8) + tls_dir_bytes
            raw_tls_len = len(tls_blob)
            raw_tls_sec = tls_blob.ljust(self._align_up(max(1, raw_tls_len), file_align), b"\x00")
            tls_vspan = self._align_up(len(raw_tls_sec), sec_align)
            tls_reloc_rvas = [tls_dir_rva, tls_dir_rva + 8, tls_dir_rva + 16]

        # Optional CodeView RSDS Debug Directory (.debug) + MSF 7.0 .pdb
        has_debug_sec = bool(emit_debug_dir or emit_pdb_path)
        rva_debug = rva_tls + tls_vspan
        raw_debug_sec = b""
        raw_debug_len = 0
        debug_vspan = 0
        if has_debug_sec:
            rsds_rec, pdb_bytes, _guid = self.build_pdb_msf_rsds(dll_name, exports_map, base_fn_rva=base_fn_rva)
            if emit_pdb_path:
                self._write_file(emit_pdb_path, pdb_bytes)
            raw_debug_len = 28 + len(rsds_rec)
            # Defer PointerToRawData fill until size_of_headers is computed below
            raw_debug_sec = bytearray(self._align_up(max(1, raw_debug_len), file_align))
            raw_debug_sec[28:28 + len(rsds_rec)] = rsds_rec
            debug_vspan = self._align_up(len(raw_debug_sec), sec_align)

        # Optional .reloc Base Relocation Table (`IMAGE_REL_BASED_DIR64`)
        reloc_list = sorted(set([int(r) for r in (abs64_reloc_rvas or [])] + tls_reloc_rvas))
        has_reloc = bool(reloc_list)
        rva_reloc = rva_debug + debug_vspan
        raw_reloc_sec = b""
        raw_reloc_len = 0
        reloc_vspan = 0
        if has_reloc:
            pages: Dict[int, List[int]] = {}
            for r in reloc_list:
                pages.setdefault(r & ~0xFFF, []).append(r & 0xFFF)
            reloc_blob = bytearray()
            for pg_rva in sorted(pages.keys()):
                entries = [(0xA << 12) | off for off in pages[pg_rva]]
                if len(entries) % 2:
                    entries.append(0)
                blk_sz = 8 + 2 * len(entries)
                reloc_blob.extend(struct.pack("<II", pg_rva, blk_sz))
                for ent in entries:
                    reloc_blob.extend(struct.pack("<H", ent))
            raw_reloc_len = len(reloc_blob)
            raw_reloc_sec = bytes(reloc_blob).ljust(self._align_up(max(1, raw_reloc_len), file_align), b"\x00")
            reloc_vspan = self._align_up(len(raw_reloc_sec), sec_align)

        size_of_image = rva_reloc + reloc_vspan

        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<I", dos_header, 0x3C, 0x80)
        dos_stub = b"This program cannot be run in DOS mode.\r\r\n$\0\0\0\0\0\0\0".ljust(64, b"\0")
        pe_sig = b"PE\0\0"

        num_sections = (
            2
            + (1 if has_idata else 0)
            + (1 if has_pdata else 0)
            + (1 if has_data_sec else 0)
            + (1 if has_tls_sec else 0)
            + (1 if has_debug_sec else 0)
            + (1 if has_reloc else 0)
        )
        size_of_headers = self._align_up(64 + 64 + 4 + 20 + 96 + (16 * 8) + (40 * num_sections), file_align)
        if has_debug_sec:
            ptr_to_debug_sec = (
                size_of_headers
                + len(raw_text)
                + len(raw_edata)
                + len(raw_idata)
                + len(raw_pdata)
                + len(raw_data_sec)
                + len(raw_tls_sec)
            )
            struct.pack_into(
                "<IIHHIIII",
                raw_debug_sec,
                0,
                0,
                0,
                0,
                0,
                2,  # IMAGE_DEBUG_TYPE_CODEVIEW
                raw_debug_len - 28,
                rva_debug + 28,
                ptr_to_debug_sec + 28,
            )
            raw_debug_sec = bytes(raw_debug_sec)

        coff = struct.pack("<HHIIIHH", 0x8664, num_sections, 0, 0, 0, 240, 0x2022)

        opt = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            0x020B, 14, 0,
            len(raw_text), len(raw_edata) + len(raw_idata) + len(raw_pdata) + len(raw_data_sec) + len(raw_tls_sec) + len(raw_debug_sec) + len(raw_reloc_sec), max(0, int(bss_size)),
            0x1000, 0x1000,
            image_base,
            sec_align, file_align,
            6, 0, 0, 0, 6, 0, 0,
            size_of_image, size_of_headers, 0,
            3, 0x8160,
            0x100000, 0x1000, 0x100000, 0x1000,
            0, 16
        )

        data_dirs = bytearray(16 * 8)
        struct.pack_into("<II", data_dirs, 0 * 8, rva_edata, raw_edata_len)
        if has_idata:
            struct.pack_into("<II", data_dirs, 1 * 8, rva_idata, idata_desc_bytes)
            struct.pack_into("<II", data_dirs, 12 * 8, iat_rva, iat_total_bytes)
        if has_pdata:
            struct.pack_into("<II", data_dirs, 3 * 8, rva_pdata, pdata_dir_size)
        if has_reloc:
            struct.pack_into("<II", data_dirs, 5 * 8, rva_reloc, raw_reloc_len)
        if has_debug_sec:
            struct.pack_into("<II", data_dirs, 6 * 8, rva_debug, 28)
        if has_tls_sec:
            struct.pack_into("<II", data_dirs, 9 * 8, tls_dir_rva, 40)

        cur_file_ptr = size_of_headers
        sec1 = struct.pack("<8sIIIIIIHHI", b".text\0\0\0", raw_text_len, 0x1000, len(raw_text), cur_file_ptr, 0, 0, 0, 0, 0x60000020)
        cur_file_ptr += len(raw_text)
        sec2 = struct.pack("<8sIIIIIIHHI", b".edata\0\0", raw_edata_len, rva_edata, len(raw_edata), cur_file_ptr, 0, 0, 0, 0, 0x40000040)
        cur_file_ptr += len(raw_edata)

        sec_hdrs = sec1 + sec2
        if has_idata:
            sec_hdrs += struct.pack("<8sIIIIIIHHI", b".idata\0\0", raw_idata_len, rva_idata, len(raw_idata), cur_file_ptr, 0, 0, 0, 0, 0xC0000040)
            cur_file_ptr += len(raw_idata)
        if has_pdata:
            sec_hdrs += struct.pack("<8sIIIIIIHHI", b".pdata\0\0", raw_pdata_len, rva_pdata, len(raw_pdata), cur_file_ptr, 0, 0, 0, 0, 0x40000040)
            cur_file_ptr += len(raw_pdata)
        if has_data_sec:
            sec_hdrs += struct.pack("<8sIIIIIIHHI", b".data\0\0\0", data_vsize, rva_data, len(raw_data_sec), cur_file_ptr, 0, 0, 0, 0, 0xC0000040)
            cur_file_ptr += len(raw_data_sec)
        if has_tls_sec:
            sec_hdrs += struct.pack("<8sIIIIIIHHI", b".tls\0\0\0\0", raw_tls_len, rva_tls, len(raw_tls_sec), cur_file_ptr, 0, 0, 0, 0, 0xC0000040)
            cur_file_ptr += len(raw_tls_sec)
        if has_debug_sec:
            sec_hdrs += struct.pack("<8sIIIIIIHHI", b".debug\0\0", raw_debug_len, rva_debug, len(raw_debug_sec), cur_file_ptr, 0, 0, 0, 0, 0x40000040)
            cur_file_ptr += len(raw_debug_sec)
        if has_reloc:
            sec_hdrs += struct.pack("<8sIIIIIIHHI", b".reloc\0\0", raw_reloc_len, rva_reloc, len(raw_reloc_sec), cur_file_ptr, 0, 0, 0, 0, 0x42000040)
            cur_file_ptr += len(raw_reloc_sec)

        headers = (dos_header + dos_stub + pe_sig + coff + opt + data_dirs + sec_hdrs).ljust(size_of_headers, b"\0")
        return bytes(headers + raw_text + raw_edata + raw_idata + raw_pdata + raw_data_sec + raw_tls_sec + raw_debug_sec + raw_reloc_sec)

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
            self._emit_elf64_cli_entry_prefix(asm, entry_offset)
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

    @staticmethod
    def _build_elf_eh_frame_hdr(
        code: bytes,
        code_vaddr: int,
        eh_offset: int,
        eh_size: int,
        hdr_vaddr: int,
    ) -> bytes:
        if eh_size <= 0 or eh_offset < 0 or eh_offset + eh_size > len(code):
            return b""
        eh_slice = code[eh_offset:eh_offset + eh_size]
        entries: List[Tuple[int, int]] = []
        pos = 0
        eh_base_vaddr = code_vaddr + eh_offset
        while pos + 4 <= len(eh_slice):
            rec_len = struct.unpack_from("<I", eh_slice, pos)[0]
            if rec_len == 0 or rec_len == 0xFFFFFFFF:
                break
            next_pos = pos + 4 + rec_len
            if next_pos > len(eh_slice):
                break
            if pos + 12 <= next_pos:
                cie_id = struct.unpack_from("<I", eh_slice, pos + 4)[0]
                if cie_id != 0:
                    init_pc_s32 = struct.unpack_from("<i", eh_slice, pos + 8)[0]
                    func_vaddr = eh_base_vaddr + pos + 8 + init_pc_s32
                    fde_vaddr = eh_base_vaddr + pos
                    entries.append((func_vaddr - hdr_vaddr, fde_vaddr - hdr_vaddr))
            pos = next_pos
        entries.sort(key=lambda kv: kv[0])
        out = bytearray()
        eh_ptr_disp = eh_base_vaddr - (hdr_vaddr + 4)
        out.extend(struct.pack("<BBBBiI", 1, 0x1B, 0x03, 0x3B, eh_ptr_disp, len(entries)))
        for init_loc_rel, fde_rel in entries:
            out.extend(struct.pack("<ii", init_loc_rel, fde_rel))
        return bytes(out)

    def build_elf64_so(
        self,
        func_code: bytes,
        export_name: str = "omni_compute",
        extra_exports: Optional[Dict[str, int]] = None,
        dwarf_sections: Optional[Dict[str, bytes]] = None,
        arch: str = "x86_64",
        needed_libs: Optional[List[str]] = None,
        imported_funcs: Optional[List[str]] = None,
        os_import_stubs: Optional[Dict[str, int]] = None,
        data_bytes: Optional[bytes] = None,
        bss_size: int = 0,
        abs64_reloc_rvas: Optional[List[int]] = None,
        init_array_offset_in_data: int = 0,
        init_array_size: int = 0,
        fini_array_offset_in_data: int = 0,
        fini_array_size: int = 0,
        tdata_bytes: Optional[bytes] = None,
        tbss_size: int = 0,
        eh_frame_offset_in_code: int = 0,
        eh_frame_size: int = 0,
        external_dyn_relocs: Optional[List[Tuple[int, str, int, int]]] = None,
    ) -> bytes:
        """
        Builds a compliant Linux ELF64 Shared Object (ET_DYN) with
        PT_DYNAMIC (`DT_NEEDED`, `DT_JMPREL`, `DT_PLTGOT`, `DF_BIND_NOW`),
        multi-symbol `.dynsym`, `.dynstr`, `.got.plt`, and optional DWARF v5 debug sections.
        """
        is_arm64 = arch.lower() in ("arm64", "aarch64")
        e_machine = 183 if is_arm64 else 0x3E
        r_type = 1026 if is_arm64 else 7  # R_AARCH64_JUMP_SLOT vs R_X86_64_JUMP_SLOT

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
        plt_imports = sorted(set(imported_funcs or (os_import_stubs.keys() if os_import_stubs else [])))
        ext_reloc_list = list(external_dyn_relocs or [])
        dynsym_imports = sorted(set(plt_imports) | {sym for _, sym, _, _ in ext_reloc_list})
        ordered_libs = list(needed_libs or [])

        dynstr = bytearray(b"\x00")
        lib_str_offs: List[int] = []
        for lib_s in ordered_libs:
            lib_str_offs.append(len(dynstr))
            dynstr.extend(lib_s.encode("ascii") + b"\x00")

        dynsym = bytearray(b"\x00" * 24)  # STN_UNDEF null symbol

        for sym_name, sym_off in sorted_exports:
            st_name = len(dynstr)
            dynstr.extend(sym_name.encode("ascii") + b"\x00")
            next_offs = [o for _, o in sorted_exports if o > sym_off]
            st_size = (min(next_offs) - sym_off) if next_offs else max(1, len(code) - sym_off)
            dynsym.extend(struct.pack(
                "<IBBHQQ",
                st_name, 0x12, 0, 1, code_vaddr + int(sym_off), max(1, st_size),
            ))

        imp_sym_indices: Dict[str, int] = {}
        for idx_i, imp_sym in enumerate(dynsym_imports):
            st_name = len(dynstr)
            dynstr.extend(imp_sym.encode("ascii") + b"\x00")
            imp_sym_indices[imp_sym] = 1 + len(sorted_exports) + idx_i
            dynsym.extend(struct.pack("<IBBHQQ", st_name, 0x12, 0, 0, 0, 0))

        # Align dynsym to 8 bytes
        dynstr_offset = code_offset + len(code)
        dynsym_offset = self._align_up(dynstr_offset + len(dynstr), 8)

        # Build SysV DT_HASH table covering exported symbols
        def _elf_sysv_hash(name_bytes: bytes) -> int:
            h = 0
            for b in name_bytes:
                h = (h << 4) + b
                g = h & 0xF0000000
                if g:
                    h ^= (g >> 24)
                h &= ~g
            return h & 0xFFFFFFFF

        nbucket = max(1, len(sorted_exports))
        nchain = 1 + len(sorted_exports) + len(dynsym_imports)
        buckets = [0] * nbucket
        chains = [0] * nchain
        for idx, (sym_name, _sym_off) in enumerate(sorted_exports):
            sym_idx = idx + 1
            b_idx = _elf_sysv_hash(sym_name.encode("ascii")) % nbucket
            chains[sym_idx] = buckets[b_idx]
            buckets[b_idx] = sym_idx
        hash_table = struct.pack(f"<II{nbucket}I{nchain}I", nbucket, nchain, *buckets, *chains)

        hash_offset = self._align_up(dynsym_offset + len(dynsym), 8)
        got_plt_offset = self._align_up(hash_offset + len(hash_table), 8)
        got_plt_len = (3 + len(plt_imports)) * 8 if plt_imports else 0
        rela_plt_offset = self._align_up(got_plt_offset + got_plt_len, 8)
        rela_plt = bytearray()
        got_slots: Dict[str, int] = {}
        for idx_i, imp_sym in enumerate(plt_imports):
            slot_vaddr = vaddr + got_plt_offset + (3 + idx_i) * 8
            got_slots[imp_sym] = slot_vaddr
            r_info = (imp_sym_indices[imp_sym] << 32) | r_type
            rela_plt.extend(struct.pack("<QQq", slot_vaddr, r_info, 0))

        rela_dyn_offset = self._align_up(rela_plt_offset + len(rela_plt), 8)
        rw_init = bytes(data_bytes or b"")
        tls_init = bytes(tdata_bytes or b"")
        has_tls_seg = bool(tls_init) or (int(tbss_size) > 0)
        has_rw_seg = bool(rw_init) or (int(bss_size) > 0) or has_tls_seg
        rel_rvas = sorted(set(int(r) for r in (abs64_reloc_rvas or [])))
        eh_hdr_probe_len = (
            len(self._build_elf_eh_frame_hdr(code, code_vaddr, eh_frame_offset_in_code, eh_frame_size, 0))
            if eh_frame_size > 0
            else 0
        )
        rela_dyn = bytearray()
        if rel_rvas or ext_reloc_list:
            r_rel_type = 1027 if is_arm64 else 8  # R_AARCH64_RELATIVE vs R_X86_64_RELATIVE
            # Preliminary dynamic size to locate rw_vaddr if needed for inspecting addends inside data_bytes
            n_dyn_tags = (
                len(lib_str_offs)
                + 5
                + (5 if plt_imports else 0)
                + 3
                + (2 if init_array_size > 0 else 0)
                + (2 if fini_array_size > 0 else 0)
                + 1
            )
            est_dyn_off = self._align_up(rela_dyn_offset + (len(rel_rvas) + len(ext_reloc_list)) * 24, 8)
            est_ro_end = est_dyn_off + n_dyn_tags * 16 + eh_hdr_probe_len
            est_rw_vaddr = self._align_up(est_ro_end, 0x1000) if has_rw_seg else 0
            for rva_r in rel_rvas:
                add_v = 0
                if has_rw_seg and est_rw_vaddr <= rva_r and (rva_r - est_rw_vaddr) + 8 <= len(rw_init):
                    add_v = struct.unpack_from("<q", rw_init, rva_r - est_rw_vaddr)[0]
                elif code_vaddr <= rva_r and (rva_r - code_vaddr) + 8 <= len(code):
                    add_v = struct.unpack_from("<q", code, rva_r - code_vaddr)[0]
                rela_dyn.extend(struct.pack("<QQq", rva_r, r_rel_type, add_v))
            for ext_rva, ext_sym, ext_rtype, ext_addend in ext_reloc_list:
                r_info_ext = (imp_sym_indices[ext_sym] << 32) | int(ext_rtype)
                rela_dyn.extend(struct.pack("<QQq", int(ext_rva), r_info_ext, int(ext_addend)))

        dynamic_offset = self._align_up(rela_dyn_offset + len(rela_dyn), 8)
        pre_n_tags = (
            len(lib_str_offs)
            + 5
            + (5 if plt_imports else 0)
            + (3 if rela_dyn else 0)
            + (2 if init_array_size > 0 else 0)
            + (2 if fini_array_size > 0 else 0)
            + 1
        )
        eh_hdr_offset = dynamic_offset + pre_n_tags * 16
        eh_frame_hdr = (
            self._build_elf_eh_frame_hdr(code, code_vaddr, eh_frame_offset_in_code, eh_frame_size, vaddr + eh_hdr_offset)
            if eh_frame_size > 0
            else b""
        )
        has_eh_hdr = bool(eh_frame_hdr)
        ro_total_size = eh_hdr_offset + len(eh_frame_hdr)
        rw_file_off = self._align_up(ro_total_size, 0x1000) if has_rw_seg else ro_total_size
        rw_vaddr = vaddr + rw_file_off

        dyn_entries: List[Tuple[int, int]] = [(1, l_off) for l_off in lib_str_offs]
        dyn_entries.extend([
            (4, vaddr + hash_offset),       # DT_HASH
            (5, vaddr + dynstr_offset),     # DT_STRTAB
            (6, vaddr + dynsym_offset),     # DT_SYMTAB
            (10, len(dynstr)),              # DT_STRSZ
            (11, 24),                       # DT_SYMENT
        ])
        if plt_imports:
            dyn_entries.extend([
                (3, vaddr + got_plt_offset),    # DT_PLTGOT
                (20, 7),                        # DT_PLTREL = DT_RELA
                (2, len(rela_plt)),             # DT_PLTRELSZ
                (23, vaddr + rela_plt_offset),  # DT_JMPREL
                (30, 8),                        # DT_FLAGS = DF_BIND_NOW
            ])
        if rela_dyn:
            dyn_entries.extend([
                (7, vaddr + rela_dyn_offset),   # DT_RELA
                (8, len(rela_dyn)),             # DT_RELASZ
                (9, 24),                        # DT_RELAENT
            ])
        if init_array_size > 0:
            dyn_entries.extend([
                (25, rw_vaddr + int(init_array_offset_in_data)),  # DT_INIT_ARRAY
                (27, int(init_array_size)),                       # DT_INIT_ARRAYSZ
            ])
        if fini_array_size > 0:
            dyn_entries.extend([
                (26, rw_vaddr + int(fini_array_offset_in_data)),  # DT_FINI_ARRAY
                (28, int(fini_array_size)),                       # DT_FINI_ARRAYSZ
            ])
        dyn_entries.append((0, 0))              # DT_NULL

        dyn_table = bytearray()
        for tag, val in dyn_entries:
            dyn_table.extend(struct.pack("<QQ", tag, val))

        if os_import_stubs and got_slots:
            for sym, stub_off in os_import_stubs.items():
                if sym not in got_slots:
                    continue
                if is_arm64:
                    if stub_off + 12 <= len(code):
                        code[stub_off:stub_off + 12] = self._encode_a64_got_stub(
                            code_vaddr + stub_off, got_slots[sym]
                        )
                else:
                    if stub_off + 6 <= len(code):
                        stub_rip = code_vaddr + stub_off + 6
                        disp = got_slots[sym] - stub_rip
                        code[stub_off:stub_off + 6] = b"\xff\x25" + struct.pack("<i", disp)

        tls_file_off = (rw_file_off + len(rw_init)) if has_tls_seg else 0
        tls_vaddr = (rw_vaddr + len(rw_init)) if has_tls_seg else 0
        rw_tail_end = (tls_file_off + len(tls_init)) if has_tls_seg else (rw_file_off + len(rw_init))
        total_size = rw_tail_end if has_rw_seg else ro_total_size
        n_ph = 3 + (1 if has_rw_seg else 0) + (1 if has_tls_seg else 0) + (1 if has_eh_hdr else 0)

        elf_ident = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8)
        elf_header = struct.pack(
            "<16sHHIQQQIHHHHHH",
            elf_ident,
            3,          # ET_DYN
            e_machine,
            1,
            code_vaddr,
            64, 0, 0,
            64, 56, n_ph, 64, 0, 0
        )

        ph_load = struct.pack(
            "<IIQQQQQQ",
            1, 7, 0, vaddr, vaddr, ro_total_size, ro_total_size, 0x1000
        )

        ph_dynamic = struct.pack(
            "<IIQQQQQQ",
            2, 6, dynamic_offset,
            vaddr + dynamic_offset, vaddr + dynamic_offset,
            len(dyn_table), len(dyn_table), 8
        )

        ph_gnu_stack = struct.pack(
            "<IIQQQQQQ",
            0x6474E551,  # PT_GNU_STACK
            6,           # PF_R | PF_W
            0, 0, 0, 0, 0, 16
        )

        file_bytes = bytearray(total_size)
        file_bytes[0:64] = elf_header
        ph_pos = 64
        for ph_bytes in (ph_load, ph_dynamic, ph_gnu_stack):
            file_bytes[ph_pos:ph_pos + 56] = ph_bytes
            ph_pos += 56
        if has_rw_seg:
            ph_load_rw = struct.pack(
                "<IIQQQQQQ",
                1, 6, rw_file_off, rw_vaddr, rw_vaddr,
                len(rw_init) + (len(tls_init) if has_tls_seg else 0),
                len(rw_init) + max(0, int(bss_size)) + (len(tls_init) + max(0, int(tbss_size)) if has_tls_seg else 0),
                0x1000,
            )
            file_bytes[ph_pos:ph_pos + 56] = ph_load_rw
            ph_pos += 56
        if has_tls_seg:
            ph_tls = struct.pack(
                "<IIQQQQQQ",
                7, 4, tls_file_off, tls_vaddr, tls_vaddr,
                len(tls_init), len(tls_init) + max(0, int(tbss_size)), 16,
            )
            file_bytes[ph_pos:ph_pos + 56] = ph_tls
            ph_pos += 56
        if has_eh_hdr:
            ph_eh_frame = struct.pack(
                "<IIQQQQQQ",
                0x6474E550,  # PT_GNU_EH_FRAME
                4,           # PF_R
                eh_hdr_offset,
                vaddr + eh_hdr_offset,
                vaddr + eh_hdr_offset,
                len(eh_frame_hdr),
                len(eh_frame_hdr),
                4,
            )
            file_bytes[ph_pos:ph_pos + 56] = ph_eh_frame
            ph_pos += 56
        file_bytes[code_offset:code_offset + len(code)] = code
        file_bytes[dynstr_offset:dynstr_offset + len(dynstr)] = dynstr
        file_bytes[dynsym_offset:dynsym_offset + len(dynsym)] = dynsym
        file_bytes[hash_offset:hash_offset + len(hash_table)] = hash_table
        if plt_imports:
            file_bytes[got_plt_offset:got_plt_offset + 8] = struct.pack("<Q", vaddr + dynamic_offset)
            file_bytes[rela_plt_offset:rela_plt_offset + len(rela_plt)] = rela_plt
        if rela_dyn:
            file_bytes[rela_dyn_offset:rela_dyn_offset + len(rela_dyn)] = rela_dyn
        file_bytes[dynamic_offset:dynamic_offset + len(dyn_table)] = dyn_table
        if has_eh_hdr:
            file_bytes[eh_hdr_offset:eh_hdr_offset + len(eh_frame_hdr)] = eh_frame_hdr
        if has_rw_seg and rw_init:
            file_bytes[rw_file_off:rw_file_off + len(rw_init)] = rw_init
        if has_tls_seg and tls_init:
            file_bytes[tls_file_off:tls_file_off + len(tls_init)] = tls_init

        if dwarf_sections:
            valid_dwarf = [(k, v) for k, v in dwarf_sections.items() if v]
            if valid_dwarf:
                shstrtab = bytearray(b"\x00")
                shstr_name = b".shstrtab\x00"
                shstr_off_in_tab = len(shstrtab)
                shstrtab.extend(shstr_name)
                sec_name_offs = []
                for sname, _ in valid_dwarf:
                    sec_name_offs.append(len(shstrtab))
                    shstrtab.extend(sname.encode("ascii") + b"\x00")

                shstrtab_file_off = len(file_bytes)
                file_bytes.extend(shstrtab)

                sec_file_offs = []
                for _, sdata in valid_dwarf:
                    pad = (8 - (len(file_bytes) % 8)) % 8
                    if pad:
                        file_bytes.extend(b"\x00" * pad)
                    sec_file_offs.append((len(file_bytes), len(sdata)))
                    file_bytes.extend(sdata)

                pad_sh = (8 - (len(file_bytes) % 8)) % 8
                if pad_sh:
                    file_bytes.extend(b"\x00" * pad_sh)
                shoff = len(file_bytes)
                shnum = 2 + len(valid_dwarf)  # SHT_NULL + .shstrtab + dwarf sections
                # 0: SHT_NULL
                file_bytes.extend(struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
                # 1: .shstrtab (SHT_STRTAB = 3)
                file_bytes.extend(struct.pack(
                    "<IIQQQQIIQQ",
                    shstr_off_in_tab, 3, 0, 0, shstrtab_file_off, len(shstrtab), 0, 0, 1, 0
                ))
                # 2..N: DWARF sections (SHT_PROGBITS = 1)
                for (sname, _), n_off, (f_off, f_sz) in zip(valid_dwarf, sec_name_offs, sec_file_offs):
                    file_bytes.extend(struct.pack(
                        "<IIQQQQIIQQ",
                        n_off, 1, 0, 0, f_off, f_sz, 0, 0, 1, 0
                    ))
                # Patch e_shoff (offset 40), e_shnum (offset 60), e_shstrndx (offset 62)
                struct.pack_into("<Q", file_bytes, 40, shoff)
                struct.pack_into("<HH", file_bytes, 60, shnum, 1)

        return bytes(file_bytes)

    # =========================================================================
    # 5. ARM64 (AARCH64) STANDALONE EXECUTABLES (LINUX & WINDOWS)
    # =========================================================================

    def build_arm64_elf(
        self,
        exit_code: int = 0,
        custom_code: Optional[bytes] = None,
        entry_offset: Optional[int] = None,
    ) -> bytes:
        vaddr = self.VADDR_ELF
        hdr_entry_offset = 120
        entry_addr = vaddr + hdr_entry_offset

        code = bytearray()
        if custom_code:
            # Call custom_code + (entry_offset or 0) via BL, then SVC #0 sys_exit(X0)!
            fn_off = int(entry_offset or 0)
            bl_words = 3 + (fn_off // 4)
            bl_fn = 0x94000000 | (bl_words & 0x03FFFFFF)
            mov_x8 = 0xD2800000 | (93 << 5) | 8
            svc_0 = 0xD4000001
            code.extend(struct.pack("<III", bl_fn, mov_x8, svc_0))
            code.extend(custom_code)
        else:
            mov_x0 = 0xD2800000 | ((exit_code & 0xFFFF) << 5) | 0
            mov_x8 = 0xD2800000 | (93 << 5) | 8
            svc_0 = 0xD4000001
            code.extend(struct.pack("<III", mov_x0, mov_x8, svc_0))

        total_size = hdr_entry_offset + len(code)
        elf_ident = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8)
        elf_header = struct.pack(
            "<16sHHIQQQIHHHHHH",
            elf_ident,
            2, 183, 1, entry_addr, 64, 0, 0,
            64, 56, 1, 64, 0, 0
        )
        prog_header = struct.pack("<IIQQQQQQ", 1, 7, 0, vaddr, vaddr, total_size, total_size, 0x1000)
        return elf_header + prog_header + bytes(code)

    def build_riscv64_elf(
        self,
        exit_code: int = 0,
        custom_code: Optional[bytes] = None,
        entry_offset: Optional[int] = None,
    ) -> bytes:
        """Emits a standalone Linux RISC-V 64 (`e_machine = 0xF3`) ELF64 executable."""
        vaddr = self.VADDR_ELF
        hdr_entry_offset = 64 + 56  # EHDR + 1 PHDR
        entry_addr = vaddr + hdr_entry_offset

        code = bytearray()
        if custom_code:
            # JAL ra, fn; LI a7, 93; ECALL (sys_exit with returned a0)
            fn_off = int(entry_offset or 0)
            jal_disp = 12 + fn_off
            imm = jal_disp & 0x1FFFFF
            jal_ra = (
                (((imm >> 20) & 1) << 31)
                | (((imm >> 1) & 0x3FF) << 21)
                | (((imm >> 11) & 1) << 20)
                | (((imm >> 12) & 0xFF) << 12)
                | (1 << 7)
                | 0x6F
            )
            addi_a7_93 = ((93 & 0xFFF) << 20) | (0 << 15) | (0 << 12) | (17 << 7) | 0x13
            ecall = 0x00000073
            code.extend(struct.pack("<III", jal_ra, addi_a7_93, ecall))
            code.extend(custom_code)
        else:
            addi_a0 = ((int(exit_code) & 0xFFF) << 20) | (0 << 15) | (0 << 12) | (10 << 7) | 0x13
            addi_a7_93 = ((93 & 0xFFF) << 20) | (0 << 15) | (0 << 12) | (17 << 7) | 0x13
            ecall = 0x00000073
            code.extend(struct.pack("<III", addi_a0, addi_a7_93, ecall))

        total_size = hdr_entry_offset + len(code)
        elf_ident = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8)
        elf_header = struct.pack(
            "<16sHHIQQQIHHHHHH",
            elf_ident,
            2, 0xF3, 1, entry_addr, 64, 0, 0x00000005,
            64, 56, 1, 64, 0, 0,
        )
        prog_header = struct.pack("<IIQQQQQQ", 1, 7, 0, vaddr, vaddr, total_size, total_size, 0x1000)
        return elf_header + prog_header + bytes(code)

    def build_arm64_pe(
        self,
        exit_code: int = 0,
        custom_code: Optional[bytes] = None,
        entry_offset: Optional[int] = None,
    ) -> bytes:
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
        entry_rva = 0x1000 + (int(entry_offset) if (custom_code and entry_offset is not None) else 0)

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
            entry_rva, 0x1000,
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

    @staticmethod
    def _encode_uleb128(value: int) -> bytes:
        out = bytearray()
        v = max(0, int(value))
        while True:
            byte = v & 0x7F
            v >>= 7
            if v:
                out.append(byte | 0x80)
            else:
                out.append(byte)
                break
        return bytes(out)

    @classmethod
    def _build_macho_dyld_bind_opcodes(cls, imported_symbols: List[str], data_seg_index: int = 2) -> bytes:
        """
        Builds dyld bind opcodes (`LC_DYLD_INFO_ONLY`) binding each imported symbol
        to consecutive 8-byte pointer slots in `__DATA,__got` via ordinal 1 (`libSystem.B.dylib`).
        """
        ops = bytearray()
        ops.append(0x11)  # BIND_OPCODE_SET_DYLIB_ORDINAL_IMM (ordinal=1)
        ops.append(0x70 | (data_seg_index & 0x0F))  # BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
        ops.extend(cls._encode_uleb128(0))
        ops.append(0x51)  # BIND_OPCODE_SET_TYPE_IMM (BIND_TYPE_POINTER = 1)
        for sym in imported_symbols:
            m_sym = sym if sym.startswith("_") else f"_{sym}"
            ops.append(0x40)  # BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM (flags=0)
            ops.extend(m_sym.encode("ascii") + b"\x00")
            ops.append(0x90)  # BIND_OPCODE_DO_BIND
        ops.append(0x00)  # BIND_OPCODE_DONE
        return bytes(ops)

    def build_macho64(
        self,
        exit_code: int = 0,
        custom_code: Optional[bytes] = None,
        arch: str = "x86_64",
        entry_offset: Optional[int] = None,
        load_dylibs: Optional[List[str]] = None,
        imported_symbols: Optional[List[str]] = None,
        exported_symbols: Optional[Dict[str, int]] = None,
        os_import_stubs: Optional[Dict[str, int]] = None,
    ) -> bytes:
        """
        Synthesizes a 64-bit Mach-O standalone executable (`MH_EXECUTE`) for macOS.
        Supports `LC_LOAD_DYLINKER` + `LC_LOAD_DYLIB` (`0x0C`) + `LC_SYMTAB` + `LC_DYSYMTAB` +
        `__DATA,__got` + `LC_DYLD_INFO_ONLY` (`0x80000022`) bind opcodes.
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

        ordered_imports = sorted(set(imported_symbols or (os_import_stubs.keys() if os_import_stubs else [])))
        need_got = bool(os_import_stubs and ordered_imports)
        data_vmaddr = 0x100000000 + text_vmsize
        data_fileoff = text_file_end
        got_raw_size = len(ordered_imports) * 8 if need_got else 0
        data_filesize = self._align_up(got_raw_size, page_size) if need_got else 0
        data_vmsize = data_filesize

        if need_got and os_import_stubs:
            got_vaddr_map = {sym: data_vmaddr + idx * 8 for idx, sym in enumerate(ordered_imports)}
            patched_raw = bytearray(raw_code)
            for sym, stub_off in os_import_stubs.items():
                if sym not in got_vaddr_map:
                    continue
                if is_arm64:
                    if stub_off + 12 <= len(patched_raw):
                        patched_raw[stub_off : stub_off + 12] = self._encode_a64_got_stub(
                            code_vaddr + stub_off,
                            got_vaddr_map[sym],
                        )
                else:
                    if stub_off + 6 <= len(patched_raw):
                        stub_rip = code_vaddr + stub_off + 6
                        disp = got_vaddr_map[sym] - stub_rip
                        patched_raw[stub_off : stub_off + 6] = b"\xff\x25" + struct.pack("<i", disp)
            raw_code = bytes(patched_raw)
            padded_code = raw_code.ljust(self._align_up(max(1, len(raw_code)), 16), b"\x00")

        dylib_cmds: List[bytes] = []
        if load_dylibs:
            dyld_raw = b"/usr/lib/dyld\x00"
            dyld_cmd_sz = self._align_up(12 + len(dyld_raw), 8)
            dylib_cmds.append(struct.pack("<III", 0x0E, dyld_cmd_sz, 12) + dyld_raw.ljust(dyld_cmd_sz - 12, b"\x00"))
            for dpath in load_dylibs:
                d_raw = dpath.encode("utf-8") + b"\x00"
                d_sz = self._align_up(24 + len(d_raw), 8)
                dylib_cmds.append(struct.pack("<IIIIII", 0x0C, d_sz, 24, 2, 0x010000, 0x010000) + d_raw.ljust(d_sz - 24, b"\x00"))

        need_symtab = bool(ordered_imports or exported_symbols)
        need_dysymtab = bool(ordered_imports)
        need_dyld_info = bool(need_got and load_dylibs)
        need_linkedit = is_arm64 or need_symtab or need_dyld_info

        linkedit_fileoff = text_file_end + data_filesize
        bind_opcodes = self._build_macho_dyld_bind_opcodes(ordered_imports, data_seg_index=2) if need_dyld_info else b""
        bind_pad = bind_opcodes.ljust(self._align_up(len(bind_opcodes), 8), b"\x00") if bind_opcodes else b""
        bind_off = linkedit_fileoff if bind_pad else 0

        symtab_bytes = bytearray()
        strtab_bytes = bytearray(b"\x00")
        n_ext_def = 0
        n_undef = 0
        defined_names = set()
        if exported_symbols:
            for sym, sym_off in sorted(exported_symbols.items(), key=lambda kv: kv[0]):
                m_sym = sym if sym.startswith("_") else f"_{sym}"
                defined_names.add(sym)
                defined_names.add(m_sym)
                s_off = len(strtab_bytes)
                strtab_bytes.extend(m_sym.encode("utf-8") + b"\x00")
                symtab_bytes.extend(struct.pack("<IBBHQ", s_off, 0x0F, 1, 0, code_vaddr + int(sym_off)))  # N_EXT | N_SECT
                n_ext_def += 1
        if ordered_imports:
            for sym in ordered_imports:
                if sym in defined_names:
                    continue
                m_sym = sym if sym.startswith("_") else f"_{sym}"
                s_off = len(strtab_bytes)
                strtab_bytes.extend(m_sym.encode("ascii") + b"\x00")
                symtab_bytes.extend(struct.pack("<IBBHQ", s_off, 0x01, 0, 0, 0))  # N_EXT | N_UNDF
                n_undef += 1
        nsyms = n_ext_def + n_undef
        symtab_pad = bytes(symtab_bytes)
        strtab_pad = bytes(strtab_bytes).ljust(self._align_up(len(strtab_bytes), 8), b"\x00")
        linkedit_data = (bind_pad + symtab_pad + strtab_pad) if (need_symtab or need_dyld_info) else b""
        if is_arm64 and linkedit_data:
            rem16 = (-len(linkedit_data)) & 15
            linkedit_data += b"\x00" * rem16

        symoff = linkedit_fileoff + len(bind_pad)
        stroff = symoff + len(symtab_pad)

        cmd1_size = 72        # __PAGEZERO
        cmd2_size = 72 + 80   # __TEXT + __text
        cmd_data_size = (72 + 80) if need_got else 0
        cmd3_size = 24        # LC_MAIN
        cmd_linkedit_size = 72 if need_linkedit else 0
        cmd_dyld_info_size = 48 if need_dyld_info else 0
        cmd_symtab_size = 24 if need_symtab else 0
        cmd_dysymtab_size = 80 if need_dysymtab else 0
        cmd_codesig_size = 16 if is_arm64 else 0

        ncmds = (
            3
            + (1 if need_got else 0)
            + len(dylib_cmds)
            + (1 if need_linkedit else 0)
            + (1 if need_dyld_info else 0)
            + (1 if need_symtab else 0)
            + (1 if need_dysymtab else 0)
            + (1 if is_arm64 else 0)
        )
        sizeofcmds = (
            cmd1_size + cmd2_size + cmd_data_size + cmd3_size
            + sum(len(c) for c in dylib_cmds)
            + cmd_linkedit_size + cmd_dyld_info_size + cmd_symtab_size + cmd_dysymtab_size + cmd_codesig_size
        )

        # Pre-calculate codesign size for __LINKEDIT if ARM64
        page_shift = 14 if is_arm64 else 12
        codesig_off = linkedit_fileoff + len(linkedit_data)
        dummy_unsigned = b"\x00" * codesig_off
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

        cmd_data_bytes = b""
        if need_got:
            cmd_data = struct.pack(
                "<II16sQQQQIIII",
                0x19, cmd_data_size, b"__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                data_vmaddr, data_vmsize, data_fileoff, data_filesize, 3, 3, 1, 0
            )
            sec_got = struct.pack(
                "<16s16sQQIIIIIIII",
                b"__got\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                b"__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                data_vmaddr, got_raw_size, data_fileoff, 3, 0, 0, 0x06, 0, 0, 0  # S_NON_LAZY_SYMBOL_POINTERS
            )
            cmd_data_bytes = cmd_data + sec_got

        actual_entry = code_offset + (entry_offset if entry_offset is not None else 0)
        cmd_main = struct.pack("<IIQQ", 0x80000028, cmd3_size, actual_entry, 0)

        extra_cmds = bytearray()
        for dc in dylib_cmds:
            extra_cmds.extend(dc)
        if need_linkedit:
            linkedit_vmaddr = 0x100000000 + text_vmsize + data_vmsize
            linkedit_fsize = len(linkedit_data) + len(est_sig)
            linkedit_vmsize = self._align_up(max(1, linkedit_fsize), page_size)
            extra_cmds.extend(struct.pack(
                "<II16sQQQQIIII",
                0x19, 72, b"__LINKEDIT\x00\x00\x00\x00\x00\x00",
                linkedit_vmaddr, linkedit_vmsize,
                linkedit_fileoff, linkedit_fsize,
                1, 1, 0, 0
            ))
        if need_dyld_info:
            extra_cmds.extend(struct.pack(
                "<IIIIIIIIIIII",
                0x80000022, 48,  # LC_DYLD_INFO_ONLY
                0, 0,            # rebase_off, rebase_size
                bind_off, len(bind_opcodes),
                0, 0,            # weak_bind_off, weak_bind_size
                0, 0,            # lazy_bind_off, lazy_bind_size
                0, 0,            # export_off, export_size
            ))
        if need_symtab:
            extra_cmds.extend(struct.pack("<IIIIII", 0x02, 24, symoff, nsyms, stroff, len(strtab_pad)))
        if need_dysymtab:
            extra_cmds.extend(struct.pack("<20I", 0x0B, 80, 0, 0, 0, n_ext_def, n_ext_def, n_undef, *([0] * 12)))
        if is_arm64:
            extra_cmds.extend(struct.pack("<IIII", 0x1D, 16, codesig_off, len(est_sig)))

        all_headers = (header + cmd_pagezero + cmd_text + sec_text + cmd_data_bytes + cmd_main + bytes(extra_cmds)).ljust(code_offset, b"\x00")
        text_section_img = (all_headers + padded_code).ljust(text_file_end, b"\x00")
        data_section_img = b"\x00" * data_filesize
        unsigned_img = text_section_img + data_section_img + linkedit_data

        if is_arm64:
            real_sig = build_macho_adhoc_codesign_blob(unsigned_img, page_shift=page_shift)
            return unsigned_img + real_sig
        if need_symtab or need_dyld_info:
            return unsigned_img
        return unsigned_img[:code_offset + len(raw_code)]

    @staticmethod
    def _uleb128(val: int) -> bytes:
        out = bytearray()
        while True:
            byte = val & 0x7F
            val >>= 7
            if val != 0:
                out.append(byte | 0x80)
            else:
                out.append(byte)
                break
        return bytes(out)

    @classmethod
    def _build_macho_export_trie(cls, exports_list: List[Tuple[str, int]], code_vaddr: int) -> bytes:
        """Builds a canonical Mach-O ULEB128 export trie for dyld4 dlsym resolution."""
        # Prefix tree nodes: [edges_dict, terminal_offset_or_None]
        root: List[Any] = [{}, None]
        for sym_name, sym_off in exports_list:
            mname = sym_name if sym_name.startswith("_") else f"_{sym_name}"
            node = root
            # Group full edge per symbol under unique suffix if not sharing prefix
            cur_edges = node[0]
            if mname not in cur_edges:
                cur_edges[mname] = [{}, code_vaddr + int(sym_off)]

        # Order nodes: root + sorted children
        nodes: List[List[Any]] = [root]
        child_order: List[Tuple[str, int]] = []
        for edge_str in sorted(root[0].keys()):
            child_idx = len(nodes)
            nodes.append(root[0][edge_str])
            child_order.append((edge_str, child_idx))

        offsets = [0] * len(nodes)
        for _ in range(4):
            cur_off = 0
            serialized_nodes: List[bytes] = []
            for idx_n, nd in enumerate(nodes):
                offsets[idx_n] = cur_off
                term = nd[1]
                buf = bytearray()
                if term is not None:
                    term_info = cls._uleb128(0) + cls._uleb128(term)
                    buf.extend(cls._uleb128(len(term_info)))
                    buf.extend(term_info)
                else:
                    buf.append(0)
                if idx_n == 0:
                    buf.append(len(child_order))
                    for edge_s, c_idx in child_order:
                        buf.extend(edge_s.encode("utf-8") + b"\x00")
                        buf.extend(cls._uleb128(offsets[c_idx]))
                else:
                    buf.append(0)
                serialized_nodes.append(bytes(buf))
                cur_off += len(buf)
        return b"".join(serialized_nodes)

    def build_macho64_dylib(
        self,
        func_code: bytes,
        export_name: str = "omni_compute",
        arch: str = "x86_64",
        dylib_name: Optional[str] = None,
        extra_exports: Optional[Dict[str, int]] = None,
        load_dylibs: Optional[List[str]] = None,
        imported_symbols: Optional[List[str]] = None,
        os_import_stubs: Optional[Dict[str, int]] = None,
        data_bytes: Optional[bytes] = None,
        bss_size: int = 0,
        abs64_reloc_rvas: Optional[List[int]] = None,
        init_array_offset_in_data: int = 0,
        init_array_size: int = 0,
        fini_array_offset_in_data: int = 0,
        fini_array_size: int = 0,
        tdata_bytes: Optional[bytes] = None,
        tbss_size: int = 0,
        eh_frame_offset_in_code: int = 0,
        eh_frame_size: int = 0,
    ) -> bytes:
        """
        Synthesizes a 64-bit Mach-O dynamic shared library (`MH_DYLIB`) with:
          - `LC_DYLD_INFO_ONLY` ULEB128 export trie + GOT bind opcodes + rebase opcodes (`dyld4` compatible)
          - Optional `__DATA.__got`, `__DATA.__data` (RW globals), `__DATA.__bss` (`S_ZEROFILL`)
          - `LC_LOAD_DYLIB` (`/usr/lib/libSystem.B.dylib`)
          - `LC_SYMTAB (0x02)` + `LC_DYSYMTAB (0x0B)` multi-symbol `nlist_64` export & import table
          - `LC_BUILD_VERSION (0x32)` (`PLATFORM_MACOS`)
          - `__LINKEDIT` segment + XNU Ad-Hoc `LC_CODE_SIGNATURE (0x1D)` on `arm64`.
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

        ordered_imports = sorted(set(imported_symbols or (os_import_stubs.keys() if os_import_stubs else [])))
        need_got = bool(os_import_stubs and ordered_imports)
        eff_dylibs = list(load_dylibs or (["/usr/lib/libSystem.B.dylib"] if need_got else []))

        raw_code = func_code
        padded_code = raw_code.ljust(self._align_up(max(1, len(raw_code)), 16), b"\x00")
        text_file_end = self._align_up(code_offset + len(padded_code), page_size)
        text_vmsize = text_file_end

        data_vmaddr = text_vmsize
        data_fileoff = text_file_end
        got_raw_size = self._align_up(len(ordered_imports) * 8, 16) if need_got else 0
        raw_rw_data = bytes(data_bytes or b"")
        rw_bss_size = max(0, int(bss_size))
        has_data_seg = bool(need_got or raw_rw_data or rw_bss_size > 0)
        rw_file_bytes = got_raw_size + len(raw_rw_data)
        data_filesize = self._align_up(rw_file_bytes, page_size) if rw_file_bytes > 0 else 0
        data_vmsize = self._align_up(rw_file_bytes + rw_bss_size, page_size) if has_data_seg else 0

        if need_got and os_import_stubs:
            got_vaddr_map = {sym: data_vmaddr + idx * 8 for idx, sym in enumerate(ordered_imports)}
            patched_raw = bytearray(raw_code)
            for sym, stub_off in os_import_stubs.items():
                if sym not in got_vaddr_map:
                    continue
                if is_arm64:
                    if stub_off + 12 <= len(patched_raw):
                        patched_raw[stub_off:stub_off + 12] = self._encode_a64_got_stub(
                            code_vaddr + stub_off, got_vaddr_map[sym]
                        )
                else:
                    if stub_off + 6 <= len(patched_raw):
                        stub_rip = code_vaddr + stub_off + 6
                        disp = got_vaddr_map[sym] - stub_rip
                        patched_raw[stub_off:stub_off + 6] = b"\xff\x25" + struct.pack("<i", disp)
            raw_code = bytes(patched_raw)
            padded_code = raw_code.ljust(self._align_up(max(1, len(raw_code)), 16), b"\x00")

        # Build Mach-O nlist_64 symbol table + string table + export trie + rebase/bind opcodes
        strtab = bytearray(b"\x00")
        symtab = bytearray()
        for sym_name, sym_off in sorted_exports:
            macho_sym = sym_name if sym_name.startswith("_") else f"_{sym_name}"
            n_strx = len(strtab)
            strtab.extend(macho_sym.encode("utf-8") + b"\x00")
            symtab.extend(struct.pack("<IBBHQ", n_strx, 0x0F, 1, 0, code_vaddr + int(sym_off)))
        for imp_sym in ordered_imports:
            m_imp = imp_sym if imp_sym.startswith("_") else f"_{imp_sym}"
            n_strx = len(strtab)
            strtab.extend(m_imp.encode("utf-8") + b"\x00")
            # N_EXT | N_UNDF = 0x01; GET_LIBRARY_ORDINAL = 1 in n_desc (high byte 1 -> 0x0100)
            symtab.extend(struct.pack("<IBBHQ", n_strx, 0x01, 0, 0x0100, 0))

        strtab_padded = bytes(strtab).ljust(self._align_up(len(strtab), 8), b"\x00")
        raw_trie = self._build_macho_export_trie(sorted_exports, code_vaddr)
        trie_padded = raw_trie.ljust(self._align_up(len(raw_trie), 8), b"\x00")

        rebase_buf = bytearray()
        if abs64_reloc_rvas and has_data_seg:
            rebase_buf.append(0x11)  # REBASE_OPCODE_SET_TYPE_IMM (1 = POINTER)
            for rr in sorted(set(int(r) for r in abs64_reloc_rvas)):
                if rr >= data_vmaddr:
                    seg_off = rr - data_vmaddr
                    rebase_buf.append(0x21)  # REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB (seg 1 = __DATA)
                    rebase_buf.extend(self._uleb128(seg_off))
                    rebase_buf.append(0x51)  # REBASE_OPCODE_DO_REBASE_IMM_TIMES (1)
            rebase_buf.append(0x00)  # REBASE_OPCODE_DONE
        rebase_pad = bytes(rebase_buf).ljust(self._align_up(len(rebase_buf), 8), b"\x00") if rebase_buf else b""

        bind_opcodes = self._build_macho_dyld_bind_opcodes(ordered_imports, data_seg_index=1) if need_got else b""
        bind_pad = bind_opcodes.ljust(self._align_up(len(bind_opcodes), 8), b"\x00") if bind_opcodes else b""

        linkedit_fileoff = text_file_end + data_filesize
        rebase_off = linkedit_fileoff if rebase_pad else 0
        bind_off = (linkedit_fileoff + len(rebase_pad)) if bind_pad else 0
        symoff = linkedit_fileoff + len(rebase_pad) + len(bind_pad)
        stroff = symoff + len(symtab)
        trie_off = stroff + len(strtab_padded)
        after_syms_off = self._align_up(trie_off + len(trie_padded), 16)

        install_name = (dylib_name or f"lib{export_name}.dylib").encode("utf-8") + b"\x00"
        padded_name = install_name.ljust(self._align_up(len(install_name), 8), b"\x00")
        cmd_id_size = 24 + len(padded_name)

        dylib_cmds: List[bytes] = []
        for dpath in eff_dylibs:
            d_raw = dpath.encode("utf-8") + b"\x00"
            d_sz = self._align_up(24 + len(d_raw), 8)
            dylib_cmds.append(struct.pack("<IIIIII", 0x0C, d_sz, 24, 2, 0x010000, 0x010000) + d_raw.ljust(d_sz - 24, b"\x00"))

        has_macho_eh = (
            eh_frame_size > 0
            and eh_frame_offset_in_code > 0
            and eh_frame_offset_in_code + eh_frame_size <= len(raw_code)
        )
        n_data_sects = (1 if need_got else 0) + (1 if raw_rw_data else 0) + (1 if rw_bss_size > 0 else 0)
        cmd_text_size = 72 + 80 * (2 if has_macho_eh else 1)
        cmd_data_size = (72 + 80 * n_data_sects) if has_data_seg else 0
        cmd_linkedit_size = 72
        cmd_dyld_info_size = 48
        cmd_symtab_size = 24
        cmd_dysymtab_size = 80
        cmd_buildver_size = 24
        cmd_codesig_size = 16 if is_arm64 else 0

        ncmds = (7 + (1 if has_data_seg else 0) + len(dylib_cmds) + (1 if is_arm64 else 0))
        sizeofcmds = (
            cmd_text_size + cmd_data_size + cmd_linkedit_size + cmd_id_size + sum(len(c) for c in dylib_cmds)
            + cmd_dyld_info_size + cmd_symtab_size + cmd_dysymtab_size + cmd_buildver_size + cmd_codesig_size
        )

        est_sig = build_macho_adhoc_codesign_blob(b"\x00" * after_syms_off, page_shift=page_shift) if is_arm64 else b""
        linkedit_filesize = (after_syms_off - linkedit_fileoff) + len(est_sig)
        linkedit_vmsize = self._align_up(max(1, linkedit_filesize), page_size)

        header = struct.pack(
            "<IIIIIIII",
            0xFEEDFACF, cpu_type, cpu_subtype,
            0x6, ncmds, sizeofcmds, 0x00100085, 0
        )

        cmd_text = struct.pack(
            "<II16sQQQQIIII",
            0x19, cmd_text_size, b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            0, text_vmsize, 0, text_file_end, 5, 5, 2 if has_macho_eh else 1, 0
        )
        sec_text_len = eh_frame_offset_in_code if has_macho_eh else len(raw_code)
        sec_text = struct.pack(
            "<16s16sQQIIIIIIII",
            b"__text\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            code_vaddr, sec_text_len, code_offset, 2, 0, 0, 0x80000400, 0, 0, 0
        )
        if has_macho_eh:
            sec_text += struct.pack(
                "<16s16sQQIIIIIIII",
                b"__eh_frame\x00\x00\x00\x00\x00\x00",
                b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                code_vaddr + eh_frame_offset_in_code,
                eh_frame_size,
                code_offset + eh_frame_offset_in_code,
                3, 0, 0, 0x6800000B, 0, 0, 0
            )
        cmd_data_bytes = b""
        if has_data_seg:
            cmd_data_bytes = struct.pack(
                "<II16sQQQQIIII",
                0x19, cmd_data_size, b"__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                data_vmaddr, data_vmsize, data_fileoff, data_filesize, 3, 3, n_data_sects, 0,
            )
            if need_got:
                cmd_data_bytes += struct.pack(
                    "<16s16sQQIIIIIIII",
                    b"__got\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                    b"__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                    data_vmaddr, len(ordered_imports) * 8, data_fileoff, 3, 0, 0, 0x06, 0, 0, 0,
                )
            if raw_rw_data:
                cmd_data_bytes += struct.pack(
                    "<16s16sQQIIIIIIII",
                    b"__data\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                    b"__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                    data_vmaddr + got_raw_size, len(raw_rw_data), data_fileoff + got_raw_size, 4, 0, 0, 0x00, 0, 0, 0,
                )
            if rw_bss_size > 0:
                cmd_data_bytes += struct.pack(
                    "<16s16sQQIIIIIIII",
                    b"__bss\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                    b"__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                    data_vmaddr + got_raw_size + len(raw_rw_data), rw_bss_size, 0, 4, 0, 0, 0x01, 0, 0, 0,
                )
        cmd_linkedit = struct.pack(
            "<II16sQQQQIIII",
            0x19, cmd_linkedit_size, b"__LINKEDIT\x00\x00\x00\x00\x00\x00",
            text_vmsize + data_vmsize, linkedit_vmsize,
            linkedit_fileoff, linkedit_filesize,
            1, 1, 0, 0
        )
        cmd_id = struct.pack("<IIIIII", 0x0D, cmd_id_size, 24, 2, 0x00010000, 0x00010000) + padded_name
        cmd_dyld_info = struct.pack(
            "<IIIIIIIIIIII",
            0x80000022, cmd_dyld_info_size,
            rebase_off, len(rebase_buf),
            bind_off, len(bind_opcodes),
            0, 0,
            0, 0,
            trie_off, len(raw_trie),
        )
        total_syms = len(sorted_exports) + len(ordered_imports)
        cmd_symtab = struct.pack("<IIIIII", 0x02, cmd_symtab_size, symoff, total_syms, stroff, len(strtab_padded))
        cmd_dysymtab = struct.pack(
            "<20I",
            0x0B, cmd_dysymtab_size,
            0, 0, 0, len(sorted_exports), len(sorted_exports), len(ordered_imports),
            *([0] * 12)
        )
        cmd_buildver = struct.pack("<IIIIII", 0x32, cmd_buildver_size, 1, 0x000B0000, 0x000B0000, 0)
        extra_cmds = struct.pack("<IIII", 0x1D, 16, after_syms_off, len(est_sig)) if is_arm64 else b""

        all_headers = (
            header + cmd_text + sec_text + cmd_data_bytes + cmd_linkedit + cmd_id
            + b"".join(dylib_cmds)
            + cmd_dyld_info + cmd_symtab + cmd_dysymtab + cmd_buildver + extra_cmds
        ).ljust(code_offset, b"\x00")
        text_img = (all_headers + padded_code).ljust(text_file_end, b"\x00")
        data_img = ((b"\x00" * got_raw_size) + raw_rw_data).ljust(data_filesize, b"\x00") if data_filesize else b""
        unsigned_dylib = (text_img + data_img + rebase_pad + bind_pad + bytes(symtab) + strtab_padded + trie_padded).ljust(after_syms_off, b"\x00")

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
        entry_offset: Optional[int] = None,
        exported_symbols: Optional[Dict[str, int]] = None,
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
            data = self.build_arm64_elf(exit_code=exit_code, custom_code=custom_code, entry_offset=entry_offset)
        elif target_format in ("riscv64_elf", "riscv_elf"):
            data = self.build_riscv64_elf(exit_code=exit_code, custom_code=custom_code, entry_offset=entry_offset)
        elif target_format in ("spirv", "spv"):
            if not output_path.endswith(".spv"):
                output_path += ".spv"
            if custom_code:
                data = custom_code
            else:
                from compiler.ssa_ir import BasicBlock, SSAFunction, SSAInstruction, SSAVar
                from compiler.spirv_emitter import SPIRVEmitter
                fn = SSAFunction("spv_exit", [])
                blk = BasicBlock("entry")
                rv = SSAVar("r", 1)
                blk.add_instruction(SSAInstruction(rv, "const", [exit_code]))
                blk.add_instruction(SSAInstruction(None, "ret", [rv]))
                fn.blocks = [blk]
                fn.entry_block = blk
                data = SPIRVEmitter().emit_spirv_binary(fn)
        elif target_format == "arm64_pe":
            if not output_path.endswith(".exe"):
                output_path += ".exe"
            data = self.build_arm64_pe(exit_code=exit_code, custom_code=custom_code, entry_offset=entry_offset)
        elif target_format in ("macho64", "macho_x86_64"):
            data = self.build_macho64(
                exit_code=exit_code,
                custom_code=custom_code,
                arch="x86_64",
                entry_offset=entry_offset,
                exported_symbols=exported_symbols,
            )
        elif target_format in ("arm64_macho", "macho_arm64"):
            data = self.build_macho64(
                exit_code=exit_code,
                custom_code=custom_code,
                arch="arm64",
                entry_offset=entry_offset,
                load_dylibs=["/usr/lib/libSystem.B.dylib"],
                exported_symbols=exported_symbols,
            )
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

    def compute_pe_pdata_rva(
        self,
        output_path: str = "",
        func_code: bytes = b"",
        export_name: str = "omni_compute",
        extra_exports: Optional[Dict[str, int]] = None,
        os_import_stubs: Optional[Dict[str, int]] = None,
        os_import_table: Optional[Dict[str, Tuple[str, str]]] = None,
        has_init_array: bool = False,
        lib_name: str = "omni_linked",
    ) -> int:
        """Returns the exact RVA of the `.pdata` section inside a PE32+ DLL."""
        eff_out = output_path or lib_name
        if not eff_out.endswith(".dll"):
            eff_out += ".dll"
        dll_name = os.path.basename(eff_out)
        text_prefix_len = 64 if has_init_array else 16
        aligned_text_len = self._align_up(max(1, text_prefix_len + len(func_code)), self.FILE_ALIGN)
        text_vspan = self._align_up(aligned_text_len, self.SEC_ALIGN)

        exports_map: Dict[str, int] = dict(extra_exports) if extra_exports else {}
        if export_name and export_name not in exports_map:
            exports_map[export_name] = 0
        if not exports_map:
            exports_map["omni_compute"] = 0
        sorted_exports = sorted(exports_map.items(), key=lambda kv: kv[0].encode("ascii"))
        num_syms = len(sorted_exports)
        ot_bytes_len = 2 * num_syms
        pad_after_ot = (4 - (ot_bytes_len % 4)) % 4
        strings_start = 40 + 4 * num_syms + 4 * num_syms + ot_bytes_len + pad_after_ot
        str_blob_len = len(dll_name.encode("ascii") + b"\x00") + sum(
            len(s.encode("ascii") + b"\x00") for s, _ in sorted_exports
        )
        raw_edata_len = strings_start + str_blob_len
        edata_vspan = self._align_up(self._align_up(max(1, raw_edata_len), self.FILE_ALIGN), self.SEC_ALIGN)

        os_stubs = os_import_stubs or {}
        imp_tbl = os_import_table or {}
        imports_by_dll: Dict[str, List[str]] = {}
        for sym in sorted(os_stubs.keys()):
            win_dll = imp_tbl[sym][0] if sym in imp_tbl else "MSVCRT.dll"
            imports_by_dll.setdefault(win_dll, []).append(sym)
        dll_items = [(d, list(s)) for d, s in imports_by_dll.items() if s]
        idata_vspan = 0
        if dll_items:
            cur = (len(dll_items) + 1) * 20
            for _, syms in dll_items:
                cur += (len(syms) + 1) * 8
            for _, syms in dll_items:
                cur += (len(syms) + 1) * 8
            imp_str_len = 0
            for dll, syms in dll_items:
                enc_d = dll.encode("ascii") + b"\x00"
                imp_str_len += len(enc_d) + (len(enc_d) % 2)
                for sym in syms:
                    enc_s = b"\x00\x00" + sym.encode("ascii") + b"\x00"
                    imp_str_len += len(enc_s) + (len(enc_s) % 2)
            raw_idata_len = cur + imp_str_len
            idata_vspan = self._align_up(self._align_up(max(1, raw_idata_len), self.FILE_ALIGN), self.SEC_ALIGN)

        return 0x1000 + text_vspan + edata_vspan + idata_vspan

    def compute_shared_lib_layout(
        self,
        func_code: bytes = b"",
        export_name: str = "omni_compute",
        target_format: str = "auto",
        extra_exports: Optional[Dict[str, int]] = None,
        pdata_xdata: Optional[Tuple[bytes, bytes]] = None,
        dwarf_sections: Optional[Dict[str, bytes]] = None,
        os_import_stubs: Optional[Dict[str, int]] = None,
        os_import_table: Optional[Dict[str, Tuple[str, str]]] = None,
        output_path: str = "",
        data_bytes: Optional[bytes] = None,
        bss_size: int = 0,
        abs64_reloc_rvas: Optional[List[int]] = None,
        func_code_len: Optional[int] = None,
        lib_name: str = "omni_linked",
        num_abs64_relocs: Optional[int] = None,
        has_init_array: bool = False,
        has_fini_array: bool = False,
        eh_frame_offset_in_code: int = 0,
        eh_frame_size: int = 0,
        external_dyn_relocs: Optional[List[Tuple[int, str, int, int]]] = None,
    ) -> Tuple[int, int, int]:
        """
        Deterministically computes `(image_base, text_va, data_va)` for two-pass
        cross-section `.text`/`.rodata`/`.data`/`.bss` relocation binding before emitting
        the final shared library image.
        """
        if target_format == "auto":
            target_format = "pe_dll" if sys.platform == "win32" else "elf_so"

        eff_code_len = len(func_code) if func_code_len is None else int(func_code_len)
        eff_abs64_count = (
            len(set(int(r) for r in abs64_reloc_rvas))
            if (num_abs64_relocs is None and abs64_reloc_rvas is not None)
            else int(num_abs64_relocs or 0)
        )
        os_stubs = os_import_stubs or {}
        imp_tbl = os_import_table or {}
        exports_map: Dict[str, int] = dict(extra_exports) if extra_exports else {}
        if export_name and export_name not in exports_map:
            exports_map[export_name] = 0
        if not exports_map:
            exports_map["omni_compute"] = 0
        sorted_exports = sorted(exports_map.items(), key=lambda kv: kv[0])

        if target_format == "pe_dll":
            eff_out = output_path or lib_name
            if not eff_out.endswith(".dll"):
                eff_out += ".dll"
            dll_name = os.path.basename(eff_out)
            text_prefix_len = 64 if has_init_array else 16
            aligned_text_len = self._align_up(max(1, text_prefix_len + eff_code_len), self.FILE_ALIGN)
            text_vspan = self._align_up(aligned_text_len, self.SEC_ALIGN)

            num_syms = len(sorted_exports)
            ot_bytes_len = 2 * num_syms
            pad_after_ot = (4 - (ot_bytes_len % 4)) % 4
            strings_start = 40 + 4 * num_syms + 4 * num_syms + ot_bytes_len + pad_after_ot
            str_blob_len = len(dll_name.encode("ascii") + b"\x00") + sum(
                len(s.encode("ascii") + b"\x00") for s, _ in sorted_exports
            )
            raw_edata_len = strings_start + str_blob_len
            edata_vspan = self._align_up(self._align_up(max(1, raw_edata_len), self.FILE_ALIGN), self.SEC_ALIGN)

            imports_by_dll: Dict[str, List[str]] = {}
            for sym in sorted(os_stubs.keys()):
                win_dll = imp_tbl[sym][0] if sym in imp_tbl else "MSVCRT.dll"
                imports_by_dll.setdefault(win_dll, []).append(sym)
            dll_items = [(d, list(s)) for d, s in imports_by_dll.items() if s]
            idata_vspan = 0
            if dll_items:
                cur = (len(dll_items) + 1) * 20
                for _, syms in dll_items:
                    cur += (len(syms) + 1) * 8
                for _, syms in dll_items:
                    cur += (len(syms) + 1) * 8
                imp_str_len = 0
                for dll, syms in dll_items:
                    enc_d = dll.encode("ascii") + b"\x00"
                    imp_str_len += len(enc_d) + (len(enc_d) % 2)
                    for sym in syms:
                        enc_s = b"\x00\x00" + sym.encode("ascii") + b"\x00"
                        imp_str_len += len(enc_s) + (len(enc_s) % 2)
                raw_idata_len = cur + imp_str_len
                idata_vspan = self._align_up(self._align_up(max(1, raw_idata_len), self.FILE_ALIGN), self.SEC_ALIGN)

            pdata_vspan = 0
            if pdata_xdata is not None:
                pdata_raw, xdata_raw = pdata_xdata
                xdata_off_in_sec = self._align_up(len(pdata_raw), 8)
                combined_len = xdata_off_in_sec + len(xdata_raw)
                pdata_vspan = self._align_up(self._align_up(max(1, combined_len), self.FILE_ALIGN), self.SEC_ALIGN)

            rva_data = 0x1000 + text_vspan + edata_vspan + idata_vspan + pdata_vspan
            return self.IMAGE_BASE_DLL, 0x1000 + text_prefix_len, rva_data

        if target_format in ("elf_so", "arm64_elf_so"):
            needed_libs: List[str] = []
            plt_imports = sorted(os_stubs.keys())
            ext_relocs = list(external_dyn_relocs or [])
            dynsym_imports = sorted(set(plt_imports) | {sym for _, sym, _, _ in ext_relocs})
            for sym in dynsym_imports:
                so_name = imp_tbl[sym][1] if sym in imp_tbl else "libc.so.6"
                if so_name not in needed_libs:
                    needed_libs.append(so_name)
            dynstr_len = 1 + sum(len(lb.encode("ascii")) + 1 for lb in needed_libs)
            dynstr_len += sum(len(s.encode("ascii")) + 1 for s, _ in sorted_exports)
            dynstr_len += sum(len(s.encode("ascii")) + 1 for s in dynsym_imports)
            dynsym_len = (1 + len(sorted_exports) + len(dynsym_imports)) * 24
            nbucket = max(1, len(sorted_exports))
            nchain = 1 + len(sorted_exports) + len(dynsym_imports)
            hash_len = (2 + nbucket + nchain) * 4

            dynstr_offset = 0x200 + eff_code_len
            dynsym_offset = self._align_up(dynstr_offset + dynstr_len, 8)
            hash_offset = self._align_up(dynsym_offset + dynsym_len, 8)
            got_plt_offset = self._align_up(hash_offset + hash_len, 8)
            got_plt_len = (3 + len(plt_imports)) * 8 if plt_imports else 0
            rela_plt_offset = self._align_up(got_plt_offset + got_plt_len, 8)
            rela_plt_len = len(plt_imports) * 24
            rela_dyn_offset = self._align_up(rela_plt_offset + rela_plt_len, 8)
            rela_dyn_len = (max(0, eff_abs64_count) + len(ext_relocs)) * 24
            dynamic_offset = self._align_up(rela_dyn_offset + rela_dyn_len, 8)
            n_dyn_tags = (
                len(needed_libs)
                + 5
                + (5 if plt_imports else 0)
                + (3 if rela_dyn_len > 0 else 0)
                + (2 if has_init_array else 0)
                + (2 if has_fini_array else 0)
                + 1
            )
            eh_hdr_len = (
                len(self._build_elf_eh_frame_hdr(func_code, self.VADDR_SO + 0x200, eh_frame_offset_in_code, eh_frame_size, 0))
                if eh_frame_size > 0
                else 0
            )
            ro_total_size = dynamic_offset + n_dyn_tags * 16 + eh_hdr_len
            rw_vaddr = self._align_up(ro_total_size, 0x1000)
            return self.VADDR_SO, self.VADDR_SO + 0x200, self.VADDR_SO + rw_vaddr

        if target_format in ("macho_dylib", "dylib", "arm64_macho_dylib", "macho_arm64_dylib"):
            is_arm64 = "arm64" in target_format
            page_size = 0x4000 if is_arm64 else 0x1000
            ordered_imports = sorted(set(os_stubs.keys()))
            need_got = bool(os_stubs and ordered_imports)
            padded_code_len = self._align_up(max(1, eff_code_len), 16)
            text_file_end = self._align_up(page_size + padded_code_len, page_size)
            got_raw_size = self._align_up(len(ordered_imports) * 8, 16) if need_got else 0
            return 0, page_size, text_file_end + got_raw_size

        raise ValueError(f"Unsupported shared library target: {target_format}")

    def emit_shared_library(
        self,
        output_path: str,
        func_code: bytes,
        export_name: str = "omni_compute",
        target_format: str = "auto",
        extra_exports: Optional[Dict[str, int]] = None,
        pdata_xdata: Optional[Tuple[bytes, bytes]] = None,
        dwarf_sections: Optional[Dict[str, bytes]] = None,
        os_import_stubs: Optional[Dict[str, int]] = None,
        os_import_table: Optional[Dict[str, Tuple[str, str]]] = None,
        data_bytes: Optional[bytes] = None,
        bss_size: int = 0,
        abs64_reloc_rvas: Optional[List[int]] = None,
        init_array_offset_in_data: int = 0,
        init_array_size: int = 0,
        fini_array_offset_in_data: int = 0,
        fini_array_size: int = 0,
        tdata_bytes: Optional[bytes] = None,
        tbss_size: int = 0,
        eh_frame_offset_in_code: int = 0,
        eh_frame_size: int = 0,
        external_dyn_relocs: Optional[List[Tuple[int, str, int, int]]] = None,
        pdata_prelinked: bool = False,
        emit_pdb: bool = True,
    ) -> str:
        if target_format == "auto":
            target_format = "pe_dll" if sys.platform == "win32" else "elf_so"

        os_stubs = os_import_stubs or {}
        imp_tbl = os_import_table or {}

        if target_format == "pe_dll":
            if not output_path.endswith(".dll"):
                output_path += ".dll"
            imports_by_dll: Dict[str, List[str]] = {}
            for sym in sorted(os_stubs.keys()):
                win_dll = imp_tbl[sym][0] if sym in imp_tbl else "MSVCRT.dll"
                imports_by_dll.setdefault(win_dll, []).append(sym)
            pdb_out = (os.path.splitext(output_path)[0] + ".pdb") if emit_pdb else None
            data = self.build_pe64_dll(
                func_code=func_code,
                export_name=export_name,
                dll_name=os.path.basename(output_path),
                extra_exports=extra_exports,
                pdata_xdata=pdata_xdata,
                imports=imports_by_dll or None,
                os_import_stubs=os_stubs or None,
                data_bytes=data_bytes,
                bss_size=bss_size,
                abs64_reloc_rvas=abs64_reloc_rvas,
                init_array_offset_in_data=init_array_offset_in_data,
                init_array_size=init_array_size,
                fini_array_offset_in_data=fini_array_offset_in_data,
                fini_array_size=fini_array_size,
                tdata_bytes=tdata_bytes,
                tbss_size=tbss_size,
                pdata_prelinked=pdata_prelinked,
                emit_pdb_path=pdb_out,
                emit_debug_dir=True,
            )
        elif target_format in ("elf_so", "arm64_elf_so"):
            if not output_path.endswith(".so"):
                output_path += ".so"
            needed_libs: List[str] = []
            imported_funcs = sorted(os_stubs.keys())
            all_dyn_syms = sorted(set(imported_funcs) | {s for _, s, _, _ in (external_dyn_relocs or [])})
            for sym in all_dyn_syms:
                so_name = imp_tbl[sym][1] if sym in imp_tbl else "libc.so.6"
                if so_name not in needed_libs:
                    needed_libs.append(so_name)
            data = self.build_elf64_so(
                func_code=func_code,
                export_name=export_name,
                extra_exports=extra_exports,
                dwarf_sections=dwarf_sections,
                arch="arm64" if "arm64" in target_format else "x86_64",
                needed_libs=needed_libs or None,
                imported_funcs=imported_funcs or None,
                os_import_stubs=os_stubs or None,
                data_bytes=data_bytes,
                bss_size=bss_size,
                abs64_reloc_rvas=abs64_reloc_rvas,
                init_array_offset_in_data=init_array_offset_in_data,
                init_array_size=init_array_size,
                fini_array_offset_in_data=fini_array_offset_in_data,
                fini_array_size=fini_array_size,
                tdata_bytes=tdata_bytes,
                tbss_size=tbss_size,
                eh_frame_offset_in_code=eh_frame_offset_in_code,
                eh_frame_size=eh_frame_size,
                external_dyn_relocs=external_dyn_relocs,
            )
        elif target_format in ("macho_dylib", "dylib"):
            if not output_path.endswith(".dylib"):
                output_path += ".dylib"
            imported_funcs = sorted(os_stubs.keys())
            data = self.build_macho64_dylib(
                func_code=func_code,
                export_name=export_name,
                arch="x86_64",
                dylib_name=os.path.basename(output_path),
                extra_exports=extra_exports,
                load_dylibs=["/usr/lib/libSystem.B.dylib"] if imported_funcs else None,
                imported_symbols=imported_funcs or None,
                os_import_stubs=os_stubs or None,
                data_bytes=data_bytes,
                bss_size=bss_size,
                abs64_reloc_rvas=abs64_reloc_rvas,
                eh_frame_offset_in_code=eh_frame_offset_in_code,
                eh_frame_size=eh_frame_size,
            )
        elif target_format in ("arm64_macho_dylib", "macho_arm64_dylib"):
            if not output_path.endswith(".dylib"):
                output_path += ".dylib"
            imported_funcs = sorted(os_stubs.keys())
            data = self.build_macho64_dylib(
                func_code=func_code,
                export_name=export_name,
                arch="arm64",
                dylib_name=os.path.basename(output_path),
                extra_exports=extra_exports,
                load_dylibs=["/usr/lib/libSystem.B.dylib"] if imported_funcs else None,
                imported_symbols=imported_funcs or None,
                os_import_stubs=os_stubs or None,
                data_bytes=data_bytes,
                bss_size=bss_size,
                abs64_reloc_rvas=abs64_reloc_rvas,
                eh_frame_offset_in_code=eh_frame_offset_in_code,
                eh_frame_size=eh_frame_size,
            )
        else:
            raise ValueError(f"Unsupported shared library target: {target_format}")

        self._write_file(output_path, data)
        return output_path

    def build_pe64_multi_import_exe(
        self,
        imports: Dict[str, List[str]],
        code_builder: Any,
    ) -> Tuple[bytes, Dict[Tuple[str, str], int]]:
        """
        Builds a Windows PE32+ executable with a dynamically constructed multi-DLL `.idata`
        (Import Directory, ILT, IAT, Hint/Name table) and returns `(pe_bytes, iat_rva_map)`.
        `code_builder(iat_rva_map, text_rva) -> bytes` generates the `.text` payload.
        """
        file_align = self.FILE_ALIGN
        sec_align = self.SEC_ALIGN
        image_base = self.IMAGE_BASE_PE
        text_rva = 0x1000

        dll_items = [(dll, list(syms)) for dll, syms in imports.items() if syms]
        n_dlls = len(dll_items)
        desc_table_bytes = (n_dlls + 1) * 20

        # Precompute relative offsets inside .idata independently of rva_idata
        ilt_offsets: Dict[str, int] = {}
        cur = desc_table_bytes
        for dll, syms in dll_items:
            ilt_offsets[dll] = cur
            cur += (len(syms) + 1) * 8

        iat_start_off = cur
        iat_offsets: Dict[str, int] = {}
        for dll, syms in dll_items:
            iat_offsets[dll] = cur
            cur += (len(syms) + 1) * 8
        iat_total_bytes = cur - iat_start_off

        dll_name_offs: Dict[str, int] = {}
        str_blob = bytearray()
        for dll, _ in dll_items:
            dll_name_offs[dll] = cur + len(str_blob)
            enc = dll.encode("ascii") + b"\x00"
            if len(enc) % 2:
                enc += b"\x00"
            str_blob.extend(enc)

        hint_offs: Dict[Tuple[str, str], int] = {}
        for dll, syms in dll_items:
            for sym in syms:
                hint_offs[(dll, sym)] = cur + len(str_blob)
                enc = b"\x00\x00" + sym.encode("ascii") + b"\x00"
                if len(enc) % 2:
                    enc += b"\x00"
                str_blob.extend(enc)

        idata_vsize = cur + len(str_blob)

        # Pass 1: measure text size with placeholder RVAs
        dummy_map = {
            (dll, sym): 0x2000 + iat_offsets[dll] + idx * 8
            for dll, syms in dll_items
            for idx, sym in enumerate(syms)
        }
        probe_text = bytes(code_builder(dummy_map, text_rva))
        rva_idata = text_rva + self._align_up(max(1, len(probe_text)), sec_align)

        # Pass 2: real IAT RVAs
        iat_rva_map: Dict[Tuple[str, str], int] = {
            (dll, sym): rva_idata + iat_offsets[dll] + idx * 8
            for dll, syms in dll_items
            for idx, sym in enumerate(syms)
        }
        raw_text = bytes(code_builder(iat_rva_map, text_rva))
        raw_text_len = len(raw_text)
        aligned_text_len = self._align_up(max(1, raw_text_len), file_align)
        text_code = raw_text.ljust(aligned_text_len, b"\x90")

        # Materialize .idata
        aligned_idata_len = self._align_up(max(1, idata_vsize), file_align)
        idata = bytearray(aligned_idata_len)
        for d_idx, (dll, syms) in enumerate(dll_items):
            d_off = d_idx * 20
            struct.pack_into(
                "<IIIII",
                idata,
                d_off,
                rva_idata + ilt_offsets[dll],
                0,
                0,
                rva_idata + dll_name_offs[dll],
                rva_idata + iat_offsets[dll],
            )
            for s_idx, sym in enumerate(syms):
                hint_rva = rva_idata + hint_offs[(dll, sym)]
                struct.pack_into("<Q", idata, ilt_offsets[dll] + s_idx * 8, hint_rva)
                struct.pack_into("<Q", idata, iat_offsets[dll] + s_idx * 8, hint_rva)
        idata[cur:cur + len(str_blob)] = str_blob

        iat_rva = rva_idata + iat_start_off
        size_of_image = rva_idata + self._align_up(len(idata), sec_align)

        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<I", dos_header, 0x3C, 0x80)
        dos_stub = b"This program cannot be run in DOS mode.\r\r\n$\0\0\0\0\0\0\0".ljust(64, b"\0")
        pe_sig = b"PE\0\0"
        coff = struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 240, 0x0022)
        opt = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            0x020B, 14, 0,
            len(text_code), len(idata), 0,
            text_rva, text_rva,
            image_base,
            sec_align, file_align,
            6, 0, 0, 0, 6, 0, 0,
            size_of_image, 0x200, 0,
            3, 0x8160,
            0x100000, 0x1000, 0x100000, 0x1000,
            0, 16,
        )
        data_dirs = bytearray(16 * 8)
        if n_dlls > 0:
            struct.pack_into("<II", data_dirs, 1 * 8, rva_idata, desc_table_bytes)
            struct.pack_into("<II", data_dirs, 12 * 8, iat_rva, iat_total_bytes)

        sec_text = struct.pack(
            "<8sIIIIIIHHI",
            b".text\0\0\0",
            raw_text_len, text_rva, len(text_code), 0x200,
            0, 0, 0, 0,
            0x60000020,
        )
        sec_idata = struct.pack(
            "<8sIIIIIIHHI",
            b".idata\0\0",
            idata_vsize, rva_idata, len(idata), 0x200 + len(text_code),
            0, 0, 0, 0,
            0xC0000040,
        )
        headers = (dos_header + dos_stub + pe_sig + coff + opt + data_dirs + sec_text + sec_idata).ljust(file_align, b"\0")
        return bytes(headers + text_code + idata), iat_rva_map

    def build_elf64_dynamic_exe(
        self,
        needed_libs: List[str],
        imported_funcs: List[str],
        custom_code: Optional[Any] = None,
        exit_code: int = 0,
        arch: str = "x86_64",
    ) -> Tuple[bytes, Dict[str, int]]:
        """
        Builds a dynamic Linux ELF64 executable (`ET_EXEC`) with `PT_INTERP`,
        `PT_DYNAMIC` (`DT_NEEDED`, `DT_JMPREL`, `DT_PLTGOT`), `.dynsym`, `.rela.plt`
        (`R_X86_64_JUMP_SLOT` / `R_AARCH64_JUMP_SLOT`), and `.got.plt` slots for external OS shared library calls.
        """
        is_arm64 = arch.lower() in ("arm64", "aarch64")
        e_machine = 183 if is_arm64 else 0x3E
        r_type = 1026 if is_arm64 else 7  # R_AARCH64_JUMP_SLOT vs R_X86_64_JUMP_SLOT

        vaddr = self.VADDR_ELF
        n_ph = 4
        hdrs_end = 64 + n_ph * 56  # 288
        interp_bytes = b"/lib/ld-linux-aarch64.so.1\x00" if is_arm64 else b"/lib64/ld-linux-x86-64.so.2\x00"
        interp_off = self._align_up(hdrs_end, 8)
        code_off = self._align_up(interp_off + len(interp_bytes), 16)
        entry_vaddr = vaddr + code_off

        if callable(custom_code):
            # Two-pass: probe length with dummy GOT slots, then emit with the real slot vaddrs.
            probe = bytes(custom_code({fn: 0 for fn in imported_funcs}, entry_vaddr))
            _, real_slots = self.build_elf64_dynamic_exe(needed_libs, imported_funcs, probe, exit_code, arch=arch)
            real = bytes(custom_code(real_slots, entry_vaddr))
            assert len(real) == len(probe), "ELF code builder must be length-stable across passes"
            return self.build_elf64_dynamic_exe(needed_libs, imported_funcs, real, exit_code, arch=arch)

        if custom_code is not None:
            code = bytearray(custom_code)
        elif is_arm64:
            mov_x0 = 0xD2800000 | ((exit_code & 0xFFFF) << 5) | 0
            mov_x8 = 0xD2800000 | (93 << 5) | 8
            svc_0 = 0xD4000001
            code = bytearray(struct.pack("<III", mov_x0, mov_x8, svc_0))
        else:
            code = bytearray(
                b"\xbf" + struct.pack("<I", exit_code & 0xFFFFFFFF) + b"\xb8\x3c\x00\x00\x00\x0f\x05"
            )

        # .dynstr
        dynstr = bytearray(b"\x00")
        lib_str_offs = []
        for lib in needed_libs:
            lib_str_offs.append(len(dynstr))
            dynstr.extend(lib.encode("ascii") + b"\x00")
        sym_str_offs = []
        for fn in imported_funcs:
            sym_str_offs.append(len(dynstr))
            dynstr.extend(fn.encode("ascii") + b"\x00")

        # .dynsym (SHN_UNDEF external functions)
        dynsym = bytearray(b"\x00" * 24)
        for s_off in sym_str_offs:
            dynsym.extend(struct.pack("<IBBHQQ", s_off, 0x12, 0, 0, 0, 0))

        # SysV DT_HASH
        nbucket = max(1, len(imported_funcs))
        nchain = 1 + len(imported_funcs)
        hash_bytes = struct.pack(f"<II{nbucket}I{nchain}I", nbucket, nchain, *([0] * nbucket), *([0] * nchain))

        dynstr_off = self._align_up(code_off + len(code), 8)
        dynsym_off = self._align_up(dynstr_off + len(dynstr), 8)
        hash_off = self._align_up(dynsym_off + len(dynsym), 8)
        got_plt_off = self._align_up(hash_off + len(hash_bytes), 8)
        got_plt_len = (3 + len(imported_funcs)) * 8
        rela_plt_off = self._align_up(got_plt_off + got_plt_len, 8)
        rela_plt = bytearray()
        got_slot_vaddrs: Dict[str, int] = {}
        for idx, fn in enumerate(imported_funcs):
            slot_vaddr = vaddr + got_plt_off + (3 + idx) * 8
            got_slot_vaddrs[fn] = slot_vaddr
            r_info = ((idx + 1) << 32) | r_type
            rela_plt.extend(struct.pack("<QQq", slot_vaddr, r_info, 0))

        dynamic_off = self._align_up(rela_plt_off + len(rela_plt), 8)
        dyn_table = bytearray()
        for l_off in lib_str_offs:
            dyn_table.extend(struct.pack("<QQ", 1, l_off))  # DT_NEEDED
        dyn_table.extend(struct.pack("<QQ", 4, vaddr + hash_off))         # DT_HASH
        dyn_table.extend(struct.pack("<QQ", 5, vaddr + dynstr_off))       # DT_STRTAB
        dyn_table.extend(struct.pack("<QQ", 6, vaddr + dynsym_off))       # DT_SYMTAB
        dyn_table.extend(struct.pack("<QQ", 10, len(dynstr)))             # DT_STRSZ
        dyn_table.extend(struct.pack("<QQ", 11, 24))                      # DT_SYMENT
        dyn_table.extend(struct.pack("<QQ", 3, vaddr + got_plt_off))      # DT_PLTGOT
        dyn_table.extend(struct.pack("<QQ", 20, 7))                       # DT_PLTREL = DT_RELA
        dyn_table.extend(struct.pack("<QQ", 2, len(rela_plt)))            # DT_PLTRELSZ
        dyn_table.extend(struct.pack("<QQ", 23, vaddr + rela_plt_off))    # DT_JMPREL
        dyn_table.extend(struct.pack("<QQ", 24, 0))                       # DT_BIND_NOW (no lazy PLT0 stub emitted)
        dyn_table.extend(struct.pack("<QQ", 30, 8))                       # DT_FLAGS = DF_BIND_NOW
        dyn_table.extend(struct.pack("<QQ", 0, 0))                        # DT_NULL

        total_size = dynamic_off + len(dyn_table)
        elf_ident = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8)
        elf_header = struct.pack(
            "<16sHHIQQQIHHHHHH",
            elf_ident, 2, e_machine, 1, entry_vaddr, 64, 0, 0,
            64, 56, n_ph, 64, 0, 0,
        )
        ph_interp = struct.pack(
            "<IIQQQQQQ", 3, 4, interp_off, vaddr + interp_off, vaddr + interp_off,
            len(interp_bytes), len(interp_bytes), 1,
        )
        ph_load = struct.pack(
            "<IIQQQQQQ", 1, 7, 0, vaddr, vaddr, total_size, total_size, 0x1000,
        )
        ph_dynamic = struct.pack(
            "<IIQQQQQQ", 2, 6, dynamic_off, vaddr + dynamic_off, vaddr + dynamic_off,
            len(dyn_table), len(dyn_table), 8,
        )
        ph_gnu_stack = struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0, 0, 0, 0, 0, 16)

        buf = bytearray(total_size)
        buf[0:64] = elf_header
        buf[64:120] = ph_interp
        buf[120:176] = ph_load
        buf[176:232] = ph_dynamic
        buf[232:288] = ph_gnu_stack
        buf[interp_off:interp_off + len(interp_bytes)] = interp_bytes
        buf[code_off:code_off + len(code)] = code
        buf[dynstr_off:dynstr_off + len(dynstr)] = dynstr
        buf[dynsym_off:dynsym_off + len(dynsym)] = dynsym
        buf[hash_off:hash_off + len(hash_bytes)] = hash_bytes
        buf[got_plt_off:got_plt_off + 8] = struct.pack("<Q", vaddr + dynamic_off)  # GOT[0] = _DYNAMIC
        buf[rela_plt_off:rela_plt_off + len(rela_plt)] = rela_plt
        buf[dynamic_off:dynamic_off + len(dyn_table)] = dyn_table
        return bytes(buf), got_slot_vaddrs

    def emit_dynamic_executable(
        self,
        output_path: str,
        needed_libs: Union[List[str], Dict[str, List[str]]],
        imported_funcs: Optional[List[str]] = None,
        target_format: str = "auto",
        custom_code: Optional[Any] = None,
        exit_code: int = 0,
    ) -> Tuple[str, Dict[str, int]]:
        """
        Emits a dynamic standalone native executable (.exe on Windows or ELF64 on Linux)
        with real OS dynamic import tables and GOT/IAT slot resolutions.
        """
        if target_format == "auto":
            target_format = "pe64" if sys.platform == "win32" else "elf64"

        if target_format == "pe64":
            if not output_path.endswith(".exe"):
                output_path += ".exe"
            if isinstance(needed_libs, dict):
                imports_by_dll = needed_libs
            else:
                imports_by_dll = {lib: (imported_funcs or []) for lib in needed_libs}
            if callable(custom_code):
                builder = custom_code
            else:
                def builder(slots, text_rva):
                    exit_proc_rva = next((rva for (dll, sym), rva in slots.items() if sym == "ExitProcess"), None)
                    if exit_proc_rva is not None:
                        c = bytearray()
                        c.extend(b"\x48\x83\xec\x28")  # sub rsp, 40
                        c.extend(b"\xb9" + struct.pack("<I", exit_code & 0xFFFFFFFF))  # mov ecx, exit_code
                        c.extend(b"\xff\x15")  # call [rip + disp32]
                        disp = exit_proc_rva - (text_rva + len(c) + 4)
                        c.extend(struct.pack("<i", disp))
                        c.extend(b"\x90" * 8)
                        return bytes(c)
                    return b"\xb8" + struct.pack("<I", exit_code & 0xFFFFFFFF) + b"\xc3"
            data, raw_slots = self.build_pe64_multi_import_exe(
                imports=imports_by_dll,
                code_builder=builder,
            )
            slot_map = {sym: rva for (dll, sym), rva in raw_slots.items()}
        elif target_format == "elf64":
            libs_list = list(needed_libs.keys()) if isinstance(needed_libs, dict) else needed_libs
            funcs_list = imported_funcs or (
                [fn for fns in needed_libs.values() for fn in fns] if isinstance(needed_libs, dict) else []
            )
            data, slot_map = self.build_elf64_dynamic_exe(
                needed_libs=libs_list,
                imported_funcs=funcs_list,
                custom_code=custom_code,
                exit_code=exit_code,
            )
        else:
            raise ValueError(f"Dynamic executables unsupported for format: {target_format}")

        self._write_file(output_path, data)
        return output_path, slot_map

    @staticmethod
    def _emit_pe64_cli_entry_prefix(
        asm: "MiniAssembler",
        text_rva: int,
        getcmd_iat_rva: int,
        exit_iat_rva: int,
        entry_offset: int,
    ) -> None:
        """Emits Win64 CLI entrypoint parsing argv[1] into rcx, calling fn_target+entry_offset, and calling ExitProcess(eax)."""
        asm.emit(b"\x48\x83\xec\x28")  # sub rsp, 40

        call_getcmd_rip = text_rva + len(asm.code) + 6
        asm.emit(b"\xff\x15" + struct.pack("<i", getcmd_iat_rva - call_getcmd_rip))

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

        call_exit_rip = text_rva + len(asm.code) + 6
        asm.emit(b"\xff\x15" + struct.pack("<i", exit_iat_rva - call_exit_rip))
        asm.emit(b"\x48\x83\xc4\x28\xc3")

        pad = (32 - (len(asm.code) % 32)) % 32
        if pad:
            asm.emit(b"\x90" * pad)
        asm.label("fn_target")

    @staticmethod
    def _emit_elf64_cli_entry_prefix(
        asm: "MiniAssembler",
        entry_offset: int,
        exit_got_spec: Optional[Tuple[int, int]] = None,
    ) -> None:
        """Emits Linux SysV _start CLI entrypoint parsing argv[1] into rdi, calling fn_target+entry_offset, and exiting."""
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
        if exit_got_spec is not None:
            entry_vaddr, exit_got_vaddr = exit_got_spec
            call_exit_rip = entry_vaddr + len(asm.code) + 6
            asm.emit(b"\xff\x15" + struct.pack("<i", exit_got_vaddr - call_exit_rip))
        else:
            asm.emit(b"\xb8\x3c\x00\x00\x00")
            asm.emit(b"\x0f\x05")

        pad = (32 - (len(asm.code) % 32)) % 32
        if pad:
            asm.emit(b"\x90" * pad)
        asm.label("fn_target")

    @staticmethod
    def _encode_a64_got_stub(stub_vaddr: int, got_vaddr: int) -> bytes:
        """Encodes a 12-byte AArch64 GOT indirect trampoline: ADRP X16, page; LDR X17, [X16, off]; BR X17."""
        if got_vaddr == 0:
            return struct.pack("<III", 0x90000010, 0xF9400211, 0xD61F0220)
        page_delta = (got_vaddr >> 12) - (stub_vaddr >> 12)
        immlo = page_delta & 0x3
        immhi = (page_delta >> 2) & 0x7FFFF
        adrp_x16 = 0x90000010 | (immlo << 29) | (immhi << 5)
        imm12 = (got_vaddr & 0xFFF) >> 3
        ldr_x17 = 0xF9400211 | (imm12 << 10)
        br_x17 = 0xD61F0220
        return struct.pack("<III", adrp_x16, ldr_x17, br_x17)

    def emit_dynamic_linked_executable(
        self,
        output_path: str,
        linked_code: bytes,
        entry_offset: int,
        os_import_stubs: Dict[str, int],
        os_import_table: Dict[str, Tuple[str, str]],
        target_format: str = "auto",
        exported_symbols: Optional[Dict[str, int]] = None,
    ) -> str:
        """
        Emits a native executable (`pe64`, `elf64`, `arm64_elf`, `macho64`, or `arm64_macho`)
        wrapping `linked_code` with CLI entrypoint and synthesizing OS dynamic import tables.
        """
        if target_format == "auto":
            target_format = "pe64" if sys.platform == "win32" else "elf64"

        if target_format == "pe64":
            if not output_path.endswith(".exe"):
                output_path += ".exe"
            imports_by_dll: Dict[str, List[str]] = {
                "KERNEL32.dll": ["ExitProcess", "GetCommandLineA"],
            }
            for sym in sorted(os_import_stubs.keys()):
                win_dll, _ = os_import_table[sym]
                syms_for_dll = imports_by_dll.setdefault(win_dll, [])
                if sym not in syms_for_dll:
                    syms_for_dll.append(sym)

            def pe_builder(iat_rva_map: Dict[Tuple[str, str], int], text_rva: int) -> bytes:
                getcmd_rva = iat_rva_map[("KERNEL32.dll", "GetCommandLineA")]
                exit_rva = iat_rva_map[("KERNEL32.dll", "ExitProcess")]
                flat_slots = {s: rva for (_d, s), rva in iat_rva_map.items()}
                asm = MiniAssembler()
                self._emit_pe64_cli_entry_prefix(asm, text_rva, getcmd_rva, exit_rva, entry_offset)
                code_start_off = len(asm.code)
                patched = bytearray(linked_code)
                for sym, stub_off in os_import_stubs.items():
                    stub_rip = text_rva + code_start_off + stub_off + 6
                    disp = flat_slots[sym] - stub_rip
                    patched[stub_off : stub_off + 6] = b"\xff\x25" + struct.pack("<i", disp)
                asm.emit(bytes(patched))
                return asm.resolve()

            data, _ = self.build_pe64_multi_import_exe(imports=imports_by_dll, code_builder=pe_builder)

        elif target_format in ("elf64", "arm64_elf"):
            needed_libs: List[str] = ["libc.so.6"]
            imported_funcs = sorted(set(os_import_stubs.keys()) | {"exit"})
            for sym in imported_funcs:
                if sym in os_import_table:
                    _, so_name = os_import_table[sym]
                    if so_name not in needed_libs:
                        needed_libs.append(so_name)

            if target_format == "arm64_elf":
                def arm64_elf_builder(got_slots: Dict[str, int], entry_vaddr: int) -> bytes:
                    prefix_len = 16
                    bl_words = (prefix_len + entry_offset) // 4
                    bl_fn = 0x94000000 | (bl_words & 0x03FFFFFF)
                    exit_stub = self._encode_a64_got_stub(entry_vaddr + 4, got_slots["exit"])
                    patched = bytearray(linked_code)
                    for sym, stub_off in os_import_stubs.items():
                        patched[stub_off : stub_off + 12] = self._encode_a64_got_stub(
                            entry_vaddr + prefix_len + stub_off,
                            got_slots[sym],
                        )
                    return struct.pack("<I", bl_fn) + exit_stub + bytes(patched)

                data, _ = self.build_elf64_dynamic_exe(
                    needed_libs=needed_libs,
                    imported_funcs=imported_funcs,
                    custom_code=arm64_elf_builder,
                    arch="arm64",
                )
            else:
                def elf_builder(got_slots: Dict[str, int], entry_vaddr: int) -> bytes:
                    asm = MiniAssembler()
                    self._emit_elf64_cli_entry_prefix(
                        asm,
                        entry_offset,
                        exit_got_spec=(entry_vaddr, got_slots["exit"]),
                    )
                    code_start_off = len(asm.code)
                    patched = bytearray(linked_code)
                    for sym, stub_off in os_import_stubs.items():
                        stub_rip = entry_vaddr + code_start_off + stub_off + 6
                        disp = got_slots[sym] - stub_rip
                        patched[stub_off : stub_off + 6] = b"\xff\x25" + struct.pack("<i", disp)
                    asm.emit(bytes(patched))
                    return asm.resolve()

                data, _ = self.build_elf64_dynamic_exe(
                    needed_libs=needed_libs,
                    imported_funcs=imported_funcs,
                    custom_code=elf_builder,
                )
        elif target_format in ("macho64", "macho_x86_64", "arm64_macho", "macho_arm64"):
            arch_m = "arm64" if "arm64" in target_format else "x86_64"
            imported_funcs = sorted(set(os_import_stubs.keys()))
            data = self.build_macho64(
                custom_code=linked_code,
                arch=arch_m,
                entry_offset=entry_offset,
                load_dylibs=["/usr/lib/libSystem.B.dylib"],
                imported_symbols=imported_funcs,
                exported_symbols=exported_symbols,
                os_import_stubs=os_import_stubs,
            )
        else:
            raise ValueError(f"Dynamic linked executables unsupported for format: {target_format}")

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
