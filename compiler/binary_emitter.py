"""
OmniCompiler Standalone Native Binary & Shared Library Emitter
Synthesizes fully linked, freestanding 64-bit native executables and dynamic shared libraries directly in machine code.
Zero runtime dependencies: No GCC, Clang, MSVC, or Python interpreter required.

Architectures Supported:
- x86-64 (AMD64)
- ARM64 (AArch64)

Binary Formats Supported:
1. Windows PE32+ (AMD64) Console Executable (.exe)
2. Windows PE32+ (AMD64) Dynamic Link Library (.dll) with full Export Table (.edata)
3. Windows PE32+ (ARM64) Standalone Executable (.exe)
4. Linux ELF64 (x86-64) Standalone Executable via sys_exit (syscall 60)
5. Linux ELF64 (x86-64) Shared Library (.so) with dynamic symbols (.dynsym, .dynstr)
6. Linux ELF64 (ARM64) Standalone Executable via sys_exit (syscall 93)
"""

import sys
import os
import struct
from typing import Optional, List, Union


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

    # =========================================================================
    # 1. WINDOWS PE32+ (AMD64) EXECUTABLE
    # =========================================================================

    def build_pe64(self, custom_code: Optional[bytes] = None, exit_code: int = 0) -> bytes:
        """Builds a compliant Windows PE32+ (AMD64) console executable calling ExitProcess."""
        file_align = self.FILE_ALIGN
        sec_align = self.SEC_ALIGN
        image_base = self.IMAGE_BASE_PE

        text_code = bytearray()
        text_code.extend(b"\x48\x83\xec\x28")  # sub rsp, 40

        if custom_code:
            text_code.extend(custom_code)
            text_code.extend(b"\x89\xc1")       # mov ecx, eax
        else:
            text_code.extend(b"\xb9" + struct.pack("<I", exit_code & 0xFFFFFFFF))  # mov ecx, exit_code

        next_rip = 0x1000 + len(text_code) + 6
        iat_rva = 0x2040
        disp32 = iat_rva - next_rip

        text_code.extend(b"\xff\x15" + struct.pack("<i", disp32))
        text_code.extend(b"\x48\x83\xc4\x28\xc3")  # add rsp, 40; ret

        raw_text_len = len(text_code)
        aligned_text_len = ((raw_text_len + file_align - 1) // file_align) * file_align
        text_code.extend(b"\x90" * (aligned_text_len - raw_text_len))

        idata = bytearray(file_align)
        struct.pack_into("<IIIII", idata, 0, 0x2030, 0, 0, 0x2050, 0x2040)
        struct.pack_into("<Q", idata, 0x30, 0x2060)
        struct.pack_into("<Q", idata, 0x40, 0x2060)
        idata[0x50:0x50 + 13] = b"KERNEL32.DLL\0"
        idata[0x60:0x60 + 14] = b"\x00\x00ExitProcess\0"

        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<I", dos_header, 0x3C, 0x80)
        dos_stub = b"This program cannot be run in DOS mode.\r\r\n$\0\0\0\0\0\0\0".ljust(64, b"\0")
        pe_sig = b"PE\0\0"

        coff = struct.pack(
            "<HHIIIHH",
            0x8664,  # AMD64
            2,       # .text, .idata
            0, 0, 0,
            240,     # SizeOfOptionalHeader
            0x0022   # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
        )

        opt = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            0x020B,  # PE32+
            14, 0,
            len(text_code), len(idata), 0,
            0x1000, 0x1000,
            image_base,
            sec_align, file_align,
            6, 0, 0, 0, 6, 0, 0,
            0x3000, 0x200, 0,
            3, 0x8160,
            0x100000, 0x1000, 0x100000, 0x1000,
            0, 16
        )

        data_dirs = bytearray(16 * 8)
        struct.pack_into("<II", data_dirs, 1 * 8, 0x2000, 40)
        struct.pack_into("<II", data_dirs, 12 * 8, 0x2040, 16)

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
            0x74, 0x2000, len(idata), 0x200 + len(text_code),
            0, 0, 0, 0,
            0xC0000040
        )

        headers = (dos_header + dos_stub + pe_sig + coff + opt + data_dirs + sec_text + sec_idata).ljust(file_align, b"\0")
        return headers + text_code + idata

    # =========================================================================
    # 2. WINDOWS PE32+ (AMD64) SHARED LIBRARY (.DLL) WITH EXPORT TABLE (.edata)
    # =========================================================================

    def build_pe64_dll(
        self,
        func_code: bytes,
        export_name: str = "omni_compute",
        dll_name: str = "omni_titan.dll"
    ) -> bytes:
        """
        Builds a compliant Windows PE32+ (AMD64) Dynamic Link Library (.dll)
        with DllMain stub and an Export Address Table (.edata) exporting `export_name`.
        """
        file_align = self.FILE_ALIGN
        sec_align = self.SEC_ALIGN
        image_base = self.IMAGE_BASE_DLL

        # 1. Text Section at RVA 0x1000
        text_data = bytearray()
        # DllMain at 0x1000: returns TRUE (1)
        text_data.extend(b"\xb8\x01\x00\x00\x00\xc3")  # mov eax, 1; ret
        text_data.extend(b"\x90" * 10)                  # align to 16 bytes

        # Exported function at 0x1010
        fn_rva = 0x1000 + len(text_data)
        text_data.extend(func_code)

        raw_text_len = len(text_data)
        raw_text = bytes(text_data).ljust(file_align, b"\x90")

        # 2. Edata Section at RVA 0x2000
        rva_edata = 0x2000
        eat_offset = 40
        npt_offset = eat_offset + 4
        ot_offset = npt_offset + 4
        dll_name_offset = ot_offset + 4

        dll_name_bytes = dll_name.encode("ascii") + b"\x00"
        export_name_bytes = export_name.encode("ascii") + b"\x00"
        export_name_offset = dll_name_offset + len(dll_name_bytes)

        eat_rva = rva_edata + eat_offset
        npt_rva = rva_edata + npt_offset
        ot_rva = rva_edata + ot_offset
        dll_name_rva = rva_edata + dll_name_offset
        export_name_rva = rva_edata + export_name_offset

        edata = bytearray()
        edata.extend(struct.pack(
            "<IIHHIIIIIII",
            0, 0, 0, 0,
            dll_name_rva,
            1,  # OrdinalBase
            1,  # AddressTableEntries
            1,  # NumberOfNamePointers
            eat_rva,
            npt_rva,
            ot_rva
        ))
        assert len(edata) == 40
        edata.extend(struct.pack("<I", fn_rva))
        edata.extend(struct.pack("<I", export_name_rva))
        edata.extend(struct.pack("<H", 0))
        edata.extend(b"\x00\x00")  # padding
        edata.extend(dll_name_bytes)
        edata.extend(export_name_bytes)

        raw_edata_len = len(edata)
        raw_edata = bytes(edata).ljust(file_align, b"\x00")

        # 3. Headers
        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<I", dos_header, 0x3C, 0x80)
        dos_stub = b"This program cannot be run in DOS mode.\r\r\n$\0\0\0\0\0\0\0".ljust(64, b"\0")
        pe_sig = b"PE\0\0"

        coff = struct.pack(
            "<HHIIIHH",
            0x8664,  # AMD64
            2,       # .text, .edata
            0, 0, 0,
            240,     # SizeOfOptionalHeader
            0x2022   # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DLL
        )

        opt = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            0x020B,  # PE32+
            14, 0,
            len(raw_text), len(raw_edata), 0,
            0x1000, 0x1000,
            image_base,
            sec_align, file_align,
            6, 0, 0, 0, 6, 0, 0,
            0x3000, 0x200, 0,
            3, 0x8160,
            0x100000, 0x1000, 0x100000, 0x1000,
            0, 16
        )

        data_dirs = bytearray(16 * 8)
        struct.pack_into("<II", data_dirs, 0 * 8, rva_edata, raw_edata_len)  # Export Table Directory

        sec1 = struct.pack(
            "<8sIIIIIIHHI",
            b".text\0\0\0",
            raw_text_len, 0x1000, len(raw_text), 0x200,
            0, 0, 0, 0,
            0x60000020
        )

        sec2 = struct.pack(
            "<8sIIIIIIHHI",
            b".edata\0\0",
            raw_edata_len, 0x2000, len(raw_edata), 0x200 + len(raw_text),
            0, 0, 0, 0,
            0x40000040
        )

        headers = (dos_header + dos_stub + pe_sig + coff + opt + data_dirs + sec1 + sec2).ljust(file_align, b"\0")
        return headers + raw_text + raw_edata

    # =========================================================================
    # 3. LINUX ELF64 (x86-64) STANDALONE EXECUTABLE
    # =========================================================================

    def build_elf64(self, custom_code: Optional[bytes] = None, exit_code: int = 0) -> bytes:
        """Builds a compliant Linux ELF64 (x86-64) standalone executable via sys_exit."""
        vaddr = self.VADDR_ELF
        entry_offset = 120
        entry_addr = vaddr + entry_offset

        code = bytearray()
        if custom_code:
            code.extend(custom_code)
            code.extend(b"\x89\xc7")  # mov edi, eax
        else:
            code.extend(b"\xbf" + struct.pack("<I", exit_code & 0xFFFFFFFF))

        code.extend(b"\xb8\x3c\x00\x00\x00")  # mov eax, 60 (sys_exit)
        code.extend(b"\x0f\x05")              # syscall

        total_size = entry_offset + len(code)
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

        return elf_header + prog_header + code

    # =========================================================================
    # 4. LINUX ELF64 (x86-64) SHARED OBJECT (.SO) WITH DYNAMIC SYMBOLS
    # =========================================================================

    def build_elf64_so(self, func_code: bytes, export_name: str = "omni_compute") -> bytes:
        """
        Builds a compliant Linux ELF64 Shared Object (ET_DYN) with
        PT_DYNAMIC, .dynsym, and .dynstr for dynamic runtime linking.
        """
        vaddr = self.VADDR_SO
        code = bytearray(func_code)

        code_offset = 0x200
        code_vaddr = vaddr + code_offset

        dynstr = b"\x00" + export_name.encode("ascii") + b"\x00"
        dynstr_offset = code_offset + len(code)

        null_sym = b"\x00" * 24
        exp_sym = struct.pack(
            "<IBBHQQ",
            1,          # st_name
            0x12,       # st_info: STB_GLOBAL | STT_FUNC
            0, 1,
            code_vaddr,
            len(code)
        )
        dynsym = null_sym + exp_sym
        dynsym_offset = dynstr_offset + len(dynstr)

        dyn_table = bytearray()
        dyn_table.extend(struct.pack("<QQ", 5, vaddr + dynstr_offset))   # DT_STRTAB
        dyn_table.extend(struct.pack("<QQ", 6, vaddr + dynsym_offset))   # DT_SYMTAB
        dyn_table.extend(struct.pack("<QQ", 10, len(dynstr)))            # DT_STRSZ
        dyn_table.extend(struct.pack("<QQ", 11, 24))                     # DT_SYMENT
        dyn_table.extend(struct.pack("<QQ", 0, 0))                       # DT_NULL

        dynamic_offset = dynsym_offset + len(dynsym)
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
        """
        Builds a compliant Linux ARM64 (AArch64) standalone executable.
        Executes instructions, loads exit_code into X0, and calls sys_exit (syscall 93 via SVC #0).
        """
        vaddr = self.VADDR_ELF
        entry_offset = 120
        entry_addr = vaddr + entry_offset

        code = bytearray()
        if custom_code:
            code.extend(custom_code)
        else:
            mov_x0 = 0xd2800000 | ((exit_code & 0xFFFF) << 5) | 0
            code.extend(struct.pack("<I", mov_x0))

        # Linux AArch64 syscall: MOV X8, #93; SVC #0
        mov_x8 = 0xd2800000 | (93 << 5) | 8
        svc_0 = 0xd4000001
        code.extend(struct.pack("<II", mov_x8, svc_0))

        total_size = entry_offset + len(code)
        elf_ident = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8)
        elf_header = struct.pack(
            "<16sHHIQQQIHHHHHH",
            elf_ident,
            2,          # ET_EXEC
            183,        # EM_AARCH64 (0xB7)
            1, entry_addr, 64, 0, 0,
            64, 56, 1, 64, 0, 0
        )

        prog_header = struct.pack(
            "<IIQQQQQQ",
            1, 7, 0, vaddr, vaddr, total_size, total_size, 0x1000
        )

        return elf_header + prog_header + bytes(code)

    def build_arm64_pe(self, exit_code: int = 0, custom_code: Optional[bytes] = None) -> bytes:
        """Builds a compliant Windows ARM64 (AArch64) PE32+ executable."""
        file_align = self.FILE_ALIGN
        sec_align = self.SEC_ALIGN
        image_base = self.IMAGE_BASE_PE

        code = bytearray()
        if custom_code:
            code.extend(custom_code)
        else:
            mov_x0 = 0xd2800000 | ((exit_code & 0xFFFF) << 5) | 0
            ret_inst = 0xd65f03c0
            code.extend(struct.pack("<II", mov_x0, ret_inst))

        raw_code = bytes(code).ljust(file_align, b"\x00")

        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<I", dos_header, 0x3C, 0x80)
        dos_stub = b"This program cannot be run in DOS mode.\r\r\n$\0\0\0\0\0\0\0".ljust(64, b"\0")
        pe_sig = b"PE\0\0"

        coff = struct.pack(
            "<HHIIIHH",
            0xAA64,  # IMAGE_FILE_MACHINE_ARM64
            1,       # .text
            0, 0, 0,
            240,
            0x0022
        )

        opt = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            0x020B,
            14, 0,
            len(raw_code), 0, 0,
            0x1000, 0x1000,
            image_base,
            sec_align, file_align,
            6, 0, 0, 0, 6, 0, 0,
            0x2000, 0x200, 0,
            3, 0x8160,
            0x100000, 0x1000, 0x100000, 0x1000,
            0, 16
        )

        data_dirs = bytearray(16 * 8)
        sec1 = struct.pack(
            "<8sIIIIIIHHI",
            b".text\0\0\0",
            len(code), 0x1000, len(raw_code), 0x200,
            0, 0, 0, 0,
            0x60000020
        )

        headers = (dos_header + dos_stub + pe_sig + coff + opt + data_dirs + sec1).ljust(file_align, b"\0")
        return headers + raw_code

    # =========================================================================
    # HIGH-LEVEL ORCHESTRATION HELPERS
    # =========================================================================

    def emit_standalone_binary(
        self,
        output_path: str,
        target_format: str = "auto",
        custom_code: Optional[bytes] = None,
        exit_code: int = 0
    ) -> str:
        """
        Emits a standalone executable file to `output_path`.
        target_format options:
          - 'auto': detects host OS (pe64 on Windows, elf64 on Linux)
          - 'pe64': Windows x86-64
          - 'elf64': Linux x86-64
          - 'arm64_elf': Linux ARM64
          - 'arm64_pe': Windows ARM64
        """
        if target_format == "auto":
            target_format = "pe64" if sys.platform == "win32" else "elf64"

        if target_format == "pe64":
            if not output_path.endswith(".exe"): output_path += ".exe"
            data = self.build_pe64(custom_code=custom_code, exit_code=exit_code)
        elif target_format == "elf64":
            data = self.build_elf64(custom_code=custom_code, exit_code=exit_code)
        elif target_format == "arm64_elf":
            data = self.build_arm64_elf(exit_code=exit_code, custom_code=custom_code)
        elif target_format == "arm64_pe":
            if not output_path.endswith(".exe"): output_path += ".exe"
            data = self.build_arm64_pe(exit_code=exit_code, custom_code=custom_code)
        else:
            raise ValueError(f"Unsupported binary target: {target_format}")

        self._write_file(output_path, data)
        return output_path

    def emit_shared_library(
        self,
        output_path: str,
        func_code: bytes,
        export_name: str = "omni_compute",
        target_format: str = "auto"
    ) -> str:
        """
        Emits a dynamic shared library (.dll on Windows, .so on Linux).
        """
        if target_format == "auto":
            target_format = "pe_dll" if sys.platform == "win32" else "elf_so"

        if target_format == "pe_dll":
            if not output_path.endswith(".dll"): output_path += ".dll"
            data = self.build_pe64_dll(func_code=func_code, export_name=export_name, dll_name=os.path.basename(output_path))
        elif target_format == "elf_so":
            if not output_path.endswith(".so"): output_path += ".so"
            data = self.build_elf64_so(func_code=func_code, export_name=export_name)
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
    """Convenience helper to emit a native standalone executable."""
    emitter = StandaloneBinaryEmitter()
    return emitter.emit_standalone_binary(output_path=output_path, custom_code=custom_code, exit_code=exit_code)
