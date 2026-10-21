"""
OmniCompiler Standalone Native Binary Emitter (PE32+ & ELF64)
Synthesizes fully linked, freestanding 64-bit native executables directly in machine code.
Zero runtime dependencies: No GCC, Clang, MSVC, or Python interpreter required.
Supports:
1. Windows PE32+ (x86-64) Console Executable (.exe) linking to KERNEL32.DLL!ExitProcess.
2. Linux ELF64 (x86-64) Executable via direct sys_exit (syscall 60).
"""

import sys
import os
import struct
from typing import Optional, List, Union
from compiler.ssa_ir import SSAFunction


class StandaloneBinaryEmitter:
    """
    Direct Machine-Code Binary Emitter.
    Transforms raw x86-64 machine code or SSA representations into standalone native binaries.
    """

    FILE_ALIGN = 0x200
    SEC_ALIGN = 0x1000
    IMAGE_BASE_PE = 0x140000000
    VADDR_ELF = 0x400000

    def __init__(self):
        self.host_os = "windows" if sys.platform == "win32" else "linux"

    def build_pe64(self, custom_code: Optional[bytes] = None, exit_code: int = 0) -> bytes:
        """
        Builds a compliant Windows PE32+ (AMD64) executable.
        Executes `custom_code` (if provided, result expected in RAX or ECX),
        then invokes KERNEL32!ExitProcess with the final exit code.
        """
        file_align = self.FILE_ALIGN
        sec_align = self.SEC_ALIGN
        image_base = self.IMAGE_BASE_PE

        # Assemble .text section
        # Default computation if custom_code is None: load exit_code into ECX
        text_code = bytearray()
        text_code.extend(b"\x48\x83\xec\x28")  # sub rsp, 40 (shadow space + 16-byte alignment)

        if custom_code:
            text_code.extend(custom_code)
            # Move result from EAX to ECX (1st param to ExitProcess)
            text_code.extend(b"\x89\xc1")       # mov ecx, eax
        else:
            text_code.extend(b"\xb9" + struct.pack("<I", exit_code & 0xFFFFFFFF))  # mov ecx, exit_code

        # Call ExitProcess via IAT
        # Call instruction: ff 15 <disp32> (6 bytes)
        # In .text at RVA 0x1000, call starts at len(text_code)
        # Next RIP = 0x1000 + len(text_code) + 6
        # Target IAT entry is at RVA 0x2040 (in .idata)
        next_rip = 0x1000 + len(text_code) + 6
        iat_rva = 0x2040
        disp32 = iat_rva - next_rip

        text_code.extend(b"\xff\x15" + struct.pack("<i", disp32))
        text_code.extend(b"\x48\x83\xc4\x28\xc3")  # add rsp, 40; ret

        # Pad .text to FileAlignment
        raw_text_len = len(text_code)
        aligned_text_len = ((raw_text_len + file_align - 1) // file_align) * file_align
        text_code.extend(b"\x90" * (aligned_text_len - raw_text_len))

        # Build .idata section at RVA 0x2000
        # RVA 0x2000: Import Directory (20 bytes for KERNEL32 + 20 bytes null)
        #   OriginalFirstThunk: RVA 0x2030 (ILT)
        #   TimeDateStamp: 0
        #   ForwarderChain: 0
        #   Name: RVA 0x2050 (KERNEL32.DLL)
        #   FirstThunk: RVA 0x2040 (IAT)
        # RVA 0x2030: ILT -> qword RVA 0x2060 (Hint/Name) + qword 0
        # RVA 0x2040: IAT -> qword RVA 0x2060 (Hint/Name) + qword 0
        # RVA 0x2050: 'KERNEL32.DLL\0'
        # RVA 0x2060: Hint(0x0000) + 'ExitProcess\0'
        idata = bytearray(file_align)
        struct.pack_into("<IIIII", idata, 0, 0x2030, 0, 0, 0x2050, 0x2040)
        struct.pack_into("<Q", idata, 0x30, 0x2060)
        struct.pack_into("<Q", idata, 0x40, 0x2060)
        idata[0x50:0x50 + 13] = b"KERNEL32.DLL\0"
        idata[0x60:0x60 + 14] = b"\x00\x00ExitProcess\0"

        # Headers construction
        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<I", dos_header, 0x3C, 0x80)

        dos_stub = b"This program cannot be run in DOS mode.\r\r\n$\0\0\0\0\0\0\0".ljust(64, b"\0")
        pe_sig = b"PE\0\0"

        coff = struct.pack(
            "<HHIIIHH",
            0x8664,  # Machine: AMD64
            2,       # NumberOfSections (.text, .idata)
            0, 0, 0,
            240,     # SizeOfOptionalHeader
            0x0022   # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
        )

        opt = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            0x020B,  # Magic: PE32+
            14, 0,   # Linker Version
            len(text_code), len(idata), 0,
            0x1000,  # AddressOfEntryPoint (RVA 0x1000)
            0x1000,  # BaseOfCode
            image_base,
            sec_align, file_align,
            6, 0, 0, 0, 6, 0, 0,
            0x3000,  # SizeOfImage
            0x200,   # SizeOfHeaders
            0,       # CheckSum
            3,       # Subsystem: Console
            0x8160,  # DllCharacteristics: DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
            0x100000, 0x1000, 0x100000, 0x1000,
            0,
            16       # NumberOfRvaAndSizes
        )

        data_dirs = bytearray(16 * 8)
        struct.pack_into("<II", data_dirs, 1 * 8, 0x2000, 40)   # Import Table
        struct.pack_into("<II", data_dirs, 12 * 8, 0x2040, 16)  # IAT Table

        sec_text = struct.pack(
            "<8sIIIIIIHHI",
            b".text\0\0\0",
            raw_text_len, 0x1000, len(text_code), 0x200,
            0, 0, 0, 0,
            0x60000020  # CNT_CODE | MEM_EXECUTE | MEM_READ
        )

        sec_idata = struct.pack(
            "<8sIIIIIIHHI",
            b".idata\0\0",
            0x74, 0x2000, len(idata), 0x200 + len(text_code),
            0, 0, 0, 0,
            0xC0000040  # CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE
        )

        headers = (dos_header + dos_stub + pe_sig + coff + opt + data_dirs + sec_text + sec_idata).ljust(file_align, b"\0")
        return headers + text_code + idata

    def build_elf64(self, custom_code: Optional[bytes] = None, exit_code: int = 0) -> bytes:
        """
        Builds a compliant Linux ELF64 (x86-64) standalone executable.
        Executes `custom_code` (if provided, result expected in RAX or EDI),
        then executes direct sys_exit (syscall 60).
        """
        vaddr = self.VADDR_ELF
        entry_offset = 120  # 64-byte ELF Header + 56-byte Program Header
        entry_addr = vaddr + entry_offset

        code = bytearray()
        if custom_code:
            code.extend(custom_code)
            code.extend(b"\x89\xc7")  # mov edi, eax
        else:
            code.extend(b"\xbf" + struct.pack("<I", exit_code & 0xFFFFFFFF))  # mov edi, exit_code

        code.extend(b"\xb8\x3c\x00\x00\x00")  # mov eax, 60 (sys_exit)
        code.extend(b"\x0f\x05")              # syscall

        total_size = entry_offset + len(code)

        elf_ident = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8)
        elf_header = struct.pack(
            "<16sHHIQQQIHHHHHH",
            elf_ident,
            2,       # ET_EXEC
            0x3E,    # EM_X86_64
            1,       # EV_CURRENT
            entry_addr,
            64,      # e_phoff (offset of Program Header Table)
            0,       # e_shoff
            0,       # e_flags
            64,      # e_ehsize
            56,      # e_phentsize
            1,       # e_phnum
            64,      # e_shentsize
            0,       # e_shnum
            0        # e_shstrndx
        )

        prog_header = struct.pack(
            "<IIQQQQQQ",
            1,           # p_type: PT_LOAD
            7,           # p_flags: PF_R | PF_W | PF_X
            0,           # p_offset
            vaddr,       # p_vaddr
            vaddr,       # p_paddr
            total_size,  # p_filesz
            total_size,  # p_memsz
            0x1000       # p_align
        )

        return elf_header + prog_header + code

    def emit_standalone_binary(
        self,
        output_path: str,
        target_format: str = "auto",
        custom_code: Optional[bytes] = None,
        exit_code: int = 0
    ) -> str:
        """
        Emits a standalone executable file to `output_path`.
        target_format: 'pe64', 'elf64', or 'auto' (detects host OS).
        """
        if target_format == "auto":
            target_format = "pe64" if sys.platform == "win32" else "elf64"

        if target_format == "pe64":
            if not output_path.endswith(".exe"):
                output_path += ".exe"
            data = self.build_pe64(custom_code=custom_code, exit_code=exit_code)
        elif target_format == "elf64":
            data = self.build_elf64(custom_code=custom_code, exit_code=exit_code)
        else:
            raise ValueError(f"Unsupported binary format: {target_format}")

        dir_path = os.path.dirname(output_path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)

        with open(output_path, "wb") as f:
            f.write(data)

        if target_format == "elf64" and hasattr(os, "chmod"):
            os.chmod(output_path, 0o755)

        return output_path


def emit_standalone_executable(output_path: str, exit_code: int = 0, custom_code: Optional[bytes] = None) -> str:
    """Convenience helper to emit a native standalone executable."""
    emitter = StandaloneBinaryEmitter()
    return emitter.emit_standalone_binary(output_path=output_path, custom_code=custom_code, exit_code=exit_code)
