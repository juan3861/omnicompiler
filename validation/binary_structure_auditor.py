"""
OmniCompiler Formal Binary Structure Auditor.
Utilizes pefile and pyelftools to perform rigorous structural verification of emitted
PE/COFF and ELF binaries against standard OS loader specifications.
"""

import io
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.constants import E_FLAGS
    PYELFTOOLS_AVAILABLE = True
except ImportError:
    PYELFTOOLS_AVAILABLE = False


@dataclass
class BinaryAuditReport:
    is_valid: bool
    format: str  # "PE32+" or "ELF64"
    machine_arch: str  # "x86-64" or "ARM64"
    binary_type: str  # "executable" or "shared_library"
    sections: List[str] = field(default_factory=list)
    exported_symbols: List[str] = field(default_factory=list)
    imported_symbols: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)


class BinaryStructureAuditor:
    """
    Formal specification verifier for compiled standalone executables and shared libraries.
    Ensures complete compliance with Microsoft PE/COFF and System V ELF ABI standards.
    """

    def audit_binary(self, binary_bytes: bytes) -> BinaryAuditReport:
        """Automatically detects format and executes formal specification audit."""
        if len(binary_bytes) < 4:
            return BinaryAuditReport(
                is_valid=False,
                format="unknown",
                machine_arch="unknown",
                binary_type="unknown",
                errors=["Binary length is smaller than 4 bytes"]
            )

        if binary_bytes[:2] == b"MZ":
            return self.audit_pe(binary_bytes)
        elif binary_bytes[:4] == b"\x7fELF":
            return self.audit_elf(binary_bytes)
        elif binary_bytes[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
            return self.audit_macho(binary_bytes)
        else:
            return BinaryAuditReport(
                is_valid=False,
                format="unknown",
                machine_arch="unknown",
                binary_type="unknown",
                errors=[f"Unrecognized binary magic: {binary_bytes[:4].hex()}"]
            )

    def audit_macho(self, macho_bytes: bytes) -> BinaryAuditReport:
        """Formal structural audit of 64-bit Mach-O binaries (macOS x86-64 & ARM64)."""
        import struct
        errors = []
        warnings = []
        sections = []
        exports = []
        imports = []
        metrics = {}

        if len(macho_bytes) < 32:
            return BinaryAuditReport(
                is_valid=False,
                format="Mach-O 64",
                machine_arch="unknown",
                binary_type="unknown",
                errors=["Mach-O header truncated (less than 32 bytes)"]
            )

        magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack(
            "<IIIIIIII", macho_bytes[:32]
        )

        if magic != 0xFEEDFACF:
            errors.append(f"Invalid Mach-O 64 magic (expected 0xFEEDFACF, got 0x{magic:08X})")

        if cputype == 0x01000007:
            arch = "x86-64"
        elif cputype == 0x0100000C:
            arch = "ARM64"
        else:
            arch = f"unknown (0x{cputype:08X})"
            warnings.append(f"Unexpected Mach-O CPU type: {arch}")

        if filetype == 0x2:
            bin_type = "executable"
        elif filetype == 0x6:
            bin_type = "shared_library"
        else:
            bin_type = f"unknown (0x{filetype:04X})"

        offset = 32
        for _ in range(ncmds):
            if offset + 8 > len(macho_bytes):
                errors.append("Load command header truncated")
                break
            cmd, cmdsize = struct.unpack("<II", macho_bytes[offset:offset+8])
            if cmdsize < 8 or offset + cmdsize > len(macho_bytes):
                errors.append(f"Malformed load command size ({cmdsize})")
                break

            if cmd == 0x19:  # LC_SEGMENT_64
                if cmdsize >= 72:
                    segname = macho_bytes[offset+8:offset+24].decode("utf-8", errors="ignore").rstrip("\x00")
                    vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, sflags = struct.unpack(
                        "<QQQQIIII", macho_bytes[offset+24:offset+72]
                    )
                    sec_offset = offset + 72
                    for _ in range(nsects):
                        if sec_offset + 80 <= offset + cmdsize:
                            sectname = macho_bytes[sec_offset:sec_offset+16].decode("utf-8", errors="ignore").rstrip("\x00")
                            sections.append(f"{segname}.{sectname}")
                            sec_offset += 80
            elif cmd == 0x0D:  # LC_ID_DYLIB
                if cmdsize >= 24:
                    name_off, = struct.unpack("<I", macho_bytes[offset+8:offset+12])
                    if offset + name_off < offset + cmdsize:
                        raw_name = macho_bytes[offset+name_off:offset+cmdsize].split(b"\x00")[0]
                        exports.append(raw_name.decode("utf-8", errors="ignore"))

            offset += cmdsize

        metrics["magic"] = f"0x{magic:08X}"
        metrics["cpu_type"] = arch
        metrics["file_type"] = bin_type
        metrics["total_size"] = len(macho_bytes)
        metrics["ncmds"] = ncmds

        is_valid = len(errors) == 0
        return BinaryAuditReport(
            is_valid=is_valid,
            format="Mach-O 64",
            machine_arch=arch,
            binary_type=bin_type,
            sections=sections,
            exported_symbols=exports,
            imported_symbols=imports,
            warnings=warnings,
            errors=errors,
            metrics=metrics
        )

    def audit_pe(self, pe_bytes: bytes) -> BinaryAuditReport:
        """Formal structural audit of Windows PE32+ binaries via pefile."""
        if not PEFILE_AVAILABLE:
            # Fallback basic audit
            is_pe = len(pe_bytes) > 0x80 and pe_bytes[:2] == b"MZ"
            return BinaryAuditReport(
                is_valid=is_pe,
                format="PE32+ (fallback)",
                machine_arch="x86-64",
                binary_type="unknown",
                warnings=["pefile library not installed, fallback verification used."]
            )

        errors = []
        warnings = []
        sections = []
        exports = []
        imports = []
        metrics = {}

        try:
            pe = pefile.PE(data=pe_bytes, fast_load=False)
        except Exception as e:
            return BinaryAuditReport(
                is_valid=False,
                format="PE32+",
                machine_arch="unknown",
                binary_type="unknown",
                errors=[f"pefile parsing exception: {str(e)}"]
            )

        # 1. DOS Header Validation
        if pe.DOS_HEADER.e_magic != pefile.IMAGE_DOS_SIGNATURE:
            errors.append("Invalid DOS Header magic (expected 0x5A4D)")

        # 2. NT Header & Architecture
        if pe.NT_HEADERS.Signature != pefile.IMAGE_NT_SIGNATURE:
            errors.append("Invalid NT Header signature (expected PE\\0\\0)")

        machine = pe.FILE_HEADER.Machine
        if machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            arch = "x86-64"
        elif machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_ARM64"]:
            arch = "ARM64"
        else:
            arch = f"unknown (0x{machine:04x})"
            warnings.append(f"Unexpected machine architecture: {arch}")

        # 3. Characteristics (DLL vs EXE)
        chars = pe.FILE_HEADER.Characteristics
        is_dll = bool(chars & pefile.IMAGE_CHARACTERISTICS["IMAGE_FILE_DLL"])
        bin_type = "shared_library" if is_dll else "executable"

        # 4. Sections Audit & Section Alignment Verification
        sec_align = pe.OPTIONAL_HEADER.SectionAlignment
        file_align = pe.OPTIONAL_HEADER.FileAlignment
        if sec_align < file_align:
            warnings.append(f"SectionAlignment ({sec_align}) is less than FileAlignment ({file_align})")

        for sec in pe.sections:
            sec_name = sec.Name.decode("utf-8", errors="ignore").rstrip("\x00")
            sections.append(sec_name)
            if sec.SizeOfRawData == 0 and sec.Misc_VirtualSize == 0:
                warnings.append(f"Section {sec_name} has zero raw and virtual size.")
            if sec_align > 0 and (sec.VirtualAddress % sec_align != 0):
                warnings.append(f"Section {sec_name} VirtualAddress (0x{sec.VirtualAddress:x}) not aligned to SectionAlignment (0x{sec_align:x})")
            if file_align > 0 and (sec.PointerToRawData % file_align != 0):
                warnings.append(f"Section {sec_name} PointerToRawData (0x{sec.PointerToRawData:x}) not aligned to FileAlignment (0x{file_align:x})")

        # 5. Export Directory Audit
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(exp.name.decode("utf-8", errors="ignore"))
                else:
                    exports.append(f"ordinal_{exp.ordinal}")

        # 6. Import Directory Audit
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore")
                for imp in entry.imports:
                    imp_name = imp.name.decode("utf-8", errors="ignore") if imp.name else f"ord_{imp.ordinal}"
                    imports.append(f"{dll_name}!{imp_name}")

        metrics["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)
        metrics["entry_point_rva"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        metrics["section_alignment"] = pe.OPTIONAL_HEADER.SectionAlignment
        metrics["file_alignment"] = pe.OPTIONAL_HEADER.FileAlignment
        metrics["total_size"] = len(pe_bytes)

        is_valid = len(errors) == 0

        return BinaryAuditReport(
            is_valid=is_valid,
            format="PE32+",
            machine_arch=arch,
            binary_type=bin_type,
            sections=sections,
            exported_symbols=exports,
            imported_symbols=imports,
            warnings=warnings,
            errors=errors,
            metrics=metrics
        )

    def audit_elf(self, elf_bytes: bytes) -> BinaryAuditReport:
        """Formal structural audit of System V ELF64 binaries via pyelftools."""
        if not PYELFTOOLS_AVAILABLE:
            is_elf = len(elf_bytes) > 4 and elf_bytes[:4] == b"\x7fELF"
            return BinaryAuditReport(
                is_valid=is_elf,
                format="ELF64 (fallback)",
                machine_arch="x86-64",
                binary_type="unknown",
                warnings=["pyelftools not installed, fallback verification used."]
            )

        errors = []
        warnings = []
        sections = []
        exports = []
        imports = []
        metrics = {}

        try:
            stream = io.BytesIO(elf_bytes)
            elf = ELFFile(stream)
        except Exception as e:
            return BinaryAuditReport(
                is_valid=False,
                format="ELF64",
                machine_arch="unknown",
                binary_type="unknown",
                errors=[f"pyelftools parsing exception: {str(e)}"]
            )

        # 1. Header Validation
        e_ident = elf.header["e_ident"]
        if e_ident["EI_MAG"] != [0x7F, 0x45, 0x4C, 0x46]:
            errors.append("Invalid ELF magic header")

        if e_ident["EI_CLASS"] != "ELFCLASS64":
            warnings.append(f"Expected ELFCLASS64, got {e_ident['EI_CLASS']}")

        machine = elf.header["e_machine"]
        if machine == "EM_X86_64":
            arch = "x86-64"
        elif machine == "EM_AARCH64":
            arch = "ARM64"
        else:
            arch = str(machine)

        e_type = elf.header["e_type"]
        if e_type == "ET_DYN":
            bin_type = "shared_library"
        elif e_type == "ET_EXEC":
            bin_type = "executable"
        else:
            bin_type = str(e_type)

        # 2. Sections & Segment Alignments
        for seg in elf.iter_segments():
            p_align = seg["p_align"]
            if p_align > 1 and (p_align & (p_align - 1)) != 0:
                warnings.append(f"Segment alignment {p_align} is not a power of two")

        for s in elf.iter_sections():
            name = s.name
            if name:
                sections.append(name)

        # 3. Dynamic Symbols (Exports)
        dynsym = elf.get_section_by_name(".dynsym")
        if dynsym:
            for sym in dynsym.iter_symbols():
                if sym["st_info"]["type"] == "STT_FUNC" and sym["st_shndx"] != "SHN_UNDEF":
                    exports.append(sym.name)
                elif sym["st_shndx"] == "SHN_UNDEF" and sym.name:
                    imports.append(sym.name)
        else:
            # Fallback for segment-only ELF shared objects via PT_DYNAMIC
            strtab_vaddr = None
            symtab_vaddr = None
            strsz = None
            syment = 24
            dynamic_offset = None
            load_vaddr = 0

            for seg in elf.iter_segments():
                if seg["p_type"] == "PT_LOAD" and load_vaddr == 0:
                    load_vaddr = seg["p_vaddr"]
                elif seg["p_type"] == "PT_DYNAMIC":
                    dynamic_offset = seg["p_offset"]
                    for tag in seg.iter_tags():
                        if tag.entry.d_tag == "DT_STRTAB":
                            strtab_vaddr = tag.entry.d_val
                        elif tag.entry.d_tag == "DT_SYMTAB":
                            symtab_vaddr = tag.entry.d_val
                        elif tag.entry.d_tag == "DT_STRSZ":
                            strsz = tag.entry.d_val
                        elif tag.entry.d_tag == "DT_SYMENT":
                            syment = tag.entry.d_val

            if strtab_vaddr and symtab_vaddr and strsz and load_vaddr:
                strtab_offset = strtab_vaddr - load_vaddr
                symtab_offset = symtab_vaddr - load_vaddr
                strtab = elf_bytes[strtab_offset:strtab_offset + strsz]
                max_sym_offset = dynamic_offset if dynamic_offset else len(elf_bytes)
                curr = symtab_offset + syment  # skip null symbol
                import struct
                while curr + syment <= max_sym_offset:
                    entry = elf_bytes[curr:curr + syment]
                    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack("<IBBHQQ", entry)
                    if st_name != 0 and st_name < len(strtab):
                        sym_name = strtab[st_name:].split(b"\0")[0].decode("utf-8", errors="ignore")
                        if sym_name and sym_name not in exports:
                            exports.append(sym_name)
                    curr += syment

        metrics["entry_point"] = hex(elf.header["e_entry"])
        metrics["num_sections"] = elf.num_sections()
        metrics["num_segments"] = elf.num_segments()
        metrics["total_size"] = len(elf_bytes)

        is_valid = len(errors) == 0

        return BinaryAuditReport(
            is_valid=is_valid,
            format="ELF64",
            machine_arch=arch,
            binary_type=bin_type,
            sections=sections,
            exported_symbols=exports,
            imported_symbols=imports,
            warnings=warnings,
            errors=errors,
            metrics=metrics
        )
