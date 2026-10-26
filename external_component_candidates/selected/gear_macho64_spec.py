"""
Staging Component Specification: GEAR-001 & GEAR-002
Source Inspiration: gimli-rs/object, m4b/goblin, trailofbits/maco
Domain: 64-bit Mach-O Binary Emission & Invariant Auditing
Target Gap: GAP-01 (Multi-Target macOS x86-64 & Apple Silicon ARM64 Emission)
"""

import struct
from typing import Dict, Any, List

# Mach-O 64 Constants
MH_MAGIC_64 = 0xFEEDFACF  # 64-bit Mach-O magic (little-endian: 0xcffaedfe)
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_LIB64 = 0x80000000
CPU_SUBTYPE_ARM64_ALL = 0x00000000

MH_EXECUTE = 0x2
MH_DYLIB = 0x6
MH_NOUNDEFS = 0x1
MH_DYLDLINK = 0x4
MH_TWOLEVEL = 0x80
MH_PIE = 0x200000

# Load Commands
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLINKER = 0x0E
LC_MAIN = 0x80000028
LC_ID_DYLIB = 0x0D

# VM Protections
VM_PROT_NONE = 0x0
VM_PROT_READ = 0x1
VM_PROT_WRITE = 0x2
VM_PROT_EXECUTE = 0x4


def build_mach_header_64(cputype: int, cpusubtype: int, filetype: int, ncmds: int, sizeofcmds: int, flags: int) -> bytes:
    """Serializes 32-byte mach_header_64."""
    reserved = 0
    return struct.pack(
        "<IIIIIIII",
        MH_MAGIC_64,
        cputype,
        cpusubtype,
        filetype,
        ncmds,
        sizeofcmds,
        flags,
        reserved
    )
