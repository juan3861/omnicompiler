"""
Native Zero-Cost Exception Handling & Unwind Runtime (Alpha-C94).

Provides:
1. `LsdaEntry` / `LsdaTable`: Language-Specific Data Area records `[try_start, try_end) -> landing_pad`
   paired with `.eh_frame` (ELF/Mach-O) and `.pdata`/`.xdata` (Win64 PE32+) unwind metadata.
2. `NativeEHRuntime`: Synthesizes freestanding x86-64 (Win64 / SysV64) native machine code
   for `__omni_eh_throw(int64 exc_code)` that physically walks the RBP/RIP stack frames,
   checks each return address against registered `LsdaTable` ranges, writes `exc_code` to
   the catch slot / `RAX`, restores target `RBP`/`RSP`, and jumps directly to the landing pad
   with ZERO runtime overhead on non-throwing paths.
"""

import ctypes
import struct
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from compiler.debug_info_emitter import DwarfCFIFrameEmitter, decode_win64_pdata, emit_win64_multi_pdata_xdata


@dataclass
class LsdaEntry:
    function_name: str
    try_start_pc: int
    try_end_pc: int
    landing_pad_pc: int
    frame_size: int
    exc_slot_rbp_disp: int = 0

    def pack_bytes(self) -> bytes:
        return struct.pack(
            "<QQQii",
            int(self.try_start_pc) & 0xFFFFFFFFFFFFFFFF,
            int(self.try_end_pc) & 0xFFFFFFFFFFFFFFFF,
            int(self.landing_pad_pc) & 0xFFFFFFFFFFFFFFFF,
            int(self.frame_size),
            int(self.exc_slot_rbp_disp),
        )


class LsdaTable:
    """Thread-safe serializable LSDA table paired with .eh_frame / .pdata unwind tables."""

    ENTRY_SIZE = 32  # <QQQii

    def __init__(self) -> None:
        self.entries: List[LsdaEntry] = []

    def add_entry(self, entry: LsdaEntry) -> None:
        self.entries.append(entry)

    def lookup(self, pc: int) -> Optional[LsdaEntry]:
        for e in self.entries:
            if e.try_start_pc <= pc < e.try_end_pc:
                return e
        return None

    def serialize(self) -> bytes:
        raw = bytearray()
        for e in self.entries:
            raw.extend(e.pack_bytes())
        raw.extend(b"\x00" * self.ENTRY_SIZE)  # null sentinel record
        return bytes(raw)

    @classmethod
    def from_compiled_artifacts(
        cls,
        artifacts: Dict[str, Any],
        code_base_addr: int,
        global_offsets: Dict[str, int],
    ) -> "LsdaTable":
        table = cls()
        for fn_name, art in artifacts.items():
            fn_base = code_base_addr + global_offsets.get(fn_name, 0)
            for rec in getattr(art, "eh_lsda_entries", []):
                table.add_entry(
                    LsdaEntry(
                        function_name=fn_name,
                        try_start_pc=fn_base + int(rec["try_start_off"]),
                        try_end_pc=fn_base + int(rec["try_end_off"]),
                        landing_pad_pc=fn_base + int(rec["landing_pad_off"]),
                        frame_size=int(rec.get("frame_size", getattr(art, "stack_frame_size", 0))),
                        exc_slot_rbp_disp=int(rec.get("exc_slot_rbp_disp", 0)),
                    )
                )
        return table


def build_x64_unwind_throw_stub(lsda_table_addr: int, target_os: str = "windows") -> bytes:
    """
    Emits position-independent x86-64 machine code for `__omni_eh_throw(int64 exc_code)`.
    Walks RBP chain starting from immediate caller (`[rsp]` = ret_pc, `rbp` = caller rbp),
    matches `[try_start, try_end)` in the 32-byte LSDA table at `lsda_table_addr`,
    stores `exc_code` to `[target_rbp + exc_disp]` & `RAX`, restores target `RBP`/`RSP`,
    and transfers control via indirect `jmp [rdx + 16]`.
    """
    is_win = target_os.lower() in ("win", "win32", "windows")
    code = bytearray()
    labels: Dict[str, int] = {}
    fixups: List[Tuple[int, str, int]] = []

    def mark(lbl: str) -> None:
        labels[lbl] = len(code)

    def jmp_rel8(op_b: int, lbl: str) -> None:
        code.append(op_b)
        fixups.append((len(code), lbl, 1))
        code.append(0)

    def jmp_rel32(op_bytes: bytes, lbl: str) -> None:
        code.extend(op_bytes)
        fixups.append((len(code), lbl, 4))
        code.extend(b"\x00\x00\x00\x00")

    # Save exc_code into r10: win64 rcx -> r10; sysv64 rdi -> r10
    if is_win:
        code.extend(b"\x49\x89\xca")        # mov r10, rcx
    else:
        code.extend(b"\x49\x89\xfa")        # mov r10, rdi

    code.extend(b"\x4c\x8b\x1c\x24")        # mov r11, [rsp]      ; return PC in thrower
    code.extend(b"\x49\x89\xe9")            # mov r9, rbp         ; thrower RBP
    code.extend(b"\x49\xb8")                # movabs r8, lsda_table_addr
    code.extend(struct.pack("<Q", lsda_table_addr & 0xFFFFFFFFFFFFFFFF))

    mark("loop_walk")
    code.extend(b"\x4c\x89\xc2")            # mov rdx, r8

    mark("scan_lsda")
    code.extend(b"\x48\x8b\x0a")            # mov rcx, [rdx]      ; try_start_pc
    code.extend(b"\x48\x85\xc9")            # test rcx, rcx
    jmp_rel32(b"\x0f\x84", "step_up")       # jz step_up
    code.extend(b"\x49\x39\xcb")            # cmp r11, rcx
    jmp_rel8(0x72, "next_entry")            # jb next_entry
    code.extend(b"\x4c\x3b\x5a\x08")        # cmp r11, [rdx + 8]  ; try_end_pc
    jmp_rel8(0x73, "next_entry")            # jae next_entry

    # Found matching try handler!
    code.extend(b"\x8b\x42\x18")            # mov eax, [rdx + 24] ; uint32 frame_size -> rax
    code.extend(b"\x4c\x89\xc9")            # mov rcx, r9
    code.extend(b"\x48\x29\xc1")            # sub rcx, rax        ; target RSP = target RBP - frame_size
    code.extend(b"\x48\x63\x42\x1c")        # movsxd rax, dword ptr [rdx + 28] ; exc_slot_rbp_disp
    code.extend(b"\x48\x85\xc0")            # test rax, rax
    jmp_rel8(0x74, "skip_store")            # jz skip_store
    code.extend(b"\x4d\x89\x14\x01")        # mov [r9 + rax], r10 ; store exc_code into handler slot
    mark("skip_store")
    code.extend(b"\x4c\x89\xd0")            # mov rax, r10        ; RAX = exc_code
    code.extend(b"\x4c\x89\xcd")            # mov rbp, r9         ; restore target RBP
    code.extend(b"\x48\x89\xcc")            # mov rsp, rcx        ; restore target RSP
    code.extend(b"\xff\x62\x10")            # jmp qword ptr [rdx + 16] ; jump to landing_pad_pc

    mark("next_entry")
    code.extend(b"\x48\x83\xc2\x20")        # add rdx, 32
    jmp_rel8(0xEB, "scan_lsda")             # jmp scan_lsda

    mark("step_up")
    code.extend(b"\x4d\x85\xc9")            # test r9, r9
    jmp_rel8(0x74, "unhandled")             # jz unhandled
    code.extend(b"\x4d\x8b\x59\x08")        # mov r11, [r9 + 8]   ; caller return PC
    code.extend(b"\x4d\x8b\x09")            # mov r9, [r9]        ; caller RBP
    jmp_rel8(0xEB, "loop_walk")             # jmp loop_walk

    mark("unhandled")
    code.extend(b"\x4c\x89\xd0")            # mov rax, r10
    code.extend(b"\x48\xf7\xd8")            # neg rax
    code.append(0xC3)                       # ret

    for pos, lbl, sz in fixups:
        disp = labels[lbl] - (pos + sz)
        if sz == 1:
            struct.pack_into("<b", code, pos, disp)
        else:
            struct.pack_into("<i", code, pos, disp)

    return bytes(code)


class NativeEHRuntime:
    """
    Allocates executable JIT/LSDA pages (Win32 VirtualAlloc / POSIX mmap) or builds
    static unwind metadata for native `.eh_frame` + `.pdata` zero-cost exception unwinding.
    """

    def __init__(self, target_os: Optional[str] = None):
        if target_os is None:
            self.target_os = "windows" if sys.platform == "win32" else ("macos" if sys.platform == "darwin" else "linux")
        else:
            self.target_os = target_os.lower()
        self._allocations: List[Tuple[int, int]] = []

    def _alloc_rwx(self, size: int) -> int:
        sz = max(4096, ((size + 4095) // 4096) * 4096)
        if sys.platform == "win32":
            k32 = ctypes.windll.kernel32
            k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
            k32.VirtualAlloc.restype = ctypes.c_void_p
            ptr = k32.VirtualAlloc(None, sz, 0x3000, 0x40)  # MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
            if not ptr:
                raise MemoryError("VirtualAlloc failed in NativeEHRuntime")
            self._allocations.append((int(ptr), sz))
            return int(ptr)
        else:
            libc = ctypes.CDLL(None)
            libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
            libc.mmap.restype = ctypes.c_void_p
            # PROT_READ|PROT_WRITE|PROT_EXEC = 7; MAP_PRIVATE|MAP_ANONYMOUS = 0x22 (Linux) / 0x1002 (macOS)
            map_flags = 0x1002 if sys.platform == "darwin" else 0x22
            ptr = libc.mmap(None, sz, 7, map_flags, -1, 0)
            if not ptr or ptr == ctypes.c_void_p(-1).value:
                raise MemoryError("mmap RWX failed in NativeEHRuntime")
            self._allocations.append((int(ptr), sz))
            return int(ptr)

    def release(self) -> None:
        if not self._allocations:
            return
        if sys.platform == "win32":
            k32 = ctypes.windll.kernel32
            k32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
            k32.VirtualFree.restype = ctypes.c_int
            for ptr, _sz in self._allocations:
                k32.VirtualFree(ctypes.c_void_p(ptr), 0, 0x8000)  # MEM_RELEASE
        else:
            libc = ctypes.CDLL(None)
            libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libc.munmap.restype = ctypes.c_int
            for ptr, sz in self._allocations:
                libc.munmap(ctypes.c_void_p(ptr), sz)
        self._allocations.clear()

    def close(self) -> None:
        self.release()

    def __enter__(self) -> "NativeEHRuntime":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.release()

    @staticmethod
    def build_unwind_tables(
        artifacts: Dict[str, Any],
        global_offsets: Dict[str, int],
        arch: str = "x86_64",
    ) -> Dict[str, Any]:
        cfi_entries: List[Dict[str, Any]] = []
        win64_entries: List[Dict[str, Any]] = []
        for fn_name, art in artifacts.items():
            off = global_offsets.get(fn_name, 0)
            csz = max(1, len(art.code_bytes))
            fsz = int(getattr(art, "stack_frame_size", 0))
            saved = list(getattr(art, "saved_nonvolatile_regs", []))
            cfi_entries.append({
                "initial_location": 0x400000 + off,
                "address_range": csz,
                "stack_frame_size": fsz,
                "saved_regs": saved,
                "prologue_size": 4,
            })
            win64_entries.append({
                "func_rva": 0x1000 + off,
                "code_size": csz,
                "stack_frame_size": fsz,
                "saved_regs": saved,
                "prologue_size": 4,
            })
        eh_frame_bytes = DwarfCFIFrameEmitter().emit_eh_frame(cfi_entries, arch=arch)
        pdata, xdata = emit_win64_multi_pdata_xdata(win64_entries)
        return {
            "eh_frame": eh_frame_bytes,
            "pdata": pdata,
            "xdata": xdata,
            "eh_info": DwarfCFIFrameEmitter.decode_eh_frame(eh_frame_bytes),
            "win64_pdata_entries": decode_win64_pdata(pdata, xdata),
        }

    def materialize_jit_with_eh(
        self,
        combined_code: bytes,
        artifacts: Dict[str, Any],
        global_offsets: Dict[str, int],
        relocations_to_patch: Optional[List[Tuple[int, str]]] = None,
    ) -> Dict[str, Any]:
        """
        Allocates executable code page(s), constructs the real runtime LSDA table,
        synthesizes native `__omni_eh_throw`, patches calls to `__omni_eh_throw`,
        and returns base address + entry addresses ready for ctypes invocation.
        """
        # Reserve space: [code_bytes (aligned 16)] + [throw_stub (aligned 16)] + [lsda_table]
        code_padded_len = ((len(combined_code) + 15) // 16) * 16
        lsda_placeholder = LsdaTable.from_compiled_artifacts(artifacts, 0, global_offsets).serialize()
        stub_template = build_x64_unwind_throw_stub(0, target_os=self.target_os)
        stub_padded_len = ((len(stub_template) + 15) // 16) * 16
        total_len = code_padded_len + stub_padded_len + len(lsda_placeholder)

        base_addr = self._alloc_rwx(total_len)
        throw_addr = base_addr + code_padded_len
        lsda_addr = throw_addr + stub_padded_len

        lsda = LsdaTable.from_compiled_artifacts(artifacts, base_addr, global_offsets)
        lsda_bytes = lsda.serialize()
        stub_bytes = build_x64_unwind_throw_stub(lsda_addr, target_os=self.target_os)

        patched_code = bytearray(combined_code)
        for reloc_off, sym in relocations_to_patch or []:
            if sym in ("__omni_eh_throw", "omni_eh_throw"):
                call_site_next = base_addr + reloc_off + 4
                disp32 = throw_addr - call_site_next
                struct.pack_into("<i", patched_code, reloc_off, disp32)

        full_buf = (
            bytes(patched_code).ljust(code_padded_len, b"\x90")
            + stub_bytes.ljust(stub_padded_len, b"\x90")
            + lsda_bytes
        )
        ctypes.memmove(ctypes.c_void_p(base_addr), full_buf, len(full_buf))

        fn_addrs = {name: base_addr + off for name, off in global_offsets.items()}
        unwind = self.build_unwind_tables(artifacts, global_offsets, arch="x86_64")
        return {
            "base_addr": base_addr,
            "throw_addr": throw_addr,
            "lsda_addr": lsda_addr,
            "lsda_entries": len(lsda.entries),
            "fn_addrs": fn_addrs,
            "unwind": unwind,
        }
