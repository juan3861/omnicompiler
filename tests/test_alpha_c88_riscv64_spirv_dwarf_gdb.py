import ast
import faulthandler
import os
faulthandler.disable()
import shutil
import struct
import subprocess
import tempfile
import unittest

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from compiler.binary_emitter import StandaloneBinaryEmitter
from compiler.debug_info_emitter import DwarfV5Emitter
from compiler.native_codegen import NativeCodeGenerator, X64CodeGenerator
from compiler.riscv64_codegen import Riscv64CodeGenerator
from compiler.spirv_emitter import SPIRVEmitter, validate_spirv_binary
from compiler.ssa_ir import AstToSsaLowering
from validation.binary_structure_auditor import BinaryStructureAuditor


def _lower(src: str, fn_name: str):
    tree = ast.parse(src)
    fn_def = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == fn_name)
    return AstToSsaLowering().lower_function_def(fn_def)


def run_dwarf_gdb_check() -> dict:
    """Builds a real DWARF v5 ELF64 .so and audits it with pyelftools + gdb/readelf if installed."""
    from elftools.elf.elffile import ELFFile

    td = tempfile.mkdtemp(prefix="omni_dwarf_gdb_")
    try:
        src = """
def omni_dwarf_fn(a, b):
    t = a * 3 + b
    if t > 20:
        return t - 5
    return t + 7
"""
        fn = _lower(src, "omni_dwarf_fn")
        art = X64CodeGenerator(target_os="linux").compile_function(fn)
        code = art.code_bytes[:art.code_end_offset]
        line_entries = art.line_table or [(0, 2), (min(8, max(0, len(code) - 1)), 4)]

        dw = DwarfV5Emitter()
        dbg_line = dw.emit_debug_line("kernels.py", line_entries, base_address=0x1000, code_size=len(code))
        dbg_info, dbg_abbrev = dw.emit_debug_info_with_subprograms(
            unit_name="kernels.py",
            low_pc=0x1000,
            high_pc=0x1000 + len(code),
            subprograms=[{"name": "omni_dwarf_fn", "low_pc": 0x1000, "high_pc": 0x1000 + len(code), "line": 2}],
        )
        so_path = os.path.join(td, "libomni_dwarf.so")
        StandaloneBinaryEmitter().emit_shared_library(
            output_path=so_path,
            func_code=code,
            export_name="omni_dwarf_fn",
            target_format="elf_so",
            dwarf_sections={
                ".debug_line": dbg_line,
                ".debug_info": dbg_info,
                ".debug_abbrev": dbg_abbrev,
            },
        )
        with open(so_path, "rb") as f:
            elf = ELFFile(f)
            assert elf.has_dwarf_info(), "Missing DWARF info in ELF .so"
            di = elf.get_dwarf_info()
            cus = list(di.iter_CUs())
            assert len(cus) == 1
            lp = di.line_program_for_CU(cus[0])
            assert lp is not None

        res = {"pyelftools_dwarf": True, "gdb_verified": False, "readelf_verified": False}
        readelf_bin = shutil.which("readelf")
        if readelf_bin:
            p = subprocess.run([readelf_bin, "--debug-dump=info", "--debug-dump=decodedline", so_path], capture_output=True, text=True)
            if p.returncode == 0 and "omni_dwarf_fn" in p.stdout:
                res["readelf_verified"] = True

        gdb_bin = shutil.which("gdb")
        if gdb_bin:
            p = subprocess.run(
                [gdb_bin, "--batch", "-ex", f"file {so_path}", "-ex", "info functions", "-ex", "info line omni_dwarf_fn"],
                capture_output=True,
                text=True,
            )
            if p.returncode == 0 and "omni_dwarf_fn" in p.stdout and "kernels.py" in p.stdout:
                res["gdb_verified"] = True
        return res
    finally:
        shutil.rmtree(td, ignore_errors=True)


class TestAlphaC88Riscv64SpirvDwarf(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="omni_c88_")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run_unicorn_rv64(self, code: bytes, args):
        from unicorn import Uc, UC_ARCH_RISCV, UC_MODE_RISCV64
        from unicorn.riscv_const import UC_RISCV_REG_A0, UC_RISCV_REG_A1, UC_RISCV_REG_RA, UC_RISCV_REG_SP

        uc = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64)
        code_addr = 0x100000
        stack_base = 0x200000
        stack_top = 0x210000
        ret_sentinel = code_addr + 0xF000
        uc.mem_map(code_addr, 0x10000)
        uc.mem_map(stack_base, 0x20000)
        uc.mem_write(code_addr, code)
        uc.reg_write(UC_RISCV_REG_SP, stack_top)
        uc.reg_write(UC_RISCV_REG_RA, ret_sentinel)
        arg_regs = [UC_RISCV_REG_A0, UC_RISCV_REG_A1]
        for i, val in enumerate(args):
            uc.reg_write(arg_regs[i], val & 0xFFFFFFFFFFFFFFFF)
        uc.emu_start(code_addr, ret_sentinel, count=5000)
        raw = uc.reg_read(UC_RISCV_REG_A0)
        return raw - (1 << 64) if raw >= (1 << 63) else raw

    def test_01_riscv64_codegen_and_unicorn_rv64_execution(self):
        src_branch = """
def rv_branch(a, b):
    x = a * 3 + b // 2 - (a ^ 7)
    if x > 10:
        return x * 2
    return x + 100
"""
        fn_b = _lower(src_branch, "rv_branch")
        art_b = NativeCodeGenerator(arch="riscv64").compile_ssa(fn_b)
        self.assertEqual(art_b.arch, "riscv64")
        self.assertEqual(self._run_unicorn_rv64(art_b.code_bytes, [10, 6]), (10 * 3 + 3 - (10 ^ 7)) * 2)
        self.assertEqual(self._run_unicorn_rv64(art_b.code_bytes, [-4, 2]), (-12 + 1 - (-4 ^ 7)) + 100)

        src_loop = """
def rv_loop_sum(n, x):
    acc = 0
    i = 0
    while i < n:
        acc = acc + i * 2 + x
        i = i + 1
    return acc
"""
        fn_l = _lower(src_loop, "rv_loop_sum")
        art_l = Riscv64CodeGenerator().compile_function(fn_l)
        self.assertEqual(self._run_unicorn_rv64(art_l.code_bytes, [6, 5]), sum(i * 2 + 5 for i in range(6)))

    def test_02_riscv64_elf_emission_and_ecall_unicorn_proof(self):
        from unicorn import Uc, UC_ARCH_RISCV, UC_MODE_RISCV64, UC_HOOK_INTR
        from unicorn.riscv_const import UC_RISCV_REG_A0, UC_RISCV_REG_A7, UC_RISCV_REG_SP

        fn = _lower("def rv_ret():\n    return 42\n", "rv_ret")
        art = Riscv64CodeGenerator().compile_function(fn)
        elf_path = os.path.join(self.tmpdir, "omni_rv64_app")
        StandaloneBinaryEmitter().emit_standalone_binary(
            elf_path,
            target_format="riscv64_elf",
            custom_code=art.code_bytes,
            entry_offset=0,
        )
        with open(elf_path, "rb") as f:
            elf_bytes = f.read()
        rep = BinaryStructureAuditor().audit_binary(elf_bytes)
        self.assertTrue(rep.is_valid, msg=rep.errors)
        self.assertEqual(rep.machine_arch, "RISC-V 64")
        self.assertEqual(struct.unpack_from("<H", elf_bytes, 18)[0], 0xF3)

        # Emulate full ELF PT_LOAD entry point until Linux sys_exit (ecall a7=93)
        uc = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64)
        vaddr = 0x400000
        uc.mem_map(vaddr, 0x10000)
        uc.mem_map(0x500000, 0x10000)
        uc.mem_write(vaddr, elf_bytes)
        uc.reg_write(UC_RISCV_REG_SP, 0x508000)
        syscalls = []

        def _on_intr(uc_inst, intno, user_data):
            syscalls.append((uc_inst.reg_read(UC_RISCV_REG_A7), uc_inst.reg_read(UC_RISCV_REG_A0)))
            uc_inst.emu_stop()

        uc.hook_add(UC_HOOK_INTR, _on_intr)
        entry_addr = struct.unpack_from("<Q", elf_bytes, 24)[0]
        uc.emu_start(entry_addr, vaddr + 0x1000, count=1000)
        self.assertEqual(syscalls, [(93, 42)])

    def test_03_spirv_binary_emission_and_validation(self):
        src = """
def spv_kernel(a, b):
    s = a * 4 + b
    if s > 0:
        return s - 1
    return s + 1
"""
        fn = _lower(src, "spv_kernel")
        spv_bytes = SPIRVEmitter().emit_spirv_binary(fn)
        val = validate_spirv_binary(spv_bytes)
        self.assertTrue(val["valid"], msg=val)
        self.assertEqual(val["magic"], "0x7230203")
        self.assertEqual(val["version"], "0x10500")
        self.assertIn(132, val["opcodes"])   # OpIMul
        self.assertIn(128, val["opcodes"])   # OpIAdd
        self.assertIn(250, val["opcodes"])   # OpBranchConditional

        spv_path = os.path.join(self.tmpdir, "shader")
        out_p = StandaloneBinaryEmitter().emit_standalone_binary(spv_path, target_format="spirv", custom_code=spv_bytes)
        self.assertTrue(out_p.endswith(".spv"))
        with open(out_p, "rb") as f:
            self.assertEqual(struct.unpack_from("<I", f.read(4), 0)[0], 0x07230203)

        # Tamper rejection
        bad = bytearray(spv_bytes)
        bad[0] ^= 0xFF
        self.assertFalse(validate_spirv_binary(bytes(bad))["valid"])

    def test_04_dwarf_v5_elf_gdb_verification(self):
        res = run_dwarf_gdb_check()
        self.assertTrue(res["pyelftools_dwarf"])
        import shutil as _sh
        if _sh.which("readelf"):
            self.assertTrue(res["readelf_verified"], msg=res)
        if _sh.which("gdb"):
            self.assertTrue(res["gdb_verified"], msg=res)


if __name__ == "__main__":
    unittest.main()
