import ast
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from compiler.ssa_ir import AstToSsaLowering
from compiler.native_codegen import X64CodeGenerator, Arm64CodeGenerator
from validation.backend_translation_validator import (
    BackendTranslationValidator,
    X64MachineToSSALifter,
    Arm64MachineToSSALifter,
)


def _lower(src: str, fn_name: str):
    tree = ast.parse(src)
    fn_def = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == fn_name)
    return AstToSsaLowering().lower_function_def(fn_def)


class TestAlphaC84MachineToSSALifter(unittest.TestCase):
    def test_01_x64_sysv_and_win64_machine_to_ssa_z3_proof(self):
        src = """
def arith_branch(a, b):
    x = (a * 3 + (b // 8)) ^ ((a << 2) & 255)
    if x > 10:
        return x - 5
    return x + 2
"""
        fn = _lower(src, "arith_branch")
        validator = BackendTranslationValidator()

        for target_os, abi in (("linux", "sysv"), ("windows", "win64")):
            art = X64CodeGenerator(target_os=target_os).compile_function(fn)
            res = validator.verify_ssa_to_machine_code(
                fn,
                art.code_bytes,
                arch="x86_64",
                abi=abi,
                code_end_offset=art.code_end_offset,
            )
            self.assertTrue(res["proven"], msg=f"{target_os}/{abi} failed: {res}")
            self.assertEqual(res["status"], "PROVEN_EQUIVALENT")
            self.assertGreaterEqual(res["lifted_instructions"], 5)

    def test_02_arm64_aapcs64_machine_to_ssa_z3_proof(self):
        src = """
def arm_arith_branch(a, b):
    x = a * 5 + (b // 8)
    if x >= 20:
        return x - 9
    return x + 4
"""
        fn = _lower(src, "arm_arith_branch")
        validator = BackendTranslationValidator()
        art = Arm64CodeGenerator().compile_function(fn)
        res = validator.verify_ssa_to_machine_code(
            fn,
            art.code_bytes,
            arch="arm64",
            abi="aapcs64",
            code_end_offset=art.code_end_offset,
            timeout_ms=6000,
        )
        self.assertTrue(res["proven"], msg=res)
        self.assertEqual(res["status"], "PROVEN_EQUIVALENT")

    def test_03_multi_block_loop_machine_to_ssa_proof(self):
        src = """
def loop_acc(n, x):
    acc = 0
    i = 0
    while i < n:
        acc = acc + i * 2 + x
        i = i + 1
    return acc
"""
        fn = _lower(src, "loop_acc")
        validator = BackendTranslationValidator(max_loop_unroll=4, enable_inductive_loops=True)

        x64_art = X64CodeGenerator(target_os="linux").compile_function(fn)
        r_x64 = validator.verify_ssa_to_machine_code(
            fn, x64_art.code_bytes, arch="x86_64", abi="sysv", code_end_offset=x64_art.code_end_offset
        )
        self.assertTrue(r_x64["proven"], msg=r_x64)

        arm_art = Arm64CodeGenerator().compile_function(fn)
        r_arm = validator.verify_ssa_to_machine_code(
            fn, arm_art.code_bytes, arch="arm64", abi="aapcs64", code_end_offset=arm_art.code_end_offset
        )
        self.assertTrue(r_arm["proven"], msg=r_arm)

    def test_04_adversarial_machine_code_mutation_refuted(self):
        src = """
def pure_linear(a, b):
    return a * 3 + b + 7
"""
        fn = _lower(src, "pure_linear")
        validator = BackendTranslationValidator()

        # Mutate immediate constant +7 -> +8 in real x86-64 machine bytes
        art_x64 = X64CodeGenerator(target_os="linux").compile_function(fn)
        mut_x64 = bytearray(art_x64.code_bytes[:art_x64.code_end_offset])
        idx = mut_x64.find(b"\x07")
        self.assertNotEqual(idx, -1)
        mut_x64[idx] = 0x08
        r_x64 = validator.verify_ssa_to_machine_code(fn, bytes(mut_x64), arch="x86_64", abi="sysv")
        self.assertFalse(r_x64["proven"], msg=r_x64)
        self.assertEqual(r_x64["status"], "REFUTED_COUNTEREXAMPLE")
        self.assertIsNotNone(r_x64["counterexample"])

        # Mutate immediate #7 -> #8 in ARM64 MOVZ instruction (0xD28000E0 | (7 << 5))
        art_arm = Arm64CodeGenerator().compile_function(fn)
        mut_arm = bytearray(art_arm.code_bytes[:art_arm.code_end_offset])
        flipped = False
        for pc in range(0, len(mut_arm), 4):
            w = int.from_bytes(mut_arm[pc:pc + 4], "little")
            if (w & 0x7F800000) == 0x52800000 and ((w >> 5) & 0xFFFF) == 7:
                w_mut = (w & ~(0xFFFF << 5)) | (8 << 5)
                mut_arm[pc:pc + 4] = w_mut.to_bytes(4, "little")
                flipped = True
                break
        self.assertTrue(flipped)
        r_arm = validator.verify_ssa_to_machine_code(fn, bytes(mut_arm), arch="arm64", abi="aapcs64")
        self.assertFalse(r_arm["proven"], msg=r_arm)
        self.assertEqual(r_arm["status"], "REFUTED_COUNTEREXAMPLE")


if __name__ == "__main__":
    unittest.main()
