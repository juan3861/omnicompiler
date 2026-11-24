"""
Alpha-C94 Verification Suite:
1. Zero-Cost Cross-Frame Native Exception Unwinding (`runtime/native_eh_runtime.py`):
   - `outer(x)` (`try/except`) -> `middle(x)` -> `inner(x)` (`raise ValueError(...) -> __omni_eh_throw`)
   - Normal path executes zero EH runtime calls; throw path physically walks x64 RBP/RIP frames
     over `LsdaTable` + `.eh_frame`/`.pdata`, restores `outer`'s RBP/RSP, populates `err`,
     and jumps directly to `outer`'s `except` landing pad!
2. Multi-Thread Work-Stealing Native Coroutine Scheduler (`NativeWorkStealingScheduler`):
   - Compiles multi-await `async def` coroutines + native await callback to native x86-64/ARM64
   - Drives coroutines across multiple `await` points inside native `build_native_coro_driver_x64`
     across worker threads with Chase-Lev work stealing without returning to Python per `await`.
"""

import ast
import ctypes
import os
import platform
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler.async_coroutine_lowering import AsyncCoroutineLowerer, NativeWorkStealingScheduler
from compiler.native_codegen import NativeCodeGenerator, X64CodeGenerator
from compiler.object_linker import NativeObjectLinker
from compiler.ssa_ir import AstToSsaLowering
from runtime.native_eh_runtime import NativeEHRuntime


class TestAlphaC94NativeEhAndAsyncStealing(unittest.TestCase):
    def test_01_zero_cost_cross_frame_eh_unwind_and_tables(self):
        src = """
def inner(x: int) -> int:
    if x < 0:
        raise ValueError(7 - x)
    return x * 3

def middle(x: int) -> int:
    return inner(x) + 2

def outer(x: int) -> int:
    try:
        v = middle(x)
        return v + 1
    except Exception as err:
        return err * 10 + 1
"""
        tree = ast.parse(src)
        lowerer = AstToSsaLowering(enable_cross_frame_eh=True)
        fns = [lowerer.lower_function_def(f) for f in tree.body if isinstance(f, ast.FunctionDef)]
        fn_map = {fn.name: fn for fn in fns}

        host_os = "windows" if sys.platform == "win32" else ("macos" if sys.platform == "darwin" else "linux")
        arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x86_64"

        if arch != "x86_64":
            # Verify unwind table emission & ARM64 cross-frame codegen structural soundness
            cg = NativeCodeGenerator(arch=arch, target_os=host_os)
            arts = {name: cg.compile_ssa(fn) for name, fn in fn_map.items()}
            unwind = NativeEHRuntime(target_os=host_os).build_unwind_tables(
                arts,
                {n: i * 256 for i, n in enumerate(arts)},
                arch=arch,
            )
            self.assertGreater(len(unwind["eh_frame"]), 16)
            return

        cg = X64CodeGenerator(target_os=host_os)
        arts = {name: cg.compile_function(fn) for name, fn in fn_map.items()}
        self.assertEqual(len(arts["outer"].eh_lsda_entries), 1)
        self.assertEqual(len(arts["middle"].eh_lsda_entries), 0)

        # Link inner, middle, outer sequentially & track all relocations (internal + __omni_eh_throw)
        combined = bytearray()
        offsets = {}
        for name in ("inner", "middle", "outer"):
            offsets[name] = len(combined)
            combined.extend(arts[name].code_bytes)
            pad = (-len(combined)) & 15
            if pad:
                combined.extend(b"\x90" * pad)

        eh_relocs = []
        import struct
        for name, art in arts.items():
            base_off = offsets[name]
            for rel in art.relocations:
                patch_off = base_off + rel.offset
                if rel.symbol_name == "__omni_eh_throw":
                    eh_relocs.append((patch_off, rel.symbol_name))
                elif rel.symbol_name in offsets:
                    disp = offsets[rel.symbol_name] - (patch_off + 4)
                    struct.pack_into("<i", combined, patch_off, disp)

        with NativeEHRuntime(target_os=host_os) as rt:
            jit = rt.materialize_jit_with_eh(
                bytes(combined),
                artifacts=arts,
                global_offsets=offsets,
                relocations_to_patch=eh_relocs,
            )
            self.assertEqual(jit["lsda_entries"], 1)
            self.assertEqual(jit["unwind"]["eh_info"]["cie_count"], 1)
            self.assertEqual(jit["unwind"]["eh_info"]["fde_count"], 3)
            self.assertEqual(len(jit["unwind"]["win64_pdata_entries"]), 3)

            proto = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)
            outer_fn = proto(jit["fn_addrs"]["outer"])

            # Hot non-throwing path: inner(5)=15 -> middle(5)=17 -> outer(5)=18
            self.assertEqual(outer_fn(5), 18)
            self.assertEqual(outer_fn(0), 3)

            # Unwind path: inner(-4) throws (7 - (-4) = 11) -> skips middle -> outer catch(11) -> 11*10 + 1 = 111!
            self.assertEqual(outer_fn(-4), 111)
            self.assertEqual(outer_fn(-10), 171)  # (7 - (-10))=17 -> 17*10+1 = 171

    def test_02_native_work_stealing_coroutine_scheduler(self):
        async_src = """
async def pipeline_coro(seed: int) -> int:
    a = await (seed + 1)
    b = await (a + 10)
    c = await (b + 20)
    return a + b + c
"""
        cb_src = """
def step_await(tok: int) -> int:
    return tok * 2
"""
        async_fn_def = ast.parse(async_src).body[0]
        lower_res = AsyncCoroutineLowerer().lower_async_function(async_fn_def)
        poll_fn = lower_res["poll_fn"]
        cb_fn = AstToSsaLowering().lower_function_def(ast.parse(cb_src).body[0])

        host_os = "windows" if sys.platform == "win32" else ("macos" if sys.platform == "darwin" else "linux")
        arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x86_64"
        cg = NativeCodeGenerator(arch=arch, target_os=host_os)
        art_poll = cg.compile_ssa(poll_fn)
        art_cb = cg.compile_ssa(cb_fn)

        def _expected(seed: int) -> int:
            a = (seed + 1) * 2
            b = (a + 10) * 2
            c = (b + 20) * 2
            return a + b + c

        with NativeEHRuntime(target_os=host_os) as eh_rt, NativeWorkStealingScheduler(num_workers=4, target_os=host_os) as sched:
            combined = art_poll.code_bytes.ljust(((len(art_poll.code_bytes) + 15) // 16) * 16, b"\x90") + art_cb.code_bytes
            poll_off = 0
            cb_off = ((len(art_poll.code_bytes) + 15) // 16) * 16
            jit = eh_rt.materialize_jit_with_eh(
                combined,
                artifacts={"poll": art_poll, "cb": art_cb},
                global_offsets={"poll": poll_off, "cb": cb_off},
            )
            poll_addr = jit["fn_addrs"]["poll"]
            cb_addr = jit["fn_addrs"]["cb"]
            poll_proto = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_uint64, ctypes.c_int64)
            cb_proto = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)
            poll_call = poll_proto(poll_addr)
            cb_call = cb_proto(cb_addr)

            # Skewed batch: assign heavy tasks to 1 worker / batch across 4 workers to verify concurrent completion
            tasks = []
            for s in range(32):
                item = {
                    "frame_slots": lower_res["frame_slots"],
                    "init_args": {"seed": s},
                    "poll_callable": poll_call,
                    "await_handler": cb_call,
                }
                if arch == "x86_64":
                    item["poll_addr"] = poll_addr
                    item["await_cb_addr"] = cb_addr
                tasks.append(item)

            batch = sched.run_batch(tasks, max_steps=32)
            self.assertEqual(batch["tasks_completed"], 32)
            if arch == "x86_64":
                self.assertEqual(batch["native_driver_runs"], 32)
            expected_all = [_expected(s) for s in range(32)]
            self.assertEqual(batch["results"], expected_all)


if __name__ == "__main__":
    unittest.main()
