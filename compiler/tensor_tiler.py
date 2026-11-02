"""
Halide & Triton-Inspired Decoupled Schedule Tiling & Hardware AVX2 Vectorization Engine
Features:
  - Decouples algorithm specification from compute schedule
  - Two-dimensional loop nest tiling (B_M x B_N) fitting CPU L1/L2 data cache lines
  - Real Python AST Strip-Mining / 2-Level Loop Tiling Transformer (`tile_loop_ast`)
  - Real Silicon 256-bit AVX2 YMM Tiled Vector Execution (`execute_avx2_tiled_vector_add` & `execute_avx2_tiled_reduction`)
"""

import ast
import ctypes
from typing import Dict, Any, List, Tuple, Union


class LoopScheduleTiler:
    """Computes optimal execution tiles, transforms AST loop nests, and executes tiled AVX2 kernels."""

    def __init__(self, l1_cache_bytes: int = 32768, line_size: int = 64):
        self.l1_cache_bytes = l1_cache_bytes
        self.line_size = line_size
        self._avx2_add_cache = None
        self._avx2_dot_cache = None

    def compute_tile_schedule(self, rows: int, cols: int, item_size_bytes: int = 8) -> Dict[str, Any]:
        """Calculates optimal tile_m and tile_n fitting into L1 cache."""
        working_budget = self.l1_cache_bytes // 2
        max_elems = working_budget // item_size_bytes

        tile_m = min(rows, 64)
        tile_n = min(cols, 64)

        while (tile_m * tile_n) > max_elems and (tile_m > 8 or tile_n > 8):
            if tile_m >= tile_n:
                tile_m //= 2
            else:
                tile_n //= 2

        num_tiles_m = (rows + tile_m - 1) // tile_m
        num_tiles_n = (cols + tile_n - 1) // tile_n

        vector_width = 8 if item_size_bytes == 4 else 4  # 256-bit AVX2 YMM register

        return {
            "matrix_shape": [rows, cols],
            "tile_shape": [tile_m, tile_n],
            "total_tiles": num_tiles_m * num_tiles_n,
            "vector_width": vector_width,
            "unroll_factor": 4,
            "l1_utilization_bytes": tile_m * tile_n * item_size_bytes,
            "schedule_type": "HalidePolytopicTiling"
        }

    def tile_loop_ast(self, source_or_ast: Union[str, ast.AST], tile_size: int = 64) -> ast.AST:
        """
        Applies Halide/Polyhedral Strip-Mining (loop tiling) directly on Python AST:
        Transforms `for i in range(N): <body>` or `for i in range(start, stop): <body>`
        into cache-tiled outer/inner loops:
          for _tile_i in range(start, stop, tile_size):
              for i in range(_tile_i, min(_tile_i + tile_size, stop)):
                  <body>
        """
        if tile_size <= 0:
            raise ValueError("tile_size must be positive")

        tree = ast.parse(source_or_ast) if isinstance(source_or_ast, str) else source_or_ast

        class _StripMineTransformer(ast.NodeTransformer):
            def visit_For(self, node: ast.For) -> ast.AST:
                # Transform inner loops recursively first (enables 2D/ND nested loop tiling!)
                node.body = [self.visit(s) for s in node.body]
                if (
                    isinstance(node.target, ast.Name)
                    and isinstance(node.iter, ast.Call)
                    and isinstance(node.iter.func, ast.Name)
                    and node.iter.func.id == "range"
                    and len(node.iter.args) in (1, 2)
                ):
                    iv_name = node.target.id
                    tile_iv = f"_tile_{iv_name}"
                    if len(node.iter.args) == 1:
                        start_expr: ast.expr = ast.Constant(value=0)
                        stop_expr: ast.expr = node.iter.args[0]
                    else:
                        start_expr = node.iter.args[0]
                        stop_expr = node.iter.args[1]

                    inner_end = ast.Call(
                        func=ast.Name(id="min", ctx=ast.Load()),
                        args=[
                            ast.BinOp(
                                left=ast.Name(id=tile_iv, ctx=ast.Load()),
                                op=ast.Add(),
                                right=ast.Constant(value=tile_size),
                            ),
                            stop_expr,
                        ],
                        keywords=[],
                    )
                    inner_for = ast.For(
                        target=ast.Name(id=iv_name, ctx=ast.Store()),
                        iter=ast.Call(
                            func=ast.Name(id="range", ctx=ast.Load()),
                            args=[ast.Name(id=tile_iv, ctx=ast.Load()), inner_end],
                            keywords=[],
                        ),
                        body=node.body,
                        orelse=[],
                    )
                    outer_for = ast.For(
                        target=ast.Name(id=tile_iv, ctx=ast.Store()),
                        iter=ast.Call(
                            func=ast.Name(id="range", ctx=ast.Load()),
                            args=[start_expr, stop_expr, ast.Constant(value=tile_size)],
                            keywords=[],
                        ),
                        body=[inner_for],
                        orelse=node.orelse,
                    )
                    return ast.fix_missing_locations(outer_for)
                return node

        transformed = _StripMineTransformer().visit(tree)
        return ast.fix_missing_locations(transformed)

    def execute_avx2_tiled_vector_add(self, vec_a: List[int], vec_b: List[int]) -> Dict[str, Any]:
        """
        Partitions `vec_a` and `vec_b` into L1-cache-resident tiles using `compute_tile_schedule`
        and executes native 256-bit AVX2 YMM (`vpaddq`) machine code in W^X RAM over each tile.
        """
        if len(vec_a) != len(vec_b):
            raise ValueError("Input vectors must have identical length")
        n = len(vec_a)
        if n == 0:
            return {"output": [], "tiles_executed": 0, "vector_isa": "AVX2_256_YMM"}

        from compiler.native_jit import NativeJitCompiler
        if self._avx2_add_cache is None:
            jit = NativeJitCompiler()
            self._avx2_add_cache = jit.compile_avx2_vector_add_i64()

        fn, _mem, hex_code = self._avx2_add_cache
        # Compute 1D L1 tile size (3 arrays * 8 bytes/elem <= L1/2)
        tile_elems = max(64, (self.l1_cache_bytes // 2) // 24)
        tile_elems = (tile_elems // 4) * 4

        arr_type = ctypes.c_int64 * n
        c_a = arr_type(*vec_a)
        c_b = arr_type(*vec_b)
        c_out = arr_type()

        base_a = ctypes.addressof(c_a)
        base_b = ctypes.addressof(c_b)
        base_out = ctypes.addressof(c_out)

        tiles_executed = 0
        for offset in range(0, n, tile_elems):
            chunk = min(tile_elems, n - offset)
            byte_off = offset * 8
            fn(base_a + byte_off, base_b + byte_off, base_out + byte_off, chunk)
            tiles_executed += 1

        return {
            "output": list(c_out),
            "tiles_executed": tiles_executed,
            "tile_size_elements": tile_elems,
            "vector_isa": "AVX2_256_YMM",
            "machine_code_bytes": len(bytes.fromhex(hex_code)),
        }

    def execute_avx2_tiled_reduction(self, vec_a: List[int], vec_b: List[int]) -> Dict[str, Any]:
        """Executes tiled 256-bit AVX2 YMM parallel reduction sum(a[i] + b[i]) in W^X silicon."""
        if len(vec_a) != len(vec_b):
            raise ValueError("Input vectors must have identical length")
        n = len(vec_a)
        if n == 0:
            return {"sum": 0, "tiles_executed": 0, "vector_isa": "AVX2_256_YMM"}

        from compiler.native_jit import NativeJitCompiler
        if self._avx2_dot_cache is None:
            jit = NativeJitCompiler()
            self._avx2_dot_cache = jit.compile_avx2_dot_sum_i64()

        fn, _mem, _hex = self._avx2_dot_cache
        tile_elems = max(64, (self.l1_cache_bytes // 2) // 16)
        tile_elems = (tile_elems // 4) * 4

        arr_type = ctypes.c_int64 * n
        c_a = arr_type(*vec_a)
        c_b = arr_type(*vec_b)
        base_a = ctypes.addressof(c_a)
        base_b = ctypes.addressof(c_b)

        total = 0
        tiles_executed = 0
        for offset in range(0, n, tile_elems):
            chunk = min(tile_elems, n - offset)
            byte_off = offset * 8
            total += int(fn(base_a + byte_off, base_b + byte_off, chunk))
            tiles_executed += 1

        return {
            "sum": total,
            "tiles_executed": tiles_executed,
            "tile_size_elements": tile_elems,
            "vector_isa": "AVX2_256_YMM",
        }
